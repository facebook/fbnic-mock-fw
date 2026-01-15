import errno
import logging
from abc import ABC, abstractmethod
from enum import IntEnum

from mock_fw_upstream.constants import FbnicEmuCmd
from mock_fw_upstream.dma import dma_read, dma_write
from mock_fw_upstream.mock_fw_state import fw_state, LinkSpeed, MockFwState
from mock_fw_upstream.mock_mbx import (
    extract_address,
    extract_length,
    get_mbx,
    HostIpcMbxDesc,
    is_slot_ready,
    LEN_MASK,
    LEN_SHIFT,
    MBX_0_REG_0_ADDR,
    MbxType,
    mock_mbx_0,
    read_desc_32,
    read_desc_64,
    SLOT_WIDTH,
    write_desc,
)
from mock_fw_upstream.parsers import (
    parse_tlv_hdr_data,
    ParsedBar,
    ParsedMessage,
    ParsedTlvHdr,
    ParsedTlvPayload,
)
from mock_fw_upstream.pcs_config import configure_pcs_link_signals
from mock_fw_upstream.tlv import (
    FbnicTlvIndex,
    TLV_ATTR_ARRAY_SIZE,
    tlv_attr_flag,
    tlv_attr_parse,
    tlv_attr_payload_as_int,
    tlv_attr_payload_as_raw_data,
    tlv_attr_raw_data,
    tlv_attr_s32,
    tlv_attr_u32,
    TLV_HEADER_SIZE,
    TlvMessageBuilder,
)
from mock_fw_upstream.utils import bytes_to_int, int_to_bytes

logger = logging.getLogger(__name__)

QSFP_100R2_BIN_PATH = "qsfp_binaries/qsfp_100R2_anonymized.bin"
QSFP_50R2_BIN_PATH = "qsfp_binaries/qsfp_50R2_anonymized.bin"


class TlvMsgId(IntEnum):
    HOST_CAP_REQ = 0x10
    FW_CAP_RESP = 0x11
    OWNERSHIP_REQ = 0x12
    OWNERSHIP_RESP = 0x13
    HEARTBEAT_REQ = 0x14
    HEARTBEAT_RESP = 0x15
    GET_COREDUMP_INFO_REQ = 0x18
    GET_COREDUMP_INFO_RESP = 0x19
    READ_COREDUMP_REQ = 0x20
    READ_COREDUMP_RESP = 0x21
    START_FW_UPGRADE_REQ = 0x22
    START_FW_UPGRADE_RESP = 0x23
    WRITE_FW_CHUNK_REQ = 0x24
    WRITE_FW_CHUNK_RESP = 0x25
    FINISH_FW_UPGRADE_REQ = 0x28
    READ_EEPROM_REQ = 0x2A
    READ_EEPROM_RESP = 0x2B
    WRITE_EEPROM_REQ = 0x2C
    WRITE_EEPROM_RESP = 0x2D
    READ_QSFP_REQ = 0x38
    READ_QSFP_RESP = 0x39
    TSENE_DATA_REQ = 0x3C
    TSENE_DATA_RESP = 0x3D
    SET_COMPHY_MODE_REQ = 0x3E
    SET_COMPHY_MODE_RESP = 0x3F


class CapTlvAttrId(IntEnum):
    FW_CAP_RESP_VERSION = 0x0
    FW_CAP_RESP_STORED_VERSION = 0x4
    FW_CAP_RESP_ACTIVE_FW_SLOT = 0x5
    FW_CAP_RESP_VERSION_COMMIT_STR = 0x6
    FW_CAP_RESP_FW_STATE = 0x9
    FW_CAP_RESP_LINK_SPEED = 0xA
    FW_CAP_RESP_LINK_FEC = 0xB
    FW_CAP_RESP_STORED_COMMIT_STR = 0xC
    FW_CAP_RESP_CMRT_VERSION = 0xD
    FW_CAP_RESP_STORED_CMRT_VERSION = 0xE
    FW_CAP_RESP_CMRT_COMMIT_STR = 0xF
    FW_CAP_RESP_STORED_CMRT_COMMIT_STR = 0x10
    FW_CAP_RESP_UEFI_VERSION = 0x11
    FW_CAP_RESP_UEFI_COMMIT_STR = 0x12
    FW_CAP_RESP_MAX_LINK_SPEED = 0x13
    FW_CAP_RESP_ANTI_ROLLBACK_VERSION = 0x15
    FW_CAP_RESP_TEMP_MIN = 0x18
    FW_CAP_RESP_TEMP_MAX = 0x19
    FW_CAP_RESP_TEMP_CRIT = 0x1A
    FW_CAP_RESP_VOLT_MIN = 0x1B
    FW_CAP_RESP_VOLT_MAX = 0x1C


class OwnershipTlvAttrId(IntEnum):
    HOST_TAKES_OWNERSHIP = 0x0
    OWNERSHIP_TIME = 0x1


class HeartbeatTlvAttrId(IntEnum):
    HEARTBEAT_UPTIME = 0x0


class CoredumpReqInfoTlvAttrId(IntEnum):
    COREDUMP_REQ_INFO_CREATE = 0x0


class CoredumpInfoTlvAttrId(IntEnum):
    COREDUMP_INFO_AVAILABLE = 0x0
    COREDUMP_INFO_SIZE = 0x1


class CoredumpReadTlvAttrId(IntEnum):
    COREDUMP_READ_OFFSET = 0x0
    COREDUMP_READ_LENGTH = 0x1
    COREDUMP_READ_DATA = 0x2
    COREDUMP_READ_ERROR = 0x3


class FwStartUpgradeTlvAttrId(IntEnum):
    FW_START_UPGRADE_ERROR = 0x0
    FW_START_UPGRADE_SECTION = 0x1
    FW_START_UPGRADE_IMAGE_LENGTH = 0x2


class WriteChunkTlvAttrId(IntEnum):
    WRITE_CHUNK_OFFSET = 0x0
    WRITE_CHUNK_LENGTH = 0x1
    WRITE_CHUNK_DATA = 0x2
    WRITE_CHUNK_ERROR = 0x3


class FwFinishUpgradeTlvAttrId(IntEnum):
    FW_FINISH_UPGRADE_ERROR = 0x0


class EEPromReadTlvAttrId(IntEnum):
    READ_EEPROM_OFFSET = 0x0
    READ_EEPROM_LENGTH = 0x1
    READ_EEPROM_ERROR = 0x3
    READ_EEPROM_DATA = 0x4


class EEPromWriteTlvAttrId(IntEnum):
    WRITE_EEPROM_OFFSET = 0x0
    WRITE_EEPROM_LENGTH = 0x1
    WRITE_EEPROM_ERROR = 0x3
    WRITE_EEPROM_DATA = 0x4


class QSFPReadTlvAttrId(IntEnum):
    READ_QSFP_BANK = 0x0
    READ_QSFP_PAGE = 0x1
    READ_QSFP_OFFSET = 0x2
    READ_QSFP_LENGTH = 0x3
    READ_QSFP_ERROR = 0x4
    READ_QSFP_DATA = 0x5


class TSeneDataTlvAttrId(IntEnum):
    TSENE_THERM = 0x0
    TSENE_VOLT = 0x1


class ComphyModeTlvAttrId(IntEnum):
    COMPHY_MODE_PAM4 = 0x0
    COMPHY_MODE_ERROR = 0x1
    COMPHY_MODE_LANE_MASK = 0x4


TLV_MESSAGE_HANDLERS = {}


class TlvMessageHandler(ABC):
    def __init__(self, state: MockFwState) -> None:
        self.state = state
        self._attr_list = None

    @property
    @abstractmethod
    def message_id(self) -> TlvMsgId:
        pass

    @property
    @abstractmethod
    def schema_list(self) -> list[FbnicTlvIndex]:
        pass

    def insert_attr_list(
        self, attr_list: list[(ParsedTlvHdr, ParsedTlvPayload)]
    ) -> None:
        self._attr_list = attr_list

    @abstractmethod
    def handle(self) -> None:
        pass


class CapsRequestHandler(TlvMessageHandler):
    @property
    def message_id(self) -> TlvMsgId:
        return TlvMsgId.HOST_CAP_REQ

    @property
    def schema_list(self) -> list[FbnicTlvIndex]:
        return []

    def handle(self) -> None:
        configure_pcs_link_signals()

        logger.info("Sending caps response to host")
        send_to_host(gen_caps_response())
        return


class OwnershipRequestHandler(TlvMessageHandler):
    @property
    def message_id(self) -> TlvMsgId:
        return TlvMsgId.OWNERSHIP_REQ

    @property
    def schema_list(self) -> list[FbnicTlvIndex]:
        return [tlv_attr_flag(OwnershipTlvAttrId.HOST_TAKES_OWNERSHIP)]

    def handle(self) -> None:
        host_wants_ownership = bool(
            self._attr_list[OwnershipTlvAttrId.HOST_TAKES_OWNERSHIP]
        )
        fw_state.set_host_owns_nic(host_wants_ownership)

        msg = TlvMessageBuilder(TlvMsgId.OWNERSHIP_RESP).add_u64(
            OwnershipTlvAttrId.OWNERSHIP_TIME, fw_state.get_uptime_ms()
        )

        logger.info("Sending ownership response to host")
        send_to_host(msg)
        return


class HeartbeatRequestHandler(TlvMessageHandler):
    @property
    def message_id(self) -> TlvMsgId:
        return TlvMsgId.HEARTBEAT_REQ

    @property
    def schema_list(self) -> list[FbnicTlvIndex]:
        return []

    def handle(self) -> None:
        msg = TlvMessageBuilder(TlvMsgId.HEARTBEAT_RESP).add_u64(
            HeartbeatTlvAttrId.HEARTBEAT_UPTIME, fw_state.get_uptime_ms()
        )

        logger.info("Sending heartbeat response to host")
        send_to_host(msg)
        return


class GetCoredumpInfoRequestHandler(TlvMessageHandler):
    @property
    def message_id(self) -> TlvMsgId:
        return TlvMsgId.GET_COREDUMP_INFO_REQ

    @property
    def schema_list(self) -> list[FbnicTlvIndex]:
        return [tlv_attr_flag(CoredumpReqInfoTlvAttrId.COREDUMP_REQ_INFO_CREATE)]

    def handle(self) -> None:
        msg = (
            TlvMessageBuilder(TlvMsgId.GET_COREDUMP_INFO_RESP)
            .add_flag(CoredumpInfoTlvAttrId.COREDUMP_INFO_AVAILABLE)
            .add_u32(
                CoredumpInfoTlvAttrId.COREDUMP_INFO_SIZE,
                fw_state.coredump_manager.get_coredump_length(),
            )
        )

        logger.info("Sending coredump info response to host")
        send_to_host(msg)
        return


class ReadCoredumpRequestHandler(TlvMessageHandler):
    @property
    def message_id(self) -> TlvMsgId:
        return TlvMsgId.READ_COREDUMP_REQ

    @property
    def schema_list(self) -> list[FbnicTlvIndex]:
        return [
            tlv_attr_u32(CoredumpReadTlvAttrId.COREDUMP_READ_OFFSET),
            tlv_attr_u32(CoredumpReadTlvAttrId.COREDUMP_READ_LENGTH),
        ]

    def handle(self) -> None:
        offset = (
            0
            if self._attr_list[CoredumpReadTlvAttrId.COREDUMP_READ_OFFSET] is None
            else tlv_attr_payload_as_int(
                self._attr_list[CoredumpReadTlvAttrId.COREDUMP_READ_OFFSET]
            )
        )  # offset attribute is not sent if its 0x00

        length = tlv_attr_payload_as_int(
            self._attr_list[CoredumpReadTlvAttrId.COREDUMP_READ_LENGTH]
        )

        msg = (
            TlvMessageBuilder(TlvMsgId.READ_COREDUMP_RESP)
            .add_u32(CoredumpReadTlvAttrId.COREDUMP_READ_OFFSET, offset)
            .add_u32(CoredumpReadTlvAttrId.COREDUMP_READ_LENGTH, length)
        )

        buffer = bytearray(0)

        err = fw_state.coredump_manager.read_coredump(buffer, offset, length)

        if err:
            msg.add_u32(CoredumpReadTlvAttrId.COREDUMP_READ_ERROR, err)
        else:
            msg.add_value(
                CoredumpReadTlvAttrId.COREDUMP_READ_DATA, bytes(buffer), length
            )

        logger.info("Sending read coredump response to host")
        send_to_host(msg)
        return


class FwStartUpgradeRequestHandler(TlvMessageHandler):
    @property
    def message_id(self) -> TlvMsgId:
        return TlvMsgId.START_FW_UPGRADE_REQ

    @property
    def schema_list(self) -> list[FbnicTlvIndex]:
        return [
            tlv_attr_u32(FwStartUpgradeTlvAttrId.FW_START_UPGRADE_SECTION),
            tlv_attr_u32(FwStartUpgradeTlvAttrId.FW_START_UPGRADE_IMAGE_LENGTH),
        ]

    def handle(self) -> None:
        logger.info("Starting FW upgrade")

        img_length = tlv_attr_payload_as_int(
            self._attr_list[FwStartUpgradeTlvAttrId.FW_START_UPGRADE_IMAGE_LENGTH]
        )

        msg = TlvMessageBuilder(TlvMsgId.START_FW_UPGRADE_RESP)

        err = fw_state.fw_upgrade_manager.start_firmware_upgrade(img_length)

        if err:
            msg.add_u32(FwStartUpgradeTlvAttrId.FW_START_UPGRADE_ERROR, err)
            logger.error("Failed to start firmware upgrade, error code: %d", err)
        else:
            logger.info("Sending start FW upgrade response to host")

        send_to_host(msg)

        if not err:
            fw_upgrade_request_next_chunk()
        return


class WriteFwChunkRespHandler(TlvMessageHandler):
    @property
    def message_id(self) -> TlvMsgId:
        return TlvMsgId.WRITE_FW_CHUNK_RESP

    @property
    def schema_list(self) -> list[FbnicTlvIndex]:
        return [
            tlv_attr_u32(WriteChunkTlvAttrId.WRITE_CHUNK_OFFSET),
            tlv_attr_u32(WriteChunkTlvAttrId.WRITE_CHUNK_LENGTH),
            tlv_attr_raw_data(WriteChunkTlvAttrId.WRITE_CHUNK_DATA),
            tlv_attr_s32(WriteChunkTlvAttrId.WRITE_CHUNK_ERROR),
        ]

    def handle(self) -> None:
        def handle_fail(err: int):
            fw_state.fw_upgrade_manager.in_progress = False
            fw_state.fw_upgrade_manager.img_length = 0
            fw_state.fw_upgrade_manager.offset = 0

            msg = TlvMessageBuilder(TlvMsgId.FINISH_FW_UPGRADE_REQ).add_u32(
                FwFinishUpgradeTlvAttrId.FW_FINISH_UPGRADE_ERROR, err
            )
            send_to_host(msg)
            return

        if not fw_state.fw_upgrade_manager.in_progress:
            logger.error("FW update is not in progress")
            handle_fail(errno.EINVAL)
            return

        offset = tlv_attr_payload_as_int(
            self._attr_list[WriteChunkTlvAttrId.WRITE_CHUNK_OFFSET]
        )
        length = tlv_attr_payload_as_int(
            self._attr_list[WriteChunkTlvAttrId.WRITE_CHUNK_LENGTH]
        )
        error = (
            0
            if self._attr_list[WriteChunkTlvAttrId.WRITE_CHUNK_ERROR] is None
            else tlv_attr_payload_as_int(
                self._attr_list[WriteChunkTlvAttrId.WRITE_CHUNK_ERROR]
            )
        )

        if error:
            logger.error(f"Host returned error: {error}, cancelling update")
            handle_fail(error)
            return

        data = tlv_attr_payload_as_raw_data(
            self._attr_list[WriteChunkTlvAttrId.WRITE_CHUNK_DATA]
        )

        if not data:
            logger.error("Host sent no data")
            handle_fail(errno.ENODATA)
            return

        if offset != fw_state.fw_upgrade_manager.offset:
            logger.error(
                f"Host sent offset {offset}, expected {fw_state.fw_upgrade_manager.offset}"
            )
            handle_fail(errno.EINVAL)
            return

        if length != fw_state.fw_upgrade_manager.requested_length:
            logger.error(
                f"Host sent length {length}, expected {fw_state.fw_upgrade_manager.requested_length}"
            )
            handle_fail(errno.EINVAL)
            return

        # In real firmware, this is where the received chunk would be written to persistent storage.
        # In our mock firmware, we just append to offset
        fw_state.fw_upgrade_manager.offset += length

        bytes_remaining = (
            fw_state.fw_upgrade_manager.img_length - fw_state.fw_upgrade_manager.offset
            if fw_state.fw_upgrade_manager.offset
            < fw_state.fw_upgrade_manager.img_length
            else 0
        )

        if bytes_remaining:
            logger.info("Sending firmware chunk request to host")
            fw_upgrade_request_next_chunk()
        else:
            # upgrade complete
            fw_state.fw_upgrade_manager.in_progress = False
            fw_state.fw_upgrade_manager.img_length = 0
            fw_state.fw_upgrade_manager.offset = 0

            logger.info("Upgrade complete, resending updated capabilities")
            send_to_host(gen_caps_response())

            msg = TlvMessageBuilder(TlvMsgId.FINISH_FW_UPGRADE_REQ)
            send_to_host(msg)

        return


class ReadEEPromRequestHandler(TlvMessageHandler):
    @property
    def message_id(self) -> TlvMsgId:
        return TlvMsgId.READ_EEPROM_REQ

    @property
    def schema_list(self) -> list[FbnicTlvIndex]:
        return [
            tlv_attr_u32(EEPromReadTlvAttrId.READ_EEPROM_OFFSET),
            tlv_attr_u32(EEPromReadTlvAttrId.READ_EEPROM_LENGTH),
        ]

    def handle(self) -> None:
        offset = (
            0
            if self._attr_list[EEPromReadTlvAttrId.READ_EEPROM_OFFSET] is None
            else tlv_attr_payload_as_int(
                self._attr_list[EEPromReadTlvAttrId.READ_EEPROM_OFFSET]
            )
        )  # offset attribute is not sent if its 0x00

        length = tlv_attr_payload_as_int(
            self._attr_list[EEPromReadTlvAttrId.READ_EEPROM_LENGTH]
        )

        msg = (
            TlvMessageBuilder(TlvMsgId.READ_EEPROM_RESP)
            .add_u32(EEPromReadTlvAttrId.READ_EEPROM_OFFSET, offset)
            .add_u32(EEPromReadTlvAttrId.READ_EEPROM_LENGTH, length)
        )

        buffer = bytearray(0)

        err = fw_state.eeprom_manager.read_eeprom(buffer, offset, length)

        if err:
            msg.add_u32(EEPromReadTlvAttrId.READ_EEPROM_ERROR, err)
        else:
            msg.add_value(EEPromReadTlvAttrId.READ_EEPROM_DATA, bytes(buffer), length)

        logger.info("Sending read EEPROM response to host")
        send_to_host(msg)
        return


class WriteEEPromRequestHandler(TlvMessageHandler):
    @property
    def message_id(self) -> TlvMsgId:
        return TlvMsgId.WRITE_EEPROM_REQ

    @property
    def schema_list(self) -> list[FbnicTlvIndex]:
        return [
            tlv_attr_u32(EEPromWriteTlvAttrId.WRITE_EEPROM_OFFSET),
            tlv_attr_u32(EEPromWriteTlvAttrId.WRITE_EEPROM_LENGTH),
            tlv_attr_raw_data(EEPromWriteTlvAttrId.WRITE_EEPROM_DATA),
        ]

    def handle(self) -> None:
        offset = (
            0
            if self._attr_list[EEPromWriteTlvAttrId.WRITE_EEPROM_OFFSET] is None
            else tlv_attr_payload_as_int(
                self._attr_list[EEPromWriteTlvAttrId.WRITE_EEPROM_OFFSET]
            )
        )  # offset attribute is not sent if its 0x00
        length = tlv_attr_payload_as_int(
            self._attr_list[EEPromWriteTlvAttrId.WRITE_EEPROM_LENGTH]
        )

        msg = (
            TlvMessageBuilder(TlvMsgId.WRITE_EEPROM_RESP)
            .add_u32(EEPromWriteTlvAttrId.WRITE_EEPROM_OFFSET, offset)
            .add_u32(EEPromWriteTlvAttrId.WRITE_EEPROM_LENGTH, length)
        )

        data = tlv_attr_payload_as_raw_data(
            self._attr_list[EEPromWriteTlvAttrId.WRITE_EEPROM_DATA]
        )

        err = fw_state.eeprom_manager.write_eeprom(data, offset, length)

        if err:
            msg.add_u32(EEPromWriteTlvAttrId.WRITE_EEPROM_ERROR, err)

        logger.info("Sending write EEPROM response to host")
        send_to_host(msg)
        return


class ReadQSFPRequestHandler(TlvMessageHandler):
    @property
    def message_id(self) -> TlvMsgId:
        return TlvMsgId.READ_QSFP_REQ

    @property
    def schema_list(self) -> list[FbnicTlvIndex]:
        return [
            tlv_attr_u32(QSFPReadTlvAttrId.READ_QSFP_BANK),
            tlv_attr_u32(QSFPReadTlvAttrId.READ_QSFP_PAGE),
            tlv_attr_u32(QSFPReadTlvAttrId.READ_QSFP_OFFSET),
            tlv_attr_u32(QSFPReadTlvAttrId.READ_QSFP_LENGTH),
        ]

    def handle(self) -> None:
        bank = (
            0
            if self._attr_list[QSFPReadTlvAttrId.READ_QSFP_BANK] is None
            else tlv_attr_payload_as_int(
                self._attr_list[QSFPReadTlvAttrId.READ_QSFP_BANK]
            )
        )
        page = (
            0
            if self._attr_list[QSFPReadTlvAttrId.READ_QSFP_PAGE] is None
            else tlv_attr_payload_as_int(
                self._attr_list[QSFPReadTlvAttrId.READ_QSFP_PAGE]
            )
        )
        offset = (
            0
            if self._attr_list[QSFPReadTlvAttrId.READ_QSFP_OFFSET] is None
            else tlv_attr_payload_as_int(
                self._attr_list[QSFPReadTlvAttrId.READ_QSFP_OFFSET]
            )
        )
        length = (
            0
            if self._attr_list[QSFPReadTlvAttrId.READ_QSFP_LENGTH] is None
            else tlv_attr_payload_as_int(
                self._attr_list[QSFPReadTlvAttrId.READ_QSFP_LENGTH]
            )
        )

        bin_to_read = (
            QSFP_100R2_BIN_PATH
            if fw_state.get_comphy_link_speed()
            in (
                LinkSpeed.FBNIC_100G,
                LinkSpeed.FBNIC_50G_R1,
            )
            else QSFP_50R2_BIN_PATH
        )

        msg = (
            TlvMessageBuilder(TlvMsgId.READ_QSFP_RESP)
            .add_u32(QSFPReadTlvAttrId.READ_QSFP_BANK, bank)
            .add_u32(QSFPReadTlvAttrId.READ_QSFP_PAGE, page)
            .add_u32(QSFPReadTlvAttrId.READ_QSFP_OFFSET, offset)
            .add_u32(QSFPReadTlvAttrId.READ_QSFP_LENGTH, length)
        )

        try:
            with open(bin_to_read, "rb") as f:
                data = f.read()

                # for QSFP binaries, the offset is 0x000 for page 0 and 0x100 for page 3
                # also note that there is always only one bank (0), so we don't include it in our calculations
                if page == 0:
                    base_file_offset = 0x000

                elif page == 3:
                    base_file_offset = 0x100

                resp_data = data[
                    base_file_offset + offset : base_file_offset + offset + length
                ]

                msg.add_value(QSFPReadTlvAttrId.READ_QSFP_DATA, resp_data, length)

        except Exception as e:
            logger.error(f"QSFP binary file {bin_to_read} not found, error: {e}")
            msg.add_u32(QSFPReadTlvAttrId.READ_QSFP_ERROR, 1)

        logger.info("Sending read QSFP response to host")
        send_to_host(msg)
        return


class TSeneDataRequestHandler(TlvMessageHandler):
    @property
    def message_id(self) -> TlvMsgId:
        return TlvMsgId.TSENE_DATA_REQ

    @property
    def schema_list(self) -> list[FbnicTlvIndex]:
        return [
            tlv_attr_s32(TSeneDataTlvAttrId.TSENE_THERM),
            tlv_attr_s32(TSeneDataTlvAttrId.TSENE_VOLT),
        ]

    def handle(self) -> None:
        msg = (
            TlvMessageBuilder(TlvMsgId.TSENE_DATA_RESP)
            .add_s32(TSeneDataTlvAttrId.TSENE_THERM, fw_state.get_curr_temp())
            .add_s32(TSeneDataTlvAttrId.TSENE_VOLT, fw_state.get_curr_volt())
        )

        logger.info("Sending sensor data to host")
        send_to_host(msg)
        return


class SetComphyModeRequestHandler(TlvMessageHandler):
    @property
    def message_id(self) -> TlvMsgId:
        return TlvMsgId.SET_COMPHY_MODE_REQ

    @property
    def schema_list(self) -> list[FbnicTlvIndex]:
        return [
            tlv_attr_u32(ComphyModeTlvAttrId.COMPHY_MODE_PAM4),
            tlv_attr_u32(ComphyModeTlvAttrId.COMPHY_MODE_LANE_MASK),
            # skip attr checking for TX_FIR_LANE0/1 for now
        ]

    def handle(self) -> None:
        msg = TlvMessageBuilder(TlvMsgId.SET_COMPHY_MODE_RESP)

        if not fw_state.get_host_owns_nic():
            logger.error("Host tried to change comphy mode without owning the NIC!")
            msg.add_u32(ComphyModeTlvAttrId.COMPHY_MODE_ERROR, errno.EPERM)
            send_to_host(msg)
            return

        pam4 = tlv_attr_payload_as_int(
            self._attr_list[ComphyModeTlvAttrId.COMPHY_MODE_PAM4]
        )
        lane_mask = tlv_attr_payload_as_int(
            self._attr_list[ComphyModeTlvAttrId.COMPHY_MODE_LANE_MASK]
        )

        if lane_mask == 3:
            speed = LinkSpeed.FBNIC_100G if pam4 else LinkSpeed.FBNIC_50G_R2
        else:
            speed = LinkSpeed.FBNIC_50G_R1 if pam4 else LinkSpeed.FBNIC_25G

        fw_state.set_comphy_link_speed(speed)

        logger.info("Sending set comphy mode response to host")
        send_to_host(msg)
        return


for handler_class in TlvMessageHandler.__subclasses__():
    handler = handler_class(fw_state)
    TLV_MESSAGE_HANDLERS[handler.message_id] = handler


def process_descriptor_write(addr: bytes, val: int) -> None:
    mbx = get_mbx(addr)
    slot_idx = mbx.get_slot(addr)
    write_desc(mbx, slot_idx, val)

    # skip processing entire descriptor if it's a write to an upper slot
    if slot_idx % 2 == 1:
        return

    if mbx.type == MbxType.RX:
        # skip processing RX MBX write, was just for book-keeping
        return

    desc = read_desc_64(addr)

    if not is_slot_ready(desc):
        logger.debug(f"Slot {slot_idx} not ready for processing")
    else:
        dma_addr = extract_address(desc)
        length = extract_length(desc)
        logger.info(f"DMA into address {bytes_to_int(dma_addr):#x}")
        data = dma_read(dma_addr, length)
        msg_hdr_bytes, attr_bytes = data[:TLV_HEADER_SIZE], data[TLV_HEADER_SIZE:]
        parsed_tlv_msg_hdr = parse_tlv_hdr_data(msg_hdr_bytes)
        process_tlv_tx_msg(parsed_tlv_msg_hdr, attr_bytes)

        completed_desc = desc | HostIpcMbxDesc.FW_CMPL
        logger.debug(f"Completed descriptor is {completed_desc:#x}")

        lower_32_bits = completed_desc & 0xFFFFFFFF
        upper_32_bits = (completed_desc >> 32) & 0xFFFFFFFF
        write_desc(mbx, slot_idx, lower_32_bits)
        write_desc(mbx, slot_idx + 1, upper_32_bits)
        logger.debug(
            f"Updating mailbox descriptor slots {slot_idx} (lower 32 bits) and {slot_idx + 1} (upper 32 bits) with values "
            f"{lower_32_bits:#x} and {upper_32_bits:#x}"
        )

    # Let the host know we've finished processing tx.
    set_host_interrupt()
    return


def process_descriptor_read(addr: bytes) -> None:
    desc = read_desc_32(addr)
    logger.debug(
        f"addr received in process_descriptor_read is {addr},{bytes_to_int(addr):#x}"
    )
    bar_access_data = ParsedBar(
        addr=addr,
        val=desc,
        size=4,  # indicates 32-bit
        memory=False,
    ).serialize()

    msg = ParsedMessage(
        cmd=FbnicEmuCmd.FBNICEMU_CMD_BAR_CMPL,
        size=24,  # sizeof(BarAccessMsg)
        data=bar_access_data,
        num_fds=0,
    ).serialize()

    fw_state.conn.sendall(msg)


def process_tlv_tx_msg(msg_hdr: ParsedTlvHdr, attr_bytes: bytes) -> None:
    type_id = msg_hdr.type_id

    if type_id not in TlvMsgId:
        logger.info(
            f"Message ID {type_id:#x} is currently not supported and won't be processed!"
        )
        return

    msg_type = TlvMsgId(type_id)

    logger.info(f"Processing message: {msg_type.name}")
    handler = TLV_MESSAGE_HANDLERS.get(msg_type)
    if handler is None:
        logger.error(f"Message handler not found: {msg_type.name}")
        return

    attr_list = [None] * TLV_ATTR_ARRAY_SIZE
    success = tlv_attr_parse(
        attr_bytes, msg_hdr.length - 1, attr_list, handler.schema_list
    )

    if not success:
        logger.error(f"Error parsing message: {msg_type.name}")
        return

    handler.insert_attr_list(attr_list)
    handler.handle()


def set_host_interrupt() -> None:
    """Mimics set_host_interrupt() in host_ipc.c"""

    bar_access_data = ParsedBar(
        addr=b"\x40",  # FB_NIC_INTR_GLOBAL_SW_SET_0__ADDR - FB_NIC_INTR_GLOBAL_STATUS_0__ADDR
        val=1,
        size=4,  # indicates 32-bit sys_write
        memory=False,
    ).serialize()

    msg = ParsedMessage(
        cmd=FbnicEmuCmd.FBNICEMU_CMD_BAR_WRITE,
        size=24,  # sizeof(BarAccessMsg)
        data=bar_access_data,
        num_fds=0,
    ).serialize()

    fw_state.conn.sendall(msg)

    return


def gen_dummy_cmpl_msg(parsed_bar: ParsedBar) -> bytes:
    addr_int = bytes_to_int(parsed_bar.addr)
    logger.debug(f"Generating dummy response for non-IPC BAR read from {addr_int:#x}")

    bar_access_data = ParsedBar(
        addr=parsed_bar.addr,
        val=0x0,  # Dummy value 0
        size=parsed_bar.size,
        memory=False,
    ).serialize()

    msg = ParsedMessage(
        cmd=FbnicEmuCmd.FBNICEMU_CMD_BAR_CMPL,
        size=24,  # sizeof(BarAccessMsg)
        data=bar_access_data,
        num_fds=0,
    ).serialize()

    return msg


def send_to_host(tlv_builder: TlvMessageBuilder) -> None:
    # 1. Find ready slot in mailbox rx
    ADDR_WIDTH = 6  # bytes
    avail_slot_idx = mock_mbx_0.head
    avail_slot_idx_addr = MBX_0_REG_0_ADDR + avail_slot_idx * SLOT_WIDTH

    # 2. Read to get address of page that host allocated for us
    desc = read_desc_64(int_to_bytes(avail_slot_idx_addr, length=ADDR_WIDTH))

    if not is_slot_ready(desc):
        logger.error(f"Mailbox 0 slot {avail_slot_idx} is not ready")
        return

    dma_addr = extract_address(desc)

    # 2. Write to page
    tlv_msg = tlv_builder.build()
    bytes_to_write = len(tlv_msg)
    dma_write(dma_addr, tlv_msg, bytes_to_write)

    # 3. Update descriptors FW_CMPL, EOM and length
    updated_desc = desc & ~LEN_MASK
    updated_desc |= (
        HostIpcMbxDesc.FW_CMPL | HostIpcMbxDesc.EOM | (bytes_to_write << LEN_SHIFT)
    )

    logger.debug(f"Updated descriptor is {updated_desc:#x}")

    # Write back the updated descriptor (split into lower and upper 32-bit slots)
    lower_32_bits = updated_desc & 0xFFFFFFFF
    upper_32_bits = (updated_desc >> 32) & 0xFFFFFFFF
    write_desc(mock_mbx_0, avail_slot_idx, lower_32_bits)
    write_desc(mock_mbx_0, avail_slot_idx + 1, upper_32_bits)
    logger.debug(
        f"Updating mailbox descriptor slots {avail_slot_idx} (lower 32 bits) and {avail_slot_idx + 1} (upper 32 bits) with values "
        f"{lower_32_bits:#x} and {upper_32_bits:#x}"
    )

    # 4. Update head pointer
    mock_mbx_0.head = mock_mbx_0.next_slot(avail_slot_idx)
    logger.debug(f"mock_mbx_0 head now at position {mock_mbx_0.head}")

    # 5. Let the host know we updated the descriptor.
    set_host_interrupt()

    return


def gen_caps_response() -> bytes:
    # TO DO: NRZ_SERDES and PAM4_SERDES in the future
    return (
        TlvMessageBuilder(TlvMsgId.FW_CAP_RESP)
        .add_u32(CapTlvAttrId.FW_CAP_RESP_VERSION, fw_state.get_fw_version())
        .add_u32(CapTlvAttrId.FW_CAP_RESP_STORED_VERSION, fw_state.get_fw_version())
        .add_string(
            CapTlvAttrId.FW_CAP_RESP_STORED_COMMIT_STR,
            fw_state.get_fw_version_commit_string(),
        )
        .add_u32(CapTlvAttrId.FW_CAP_RESP_ACTIVE_FW_SLOT, fw_state.get_active_fw_slot())
        .add_u32(CapTlvAttrId.FW_CAP_RESP_CMRT_VERSION, fw_state.get_cmrt_version())
        .add_u32(
            CapTlvAttrId.FW_CAP_RESP_STORED_CMRT_VERSION,
            fw_state.get_cmrt_version(),
        )
        .add_string(
            CapTlvAttrId.FW_CAP_RESP_STORED_CMRT_COMMIT_STR,
            fw_state.get_cmrt_commit_string(),
        )
        .add_u32(CapTlvAttrId.FW_CAP_RESP_UEFI_VERSION, fw_state.get_uefi_version())
        .add_string(
            CapTlvAttrId.FW_CAP_RESP_UEFI_COMMIT_STR,
            fw_state.get_uefi_commit_string(),
        )
        .add_string(
            CapTlvAttrId.FW_CAP_RESP_VERSION_COMMIT_STR,
            fw_state.get_fw_version_commit_string(),
        )
        .add_string(
            CapTlvAttrId.FW_CAP_RESP_CMRT_COMMIT_STR,
            fw_state.get_cmrt_commit_string(),
        )
        .add_u32(CapTlvAttrId.FW_CAP_RESP_FW_STATE, fw_state.get_hardware_fw_state())
        .add_u32(CapTlvAttrId.FW_CAP_RESP_LINK_SPEED, fw_state.get_comphy_link_speed())
        .add_u32(CapTlvAttrId.FW_CAP_RESP_LINK_FEC, fw_state.get_comphy_link_fec())
        .add_u32(
            CapTlvAttrId.FW_CAP_RESP_MAX_LINK_SPEED,
            fw_state.get_comphy_max_link_speed(),
        )
        .add_u32(
            CapTlvAttrId.FW_CAP_RESP_ANTI_ROLLBACK_VERSION,
            fw_state.get_anti_rollback_version(),
        )
        .add_s32(CapTlvAttrId.FW_CAP_RESP_TEMP_MIN, fw_state.get_temp_min())
        .add_u32(CapTlvAttrId.FW_CAP_RESP_TEMP_MAX, fw_state.get_temp_warn())
        .add_u32(CapTlvAttrId.FW_CAP_RESP_TEMP_CRIT, fw_state.get_temp_crit())
        .add_u32(CapTlvAttrId.FW_CAP_RESP_VOLT_MIN, fw_state.get_volt_min())
        .add_u32(CapTlvAttrId.FW_CAP_RESP_VOLT_MAX, fw_state.get_volt_max())
    )


def fw_upgrade_request_next_chunk() -> None:
    msg = TlvMessageBuilder(TlvMsgId.WRITE_FW_CHUNK_REQ)

    length_to_request = min(
        fw_state.fw_upgrade_manager.img_length - fw_state.fw_upgrade_manager.offset,
        0x800,  # Request at most 2KB from current offset
    )
    fw_state.fw_upgrade_manager.requested_length = length_to_request
    msg.add_u32(WriteChunkTlvAttrId.WRITE_CHUNK_LENGTH, length_to_request)
    msg.add_u32(
        WriteChunkTlvAttrId.WRITE_CHUNK_OFFSET, fw_state.fw_upgrade_manager.offset
    )

    send_to_host(msg)
