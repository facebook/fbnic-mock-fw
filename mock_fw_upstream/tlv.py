import errno
import logging
from dataclasses import dataclass
from enum import IntEnum

from mock_fw_upstream.constants import PAGE_SIZE
from mock_fw_upstream.parsers import ParsedTlvHdr, ParsedTlvPayload
from mock_fw_upstream.utils import bytes_to_int, int_to_bytes
from scapy.all import Packet, Raw

logger = logging.getLogger(__name__)

TLV_HEADER_SIZE = 4  # bytes
TLV_ATTR_ARRAY_SIZE = 32
TLV_MAX_DATA = PAGE_SIZE - 512
ETH_ALEN = 6  # MAC address length


def tlv_msg_align(size_bytes: int) -> int:
    # Equivalent to FBNIC_TLV_MSG_ALIGN(len) macro in fbnic_tlv.h
    return (size_bytes + 3) & ~3


def tlv_msg_size(size_bytes: int) -> int:
    # Equivalent to FBNIC_TLV_MSG_SIZE(len) macro in fbnic_tlv.h
    return tlv_msg_align(size_bytes) // 4


def calculate_remaining_space(curr_page_offset: int) -> int:
    return PAGE_SIZE - curr_page_offset


@dataclass(frozen=True)  # immutable
class TlvAttr:
    id: int
    value_bytes: bytes
    length: int


class TlvMessageBuilder:
    def __init__(self, msg_id: int, offset_in_page: int = 0):
        self._msg_hdr_id = msg_id
        self._len = 1  # initial message header, len in dwords
        self._attrs: list[TlvAttr] = []
        self._offset_in_page = offset_in_page

    def add_u32(self, attr_id: int, value: int) -> "TlvMessageBuilder":
        value_in_bytes = int_to_bytes(value, length=4)
        self._attrs.append(TlvAttr(id=attr_id, value_bytes=value_in_bytes, length=4))
        return self

    def add_s32(self, attr_id: int, value: int) -> "TlvMessageBuilder":
        # Handles negative values by converting to two's complement representation.
        if value < 0:
            value_unsigned = (1 << 32) + value
        else:
            value_unsigned = value

        value_in_bytes = int_to_bytes(value_unsigned, length=4)
        self._attrs.append(TlvAttr(id=attr_id, value_bytes=value_in_bytes, length=4))
        return self

    def add_u64(self, attr_id: int, value: int) -> "TlvMessageBuilder":
        value_in_bytes = int_to_bytes(value, length=8)
        self._attrs.append(TlvAttr(id=attr_id, value_bytes=value_in_bytes, length=8))
        return self

    def add_string(self, attr_id: int, value: str) -> "TlvMessageBuilder":
        value_in_bytes = value.encode("latin-1")

        attr_max_len = (
            calculate_remaining_space(self._offset_in_page) - 4
        )  # for message header
        str_len = 1  # account for null terminator first

        attr_max_len -= self._len * 4  # minus bytes instead of dwords

        # Calculate actual string length, capped at available space (Python equivalent of strnlen)
        # If value_in_bytes is greater than available space, str_len += attr_max_len and error will
        # be logged in tlv_attr_add_value when we check bounds
        str_len += min(len(value_in_bytes), attr_max_len)

        value_in_bytes += b"\x00"  # need to add null terminator for Python
        self._attrs.append(
            TlvAttr(id=attr_id, value_bytes=value_in_bytes, length=str_len)
        )
        return self

    def add_value(
        self,
        attr_id: int,
        value: bytes,
        length: int,
    ) -> "TlvMessageBuilder":
        self._attrs.append(TlvAttr(id=attr_id, value_bytes=value, length=length))
        return self

    def add_flag(self, attr_id: int) -> "TlvMessageBuilder":
        self._attrs.append(TlvAttr(id=attr_id, value_bytes=b"", length=0))
        return self

    def process_tlv_attr(self, tlv_attr: TlvAttr) -> Packet | None:
        attr_id = tlv_attr.id
        value = tlv_attr.value_bytes
        length = tlv_attr.length
        HEADER_SIZE = 4  # bytes

        attr_max_len = (
            calculate_remaining_space(self._offset_in_page)
            - HEADER_SIZE  # message header
        )

        attr_max_len -= self._len * 4  # minus bytes instead of dwords

        if attr_max_len < length + HEADER_SIZE:  # attribute header
            logger.error(
                f"Attribute {attr_id} is too large to fit in the remaining space. "
                f"Available length is {attr_max_len} bytes, but value has length {length} bytes"
            )
            return None

        attr_hdr = make_tlv_attr_hdr(attr_id, payload_size=length)

        # Adjust msg length since we added attribute header and payload
        self._len += tlv_msg_size(attr_hdr.length)

        # Likely a flag, there won't be a payload
        if length == 0 and value == b"":
            return attr_hdr

        # Zero pad end of value if we aren't aligned to DWORD boundary
        if length % HEADER_SIZE:
            # Calculate padding needed
            padding_needed = HEADER_SIZE - (length % HEADER_SIZE)
            value += b"\x00" * padding_needed

        payload = ParsedTlvPayload(data=value)
        return attr_hdr / payload

    def build(self) -> bytes:
        msg_hdr = make_tlv_msg_hdr(self._msg_hdr_id)

        pkts = []
        for tlv_attr in self._attrs:
            pkt = self.process_tlv_attr(tlv_attr)
            pkts.append(pkt)

        msg_hdr.length = self._len

        # Concatenate using scapy's / operator
        final_msg = msg_hdr
        for pkt in pkts:
            final_msg = final_msg / pkt

        return bytes(Raw(final_msg))


def make_tlv_msg_hdr(msg_id: int) -> ParsedTlvHdr:
    # length in dwords
    return ParsedTlvHdr(
        type_id=msg_id,
        length=1,
        is_msg=True,
        cannot_ignore=False,
        rsvd=0,
    )


def make_tlv_attr_hdr(
    attr_id: int,
    payload_size: int,  # in bytes
    cannot_ignore: bool = False,
) -> ParsedTlvHdr:
    # cannot_ignore only used for unrecognized attributes, identifying if it can be ignored
    # length in bytes
    return ParsedTlvHdr(
        type_id=attr_id,
        length=4 + payload_size,
        is_msg=False,
        cannot_ignore=cannot_ignore,
        rsvd=0,
    )


def tlv_attr_payload_as_int(attr: (ParsedTlvHdr, ParsedTlvPayload)) -> int:
    return bytes_to_int(attr[1])


def tlv_attr_payload_as_raw_data(attr: (ParsedTlvHdr, ParsedTlvPayload)) -> int:
    return bytes(attr[1])


class FbnicTlvType(IntEnum):
    FBNIC_TLV_STRING = 0
    FBNIC_TLV_FLAG = 1
    FBNIC_TLV_UNSIGNED = 2
    FBNIC_TLV_SIGNED = 3
    FBNIC_TLV_BINARY = 4
    FBNIC_TLV_NESTED = 5
    FBNIC_TLV_ARRAY = 6


@dataclass
class FbnicTlvIndex:
    id: int
    len: int
    type: FbnicTlvType


def tlv_attr_string(attr_id: int, length: int) -> FbnicTlvIndex:
    return FbnicTlvIndex(id=attr_id, len=length, type=FbnicTlvType.FBNIC_TLV_STRING)


def tlv_attr_flag(attr_id: int) -> FbnicTlvIndex:
    return FbnicTlvIndex(id=attr_id, len=0, type=FbnicTlvType.FBNIC_TLV_FLAG)


def tlv_attr_u32(attr_id: int) -> FbnicTlvIndex:
    return FbnicTlvIndex(id=attr_id, len=4, type=FbnicTlvType.FBNIC_TLV_UNSIGNED)


def tlv_attr_u64(attr_id: int) -> FbnicTlvIndex:
    return FbnicTlvIndex(id=attr_id, len=8, type=FbnicTlvType.FBNIC_TLV_UNSIGNED)


def tlv_attr_s32(attr_id: int) -> FbnicTlvIndex:
    return FbnicTlvIndex(id=attr_id, len=4, type=FbnicTlvType.FBNIC_TLV_SIGNED)


def tlv_attr_s64(attr_id: int) -> FbnicTlvIndex:
    return FbnicTlvIndex(id=attr_id, len=8, type=FbnicTlvType.FBNIC_TLV_SIGNED)


def tlv_attr_mac_addr(attr_id: int) -> FbnicTlvIndex:
    return FbnicTlvIndex(id=attr_id, len=ETH_ALEN, type=FbnicTlvType.FBNIC_TLV_BINARY)


def tlv_attr_nested(attr_id: int) -> FbnicTlvIndex:
    return FbnicTlvIndex(id=attr_id, len=0, type=FbnicTlvType.FBNIC_TLV_NESTED)


def tlv_attr_array(attr_id: int) -> FbnicTlvIndex:
    return FbnicTlvIndex(id=attr_id, len=0, type=FbnicTlvType.FBNIC_TLV_ARRAY)


def tlv_attr_raw_data(attr_id: int) -> FbnicTlvIndex:
    return FbnicTlvIndex(
        id=attr_id, len=TLV_MAX_DATA, type=FbnicTlvType.FBNIC_TLV_BINARY
    )


def tlv_attr_tx_fir(attr_id: int) -> FbnicTlvIndex:
    TX_FIR_SIZE = 5  # as in comphy.h
    return FbnicTlvIndex(
        id=attr_id, len=TX_FIR_SIZE, type=FbnicTlvType.FBNIC_TLV_BINARY
    )


def tlv_attr_validate(
    attr_hdr: ParsedTlvHdr, payload: ParsedTlvPayload, schema_list: list[FbnicTlvType]
) -> int:
    payload_len = attr_hdr.length - TLV_HEADER_SIZE
    attr_id = attr_hdr.type_id

    if attr_hdr.is_msg:
        logger.error("Attribute header is a message header")
        return -errno.EINVAL

    if attr_id >= TLV_ATTR_ARRAY_SIZE:
        logger.error(f"Attribute ID {attr_id} is out of range")
        return -errno.ENOENT

    schema = next((s for s in schema_list if s.id == attr_id), None)

    if schema is None:
        if attr_hdr.cannot_ignore:
            logger.error(f"Unrecognized attribute ID {attr_id}")
            return -errno.ENOENT
        return attr_hdr.length

    # TO DO: Add bounds checking that includes offset in page

    # Type-specific validation
    match schema.type:
        case FbnicTlvType.FBNIC_TLV_STRING:
            if payload_len == 0 or payload_len > schema.len:
                logger.error(
                    f"String attribute {attr_id} has invalid length {payload_len} (max: {schema.len})"
                )
                return -errno.EINVAL
            # String must be null-terminated (last byte must be 0)
            if isinstance(payload, bytes) and payload[payload_len - 1] != 0:
                logger.error(f"String attribute {attr_id} is not null-terminated")
                return -errno.EINVAL

        case FbnicTlvType.FBNIC_TLV_FLAG:
            if payload_len != 0:
                logger.error(
                    f"Flag attribute {attr_id} has invalid length {payload_len}, expected 0"
                )
                return -errno.EINVAL

        case FbnicTlvType.FBNIC_TLV_UNSIGNED | FbnicTlvType.FBNIC_TLV_SIGNED:
            # Schema length for integers must not exceed 8 bytes (u64/s64)
            if schema.len > 8:
                logger.error(
                    f"Integer attribute {attr_id} schema length {schema.len} exceeds 8 bytes"
                )
                return -errno.EINVAL
            if payload_len == 0 or payload_len > schema.len:
                logger.error(
                    f"Integer attribute {attr_id} has invalid length {payload_len} (max: {schema.len})"
                )
                return -errno.EINVAL

        case FbnicTlvType.FBNIC_TLV_BINARY:
            if payload_len == 0 or payload_len > schema.len:
                logger.error(
                    f"Binary attribute {attr_id} has invalid length {payload_len} (max: {schema.len})"
                )
                return -errno.EINVAL

        case FbnicTlvType.FBNIC_TLV_NESTED | FbnicTlvType.FBNIC_TLV_ARRAY:
            if payload_len % 4 != 0:
                logger.error(
                    f"Nested/Array attribute {attr_id} has invalid length {payload_len} (not 4-byte aligned)"
                )
                return -errno.EINVAL

        case _:
            logger.error(f"Unknown type {schema.type} for attribute {attr_id}")
            return -errno.EINVAL

    logger.debug(
        f"Successfully validated attribute id={attr_hdr.type_id}, payload_len={payload_len}, type={schema.type.name}"
    )

    return 0


def tlv_attr_parse(
    attr_bytes: bytes,
    attr_len: int,  # in dwords
    attr_list: list[(ParsedTlvHdr, ParsedTlvPayload)],
    schema_list: list[FbnicTlvType],
) -> bool:
    if attr_len == 0:  # No attributes, no need to parse
        return True

    while attr_len > 0:
        attr_hdr = ParsedTlvHdr(attr_bytes[:TLV_HEADER_SIZE])

        payload = ParsedTlvPayload(
            attr_bytes[TLV_HEADER_SIZE : attr_hdr.length]
        )  # attr_hdr.length already includes itself of 4 bytes

        attr_hdr_id = attr_hdr.type_id

        err = tlv_attr_validate(attr_hdr, payload, schema_list)

        if err < 0:
            return False

        # Ignore results for unknown attributes that can be ignored
        if err == 0:
            # Do not overwrite existing entries
            if attr_list[attr_hdr_id]:
                logger.error(
                    f"Duplicate attribute encountered: id={attr_hdr_id}; existing entry present"
                )
                return False

            attr_list[attr_hdr_id] = (attr_hdr, payload)

        # Update remaining bytes to parse (advance to next attribute)
        curr_attr_len = tlv_msg_size(attr_hdr.length)  # in dwords
        attr_len -= curr_attr_len
        attr_bytes = attr_bytes[
            curr_attr_len * 4 :
        ]  # curr_attr_len * 4 gives the right slicing index in bytes

    return len(attr_bytes) == 0
