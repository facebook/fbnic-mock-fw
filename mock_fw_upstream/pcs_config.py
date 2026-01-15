import logging

from mock_fw_upstream.constants import FbnicEmuCmd
from mock_fw_upstream.mock_fw_state import fw_state, LinkFec, LinkSpeed
from mock_fw_upstream.parsers import ParsedBar, ParsedMessage
from mock_fw_upstream.utils import bit, genmask, int_to_bytes

logger = logging.getLogger(__name__)

SIG_PCS_IN0 = 0x11807  # Link speed/modulation
SIG_PCS_IN1 = 0x11825  # FEC

SIG_PCS_IN0_SD_8X = genmask(18, 17)
SIG_PCS_IN0_F91_1LANE = bit(9)
SIG_PCS_IN0_PCS100_ENA = bit(6)
SIG_PCS_IN0_PACER_10G_MASK = genmask(1, 0)

SIG_PCS_IN1_FEC_ENA = genmask(27, 24)  # BaseR/FC FEC
SIG_PCS_IN1_F91_ENA = genmask(3, 0)  # RS FEC


# Speed to Register Value Mapping
_SPEED_TO_PCS_IN0: dict[int, int] = {
    LinkSpeed.FBNIC_25G: (SIG_PCS_IN0_PACER_10G_MASK | SIG_PCS_IN0_F91_1LANE),
    LinkSpeed.FBNIC_50G_R2: 0x0,
    LinkSpeed.FBNIC_50G_R1: SIG_PCS_IN0_SD_8X,
    LinkSpeed.FBNIC_100G: (SIG_PCS_IN0_SD_8X | SIG_PCS_IN0_PCS100_ENA),
}


# FEC to Register Value Mapping
_FEC_TO_PCS_IN1: dict[int, int] = {
    LinkFec.FBNIC_FEC_NONE: 0x0,
    LinkFec.FBNIC_FEC_RS: SIG_PCS_IN1_F91_ENA,
    LinkFec.FBNIC_FEC_FC: SIG_PCS_IN1_FEC_ENA,
}


def get_pcs_in0_value(speed: int) -> int:
    if speed not in _SPEED_TO_PCS_IN0:
        raise ValueError(f"Unknown link speed: {speed}")
    return _SPEED_TO_PCS_IN0[speed]


def get_pcs_in1_value(fec: int) -> int:
    if fec not in _FEC_TO_PCS_IN1:
        raise ValueError(f"Unknown FEC mode: {fec}")
    return _FEC_TO_PCS_IN1[fec]


def configure_pcs_link_signals() -> None:
    speed = fw_state.get_comphy_link_speed()
    fec = fw_state.get_comphy_link_fec()

    pcs_in0_val = get_pcs_in0_value(speed)
    pcs_in1_val = get_pcs_in1_value(fec)

    logger.info(
        f"Configuring PCS link signals: speed={LinkSpeed(speed).name}, fec={LinkFec(fec).name}"
    )

    # Write SIG_PCS_IN0 (link speed/modulation)
    bar_access_data_in0 = ParsedBar(
        addr=int_to_bytes(SIG_PCS_IN0 * 4),
        val=pcs_in0_val,
        size=4,
        memory=False,
    ).serialize()

    msg_in0 = ParsedMessage(
        cmd=FbnicEmuCmd.FBNICEMU_CMD_BAR_WRITE.value,
        size=24,  # sizeof(BarAccessMsg)
        data=bar_access_data_in0,
        num_fds=0,
    ).serialize()

    fw_state.conn.sendall(msg_in0)

    # Write SIG_PCS_IN1 (FEC)
    bar_access_data_in1 = ParsedBar(
        addr=int_to_bytes(SIG_PCS_IN1 * 4),
        val=pcs_in1_val,
        size=4,
        memory=False,
    ).serialize()

    msg_in1 = ParsedMessage(
        cmd=FbnicEmuCmd.FBNICEMU_CMD_BAR_WRITE.value,
        size=24,  # sizeof(BarAccessMsg)
        data=bar_access_data_in1,
        num_fds=0,
    ).serialize()

    fw_state.conn.sendall(msg_in1)
