import logging
from dataclasses import dataclass, field
from enum import Enum, IntFlag

from mock_fw_upstream.utils import bit, bytes_to_int, genmask, int_to_bytes

logger = logging.getLogger(__name__)


class MbxType(Enum):
    RX = "rx"  # FW -> HOST
    TX = "tx"  # HOST -> FW


MBX_0_REG_0_ADDR = 0x000018000  # derived from iatu_mapping[] in durga.c
MBX_1_REG_0_ADDR = 0x000018080
MBX_SIZE = 0x80  # each MBX has 32 registers of 4 bytes each

NUM_REGS = 32
SLOTS_PER_DESC = 2
SLOT_WIDTH = 4


@dataclass
class MemoryRegion:
    base_addr: int
    size: int

    def contains(self, addr: bytes) -> bool:
        return self.base_addr <= bytes_to_int(addr) < (self.base_addr + self.size)


@dataclass
class MockMbx:
    name: str
    type: MbxType
    mem_region: MemoryRegion
    slots: list[int] = field(default_factory=lambda: [0] * NUM_REGS)
    head: int = 0  # similar to data->rx_head in host_ipc.c

    def get_slot(self, addr: bytes) -> int:
        offset = bytes_to_int(addr) - self.mem_region.base_addr
        slot_idx = offset >> 2
        return slot_idx

    def next_slot(self, slot_idx: int) -> int:
        return (slot_idx + SLOTS_PER_DESC) % NUM_REGS


mock_mbx_0 = MockMbx(
    name="mock_mbx_0",
    type=MbxType.RX,
    mem_region=MemoryRegion(base_addr=MBX_0_REG_0_ADDR, size=MBX_SIZE),
)
mock_mbx_1 = MockMbx(
    name="mock_mbx_1",
    type=MbxType.TX,
    mem_region=MemoryRegion(base_addr=MBX_1_REG_0_ADDR, size=MBX_SIZE),
)
mock_mbxs = [
    mock_mbx_0,
    mock_mbx_1,
]


def get_mbx(addr: bytes) -> MockMbx:
    for mbx in mock_mbxs:
        if mbx.mem_region.contains(addr):
            logger.debug(f"MBX found: {mbx.name}")
            return mbx
    logger.error(f"Invalid MBX address {bytes_to_int(addr):#x}")
    return None


def dump_mbx(mbx: MockMbx) -> None:
    logger.debug("Mbx current state")
    for i, val in enumerate(mbx.slots):
        logger.debug(f"slot: {i}, val: {val:#x}")
    return


def write_desc(mbx: MockMbx, slot_idx: int, val: int) -> None:
    mbx.slots[slot_idx] = val
    logger.info(f"Write to mbx: {mbx.name}, slot: {slot_idx}, val: 0x{val:#x}")
    dump_mbx(mbx)
    return


def read_desc_64(base_addr: int) -> int:
    mbx = get_mbx(base_addr)
    lower_slot = mbx.get_slot(base_addr)

    if lower_slot % 2 != 0:
        raise ValueError("base_addr corresponds to an upper 32 bit register")
    elif lower_slot == NUM_REGS - 1:
        raise ValueError("base_addr corresponds to last 32 bit register")

    lower_32_bits = mbx.slots[lower_slot]
    upper_32_bits = mbx.slots[lower_slot + 1]
    desc = (upper_32_bits << 32) | lower_32_bits

    logger.debug(f"Reading desc 64 bits: {desc:#x}")
    return desc


def read_desc_32(base_addr: int) -> int:
    mbx = get_mbx(base_addr)
    slot_idx = mbx.get_slot(base_addr)
    desc = mbx.slots[slot_idx]
    logger.debug(f"Reading desc 32 bits: {desc:#x}")
    return desc


# Descriptor bit field helpers
class HostIpcMbxDesc(IntFlag):
    HOST_CMPL = bit(0)
    FW_CMPL = bit(1)
    EOM = bit(46)


LEN_MASK = genmask(63, 48)
ADDR_MASK = genmask(45, 3)
LEN_SHIFT = 48


def is_slot_ready(desc: int) -> bool:
    # Check descriptor completed by host but not FW
    mask = HostIpcMbxDesc.HOST_CMPL | HostIpcMbxDesc.FW_CMPL
    return (desc & mask) == HostIpcMbxDesc.HOST_CMPL and desc != mask


def extract_length(desc: int) -> int:
    return (desc & LEN_MASK) >> LEN_SHIFT


def extract_address(desc: int) -> bytes:
    # round up to 6 bytes
    return int_to_bytes(desc & ADDR_MASK, length=6)
