import logging

from mock_fw_upstream.mock_fw_state import fw_state, RemoteRegion
from mock_fw_upstream.utils import bytes_to_int

logger = logging.getLogger(__name__)


def _resolve_dma_addr(dma_addr: bytes) -> tuple[RemoteRegion, int]:
    region = find_remote_region(dma_addr)
    if region is None:
        raise RuntimeError("Could not find remote region")
    offset = bytes_to_int(dma_addr) - bytes_to_int(region.gpa)
    return region, offset


def dma_read(dma_addr: bytes, length: int) -> bytes:
    region, offset = _resolve_dma_addr(dma_addr)
    data = region.mm[offset : offset + length]
    logger.debug(
        f"DMA read: addr={bytes_to_int(dma_addr):#x}, offset={offset:#x}, "
        f"data={bytes_to_int(data):#x}"
    )
    return data


def dma_write(dma_addr: bytes, data: bytes, length: int) -> None:
    region, offset = _resolve_dma_addr(dma_addr)
    region.mm[offset : offset + length] = data
    logger.debug(
        f"DMA write: addr={bytes_to_int(dma_addr):#x}, offset={offset:#x}, "
        f"length={length}, data={bytes_to_int(data):#x}"
    )
    return


def find_remote_region(dma_addr: bytes) -> RemoteRegion:
    for region in fw_state.remote_regions:
        gpa_in_int = bytes_to_int(region.gpa)
        dma_addr_in_int = bytes_to_int(dma_addr)
        if gpa_in_int <= dma_addr_in_int <= gpa_in_int + region.size:
            logger.debug(f"Found remote region {region.fd}")
            return region

    logger.error(
        f"Could not find remote region that contains DMA address {bytes_to_int(dma_addr):#x}"
    )
    return None
