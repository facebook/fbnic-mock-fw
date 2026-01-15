# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the Apache 2.0 license found in the
# LICENSE file in the root directory of this source tree.

from mock_fw_upstream.utils import bytes_to_int

# Constants from iatu_mapping[] in durga.c
CTRL_IPC_BAR_OFFSET = 0x18000
CTRL_IPC_BAR_SIZE = 0x4000

CRM_CFG_BAR_OFFSET = 0x0
CRM_CFG_BAR_SIZE = 0x4000


def _is_addr_within_region(
    bar_offset: bytes, size: int, region_offset: int, region_size: int
) -> bool:
    bar_offset_in_int = bytes_to_int(bar_offset)
    return (
        bar_offset_in_int >= region_offset
        and bar_offset_in_int + size <= region_offset + region_size
    )


def is_addr_within_ipc_region(bar_offset: bytes, size: int) -> bool:
    return _is_addr_within_region(
        bar_offset, size, CTRL_IPC_BAR_OFFSET, CTRL_IPC_BAR_SIZE
    )


def is_addr_within_crm_cfg_region(bar_offset: bytes, size: int) -> bool:
    return _is_addr_within_region(
        bar_offset, size, CRM_CFG_BAR_OFFSET, CRM_CFG_BAR_SIZE
    )
