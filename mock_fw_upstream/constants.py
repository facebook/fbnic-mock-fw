# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the Apache 2.0 license found in the
# LICENSE file in the root directory of this source tree.

from enum import IntEnum

PAGE_SIZE = 4096  # 4 KB


class FbnicEmuCmd(IntEnum):
    FBNICEMU_CMD_RET = 0
    FBNICEMU_CMD_BAR_WRITE = 1
    FBNICEMU_CMD_BAR_CMPL = 2
    FBNICEMU_CMD_BAR_READ = 3
    FBNICEMU_CMD_SYNC_SYSMEM = 4
    FBNICEMU_CMD_MAX = 5
