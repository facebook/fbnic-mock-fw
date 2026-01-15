# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the Apache 2.0 license found in the
# LICENSE file in the root directory of this source tree.

import errno
import logging

logger = logging.getLogger(__name__)

COREDUMP_SIZE = 0x2000


class CoredumpManager:
    def __init__(self):
        self._coredump = bytearray(COREDUMP_SIZE)

        # Test tags
        self._coredump[0:4] = b"\xde\xad\xbe\xef"
        self._coredump[-4:] = b"\xde\xad\xbe\xef"

    def get_coredump_length(self) -> int:
        return len(self._coredump)

    def read_coredump(self, buffer: bytearray, offset: int, length: int) -> int:
        if offset < 0 or offset >= COREDUMP_SIZE:
            logger.error(f"Invalid offset {offset} (must be 0-{COREDUMP_SIZE - 1})")
            return errno.EINVAL

        if length <= 0:
            logger.error(f"Invalid length {length} (must be > 0)")
            return errno.EINVAL

        if offset + length > COREDUMP_SIZE:
            logger.error(
                f"Read exceeds COREDUMP bounds: offset={offset}, length={length}, "
                f"end={offset + length} > size={COREDUMP_SIZE}"
            )
            return errno.EOVERFLOW

        buffer[:length] = self._coredump[offset : offset + length]
        return 0
