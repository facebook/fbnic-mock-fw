# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the Apache 2.0 license found in the
# LICENSE file in the root directory of this source tree.

import errno
import logging

logger = logging.getLogger(__name__)


EEPROM_SIZE = 288  # bytes


class EEPROMManager:
    def __init__(self):
        self._eeprom = bytearray(EEPROM_SIZE)

    def validate_bounds(self, offset: int, length: int) -> int:
        if offset < 0 or offset >= EEPROM_SIZE:
            logger.error(f"Invalid offset {offset} (must be 0-{EEPROM_SIZE - 1})")
            return errno.EINVAL

        if length <= 0:
            logger.error(f"Invalid length {length} (must be > 0)")
            return errno.EINVAL

        if offset + length > EEPROM_SIZE:
            logger.error(
                f"Operation exceeds EEPROM bounds: offset={offset}, length={length}, "
                f"end={offset + length} > size={EEPROM_SIZE}"
            )
            return errno.EOVERFLOW
        return 0

    def read_eeprom(self, buffer: bytearray, offset: int, length: int) -> int:
        if err := self.validate_bounds(offset, length):
            return err

        buffer[:length] = self._eeprom[offset : offset + length]
        return 0

    def write_eeprom(self, data: bytes, offset: int, length: int) -> int:
        if err := self.validate_bounds(offset, length):
            return err

        self._eeprom[offset : offset + length] = data[:length]
        return 0
