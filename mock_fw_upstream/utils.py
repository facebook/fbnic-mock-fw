# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the Apache 2.0 license found in the
# LICENSE file in the root directory of this source tree.

BYTE_ORDER = "little"


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, byteorder=BYTE_ORDER)


def int_to_bytes(i: int, length: int = 4) -> bytes:
    return i.to_bytes(length, byteorder=BYTE_ORDER)


def genmask(high, low):
    return ((1 << (high - low + 1)) - 1) << low


def bit(pos):
    return 1 << pos
