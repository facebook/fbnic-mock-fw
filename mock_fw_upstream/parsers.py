# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the Apache 2.0 license found in the
# LICENSE file in the root directory of this source tree.

import logging
import struct

from mock_fw_upstream.utils import bytes_to_int
from scapy.all import Packet
from scapy.fields import (
    ByteField,
    LEIntField,
    LELongField,
    LEShortField,
    StrField,
    StrFixedLenField,
)


class ParsedMessage(Packet):
    fields_desc = [
        LEIntField("cmd", 0),
        StrFixedLenField("padding1", b"\x00" * 4, 4),
        LELongField("size", 0),
        StrFixedLenField("data", b"\x00" * 192, 192),
        StrFixedLenField("padding2", b"\x00" * 32, 32),
        LEIntField("num_fds", 0),
        StrFixedLenField("padding3", b"\x00" * 4, 4),
    ]

    def serialize(self) -> bytes:
        if len(self.data) > 192:
            raise ValueError(f"data field too large: {len(self.data)} bytes (max 192)")
        return bytes(self)


class ParsedSysmem(Packet):
    fields_desc = [
        StrFixedLenField("gpa", b"\x00" * 8, 8),
        LELongField("size", 0),
        LELongField("offset", 0),
    ]


class ParsedBar(Packet):
    fields_desc = [
        StrFixedLenField("addr", b"\x00" * 8, 8),
        LELongField("val", 0),
        LEIntField("size", 0),
        ByteField("memory", 0),
        StrFixedLenField(
            "padding", b"\x00" * 171, 171
        ),  # sums up entire packet to 192 bytes (union size)
    ]

    def serialize(self) -> bytes:
        return bytes(self)


class ParsedTlvHdr(Packet):
    fields_desc = [
        LEShortField("flags_and_type", 0),
        LEShortField("length", 0),
    ]

    def __init__(
        self,
        _pkt: bytes | str = b"",
        *,
        type_id: int | None = None,
        is_msg: bool | None = None,
        cannot_ignore: bool | None = None,
        rsvd: int | None = None,
        length: int | None = None,
    ):
        # Initialize ParsedTlvHdr from bytes or bit-field parameters.

        # If ALL bit-field parameters are provided, construct manually
        if all(
            param is not None
            for param in [type_id, is_msg, cannot_ignore, rsvd, length]
        ):
            flags_and_type = (
                (type_id & 0xFFF)
                | ((rsvd & 0x3) << 12)
                | (int(cannot_ignore) << 14)
                | (int(is_msg) << 15)
            )
            super().__init__(_pkt, flags_and_type=flags_and_type, length=length)
        else:
            # Parse from raw bytes
            super().__init__(_pkt)

    @property
    def is_msg(self) -> bool:
        return bool((self.flags_and_type >> 15) & 0x1)

    @property
    def cannot_ignore(self) -> bool:
        return bool((self.flags_and_type >> 14) & 0x1)

    @property
    def type_id(self) -> int:
        return self.flags_and_type & 0xFFF

    @property
    def rsvd(self) -> int:
        return (self.flags_and_type >> 12) & 0x3

    def serialize(self) -> bytes:
        return struct.pack("<HH", self.flags_and_type, self.length)


class ParsedTlvPayload(Packet):
    fields_desc = [
        StrField("data", b""),
    ]

    def serialize(self) -> bytes:
        return bytes(self)


logger = logging.getLogger(__name__)


def parse_msg(msg: bytes) -> ParsedMessage:
    # Note: In actual QEMU-to-QEMU communication, the fds[] array in FBNICEMUMsg contains placeholder values.
    # Actual file descriptors are received via SCM_RIGHTS ancillary data over the Unix socket,
    # and qemu_chr_fe_get_msgfds() overwrites the fds[] array with the real FDs from ancillary data.
    # Hence, here we simply ignore the placeholder values here.

    parsed = ParsedMessage(msg)

    logger.debug("cmd: %s", parsed.cmd)
    logger.debug("size: %s", parsed.size)
    logger.debug(f"data: {bytes_to_int(parsed.data):#x}")
    logger.debug("num_fds: %s", parsed.num_fds)

    return parsed


def parse_sysmem_data(data: bytes, region_idx: int) -> ParsedSysmem:
    """Parse SyncSysmemMsg data for a specific region.

    Each SyncSysmemMsg is 24 bytes (gpa=8,size=8,offset=8).

    Args:
        data: Raw message data containing multiple SyncSysmemMsg structures
        region_idx: Index of the region to parse (0-based)

    """

    logger.debug(f"Parsing Sysmem Data Region {region_idx}")

    # Each SyncSysmemMsg is 24 bytes
    offset_in_data = region_idx * 24

    region_data = data[offset_in_data : offset_in_data + 24]
    parsed = ParsedSysmem(region_data)

    logger.debug(f"gpa: {bytes_to_int(parsed.gpa):#x}")
    logger.debug("size: %s", parsed.size)
    logger.debug(f"offset: {parsed.offset:#x}")

    return parsed


def parse_baraccess_data(data: bytes) -> ParsedBar:
    parsed = ParsedBar(data)

    logger.debug(f"addr: {bytes_to_int(parsed.addr):#x}")
    logger.debug(f"val: {parsed.val:#x}")
    logger.debug("size: %s", parsed.size)
    logger.debug("memory: %s", parsed.memory)

    return parsed


def parse_tlv_hdr_data(data: bytes) -> ParsedTlvHdr:
    """Parsed TLV header structure.

    The TLV header is a 32-bit (4 bytes) structure with the following layout:
    Bits 31-16: Length (in dwords for messages, in bytes for attributes)
    Bit 15: is_msg (indicates if this is a message or attribute)
    Bit 14: cannot_ignore (flag for attribute handling)
    Bits 13-12: Reserved (future use)
    Bits 11-0: Type/ID (message ID or attribute ID)

    """
    parsed = ParsedTlvHdr(data)
    logger.info(
        f"Found TLV Header - type={parsed.type_id:#x}, "
        f"len={parsed.length}, is_msg={parsed.is_msg}, cannot_ignore={parsed.cannot_ignore}, rsvd={parsed.rsvd}"
    )

    return parsed
