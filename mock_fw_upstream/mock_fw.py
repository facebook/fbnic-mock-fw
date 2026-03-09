#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the Apache 2.0 license found in the
# LICENSE file in the root directory of this source tree.

import argparse
import array
import logging
import mmap
import os
import socket
import sys
from pathlib import Path

# Allow running as standalone script outside of Meta internal
# This must be BEFORE any mock_fw_upstream imports
_parent = Path(__file__).resolve().parent.parent
if str(_parent) not in sys.path:
    sys.path.insert(0, str(_parent))

from mock_fw_upstream.addr_validator import (
    is_addr_within_crm_cfg_region,
    is_addr_within_ipc_region,
)
from mock_fw_upstream.constants import FbnicEmuCmd, PAGE_SIZE
from mock_fw_upstream.host_messages import (
    gen_dummy_cmpl_msg,
    process_descriptor_read,
    process_descriptor_write,
    set_host_interrupt,
)
from mock_fw_upstream.mock_fw_state import fw_state, RemoteRegion
from mock_fw_upstream.parsers import parse_baraccess_data, parse_msg, parse_sysmem_data

logger = logging.getLogger(__name__)

REMOTE_MAX_FDS = 8


def _get_systemd_socket() -> socket.socket | None:
    """Return the socket passed by systemd socket activation, or None.

    Checks the sd_listen_fds(3) protocol: LISTEN_PID must match our PID
    and LISTEN_FDS must be >= 1.  With Accept=yes the passed fd (3) is an
    already-connected stream socket.
    """
    SD_LISTEN_FDS_START = 3

    try:
        listen_pid = int(os.environ.get("LISTEN_PID", "0"))
        listen_fds = int(os.environ.get("LISTEN_FDS", "0"))
    except ValueError:
        return None

    if listen_pid != os.getpid() or listen_fds < 1:
        return None

    # fromfd() dups the fd, so close the original afterwards.
    conn = socket.fromfd(SD_LISTEN_FDS_START, socket.AF_UNIX, socket.SOCK_STREAM)
    os.close(SD_LISTEN_FDS_START)
    return conn


def setup_socket(socket_path: str) -> socket.socket:
    """Set up a Unix domain socket server."""

    if os.path.exists(socket_path):
        os.remove(socket_path)

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(socket_path)
    sock.listen(1)

    logger.info(f"Mock firmware listening on {socket_path}")

    return sock


def process_all_msgs(msgs: bytes, received_fds: list[int]) -> None:
    FB_NIC_EMU_MSG_SIZE = 248

    if len(msgs) % FB_NIC_EMU_MSG_SIZE != 0:
        logger.error(
            "Message size is not a multiple of 248 bytes (size of one FBNICEMUMsg)"
        )
        return

    num_of_msgs = len(msgs) // FB_NIC_EMU_MSG_SIZE
    for msg_idx in range(num_of_msgs):
        start = msg_idx * FB_NIC_EMU_MSG_SIZE
        end = start + FB_NIC_EMU_MSG_SIZE
        msg = msgs[start:end]
        process_msg(msg, received_fds)

    return


def process_msg(msg: bytes, received_fds: list[int]) -> None:
    parsed_msg = parse_msg(msg)

    match parsed_msg.cmd:
        case FbnicEmuCmd.FBNICEMU_CMD_SYNC_SYSMEM:
            logger.info("Received FBNICEMU_CMD_SYNC_SYSMEM cmd")
            fw_state.remote_sysmem_reset()
            for region_idx in range(parsed_msg.num_fds):
                parsed_sysmem = parse_sysmem_data(parsed_msg.data, region_idx)
                try:
                    mm = mmap.mmap(
                        received_fds[region_idx],
                        parsed_sysmem.size,
                        offset=parsed_sysmem.offset,
                        flags=mmap.MAP_SHARED,
                        prot=mmap.PROT_READ | mmap.PROT_WRITE,
                    )

                    region = RemoteRegion(
                        gpa=parsed_sysmem.gpa,
                        size=parsed_sysmem.size,
                        fd=received_fds[region_idx],
                        mm=mm,
                    )

                    fw_state.remote_regions.append(region)
                    fw_state.num_remote_regions += 1
                    logger.debug(
                        f"Successfully mapped region {region_idx}: {len(mm)} bytes"
                    )
                except Exception as e:
                    logger.error(f"Failed to map region {region_idx}: {e}")
        case FbnicEmuCmd.FBNICEMU_CMD_BAR_WRITE:
            logger.info("Received FBNICEMU_CMD_BAR_WRITE cmd")
            parsed_bar = parse_baraccess_data(parsed_msg.data)
            assert is_addr_within_ipc_region(parsed_bar.addr, parsed_bar.size)
            process_descriptor_write(parsed_bar.addr, parsed_bar.val)
        case FbnicEmuCmd.FBNICEMU_CMD_BAR_READ:
            logger.info("Received FBNICEMU_CMD_BAR_READ cmd")
            parsed_bar = parse_baraccess_data(parsed_msg.data)
            if is_addr_within_ipc_region(parsed_bar.addr, parsed_bar.size):
                process_descriptor_read(parsed_bar.addr)
            elif is_addr_within_crm_cfg_region(parsed_bar.addr, parsed_bar.size):
                # Read from host into a CRM register checking health of FW
                # Return dummy completion message with val = 0 indicating no errors in FW and FW healthy
                logger.debug("CRM region read, sending back dummy completion message")
                fw_state.conn.sendall(gen_dummy_cmpl_msg(parsed_bar))
                set_host_interrupt()
            else:
                raise ValueError("Invalid BAR read address or size")
        case FbnicEmuCmd.FBNICEMU_CMD_BAR_CMPL:
            logger.info("Received FBNICEMU_CMD_BAR_CMPL cmd")
        case FbnicEmuCmd.FBNICEMU_CMD_RET:
            logger.info("Received FBNICEMU_CMD_RET cmd")

    return


def main():
    parser = argparse.ArgumentParser(
        description="Mock firmware server for testing",
        epilog="Example: ./%(prog)s /tmp/fbnic-ctrl-skt",
    )
    parser.add_argument(
        "socket_path",
        nargs="?",
        default=None,
        help="Path to the Unix domain socket (omit when using systemd socket activation)",
    )
    parser.add_argument(
        "-d",
        "--debug",
        help="Print debugging statements",
        action="store_true",
        dest="debug",
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(levelname)s: %(name)s: %(funcName)s: %(message)s",
    )
    logger.debug("Debugging enabled")

    socket_path = args.socket_path
    sd_sock = _get_systemd_socket()

    if sd_sock is not None:
        # Socket activation path: fd 3 is an already-connected socket.
        logger.info("Using systemd socket activation")
        fw_state.conn = sd_sock
        server_sock = None
    elif socket_path is not None:
        # Standalone path: create our own listening socket.
        server_sock = setup_socket(socket_path)
        fw_state.conn, _ = server_sock.accept()
        logger.info("Client connected")
    else:
        logger.error(
            "No socket path provided and systemd socket activation not detected"
        )
        sys.exit(1)

    try:
        # Always notify the host that we are ready to accept messages
        set_host_interrupt()
        while True:
            # Use recvmsg to receive both data and file descriptors
            fds_bytes = REMOTE_MAX_FDS * array.array("i").itemsize
            anc_buf_size = socket.CMSG_SPACE(fds_bytes)

            try:
                msgs, ancdata, flags, addr = fw_state.conn.recvmsg(
                    PAGE_SIZE, anc_buf_size
                )
            except BlockingIOError:
                continue

            if not msgs:
                break

            # Extract file descriptors from ancillary data
            received_fds = []
            for cmsg_level, cmsg_type, cmsg_data in ancdata:
                if cmsg_level == socket.SOL_SOCKET and cmsg_type == socket.SCM_RIGHTS:
                    # Unpack file descriptors from ancillary data
                    fds_array = array.array("i")
                    fds_array.frombytes(cmsg_data)
                    received_fds = list(fds_array)
                    break

            if received_fds:
                logger.debug(f"Received file descriptors: {received_fds}")

            # Messages sometimes get bundled together, so process all of them
            process_all_msgs(msgs, received_fds)

    finally:
        if server_sock is not None:
            server_sock.close()
            if os.path.exists(socket_path):
                os.remove(socket_path)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
