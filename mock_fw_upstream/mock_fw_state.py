import logging
import mmap
import os
import socket
import time
from dataclasses import dataclass, field
from enum import IntEnum

from mock_fw_upstream.coredump import CoredumpManager
from mock_fw_upstream.eeprom import EEPROMManager
from mock_fw_upstream.fw_upgrade import FwUpgradeManager

logger = logging.getLogger(__name__)

# Minimum firmware version that supports ALL capabilities
FW_VERSION = (25, 7, 25, 2)
FW_VERSION_COMMIT_STRING = "fw_ver_commit_str"
ACTIVE_PARTITION_ID = 0x0
CMRT_VERSION = (0, 0, 0, 0)
CMRT_VERSION_COMMIT_STRING = "cmrt_commit_str"
UEFI_VERSION = (0, 0, 0, 0)
UEFI_VERSION_COMMIT_STRING = "uefi_commit_str"
FW_STATE = 0x0
ANTI_ROLLBACK_VERSION = 0  # 0 when actual hardware register is not initialized


class LinkSpeed(IntEnum):
    FBNIC_UNKNOWN = 0
    FBNIC_25G = 1
    FBNIC_50G_R2 = 2
    FBNIC_50G_R1 = 3
    FBNIC_100G = 4


class LinkFec(IntEnum):
    FBNIC_FEC_UNKNOWN = 0
    FBNIC_FEC_NONE = 1
    FBNIC_FEC_RS = 2
    FBNIC_FEC_FC = 3


TEMP_MIN_THR = -1000  # -1°C
TEMP_WARN_THR = 95000  # 95°C (warning threshold)
TEMP_CRIT_THR = 105000  # 105°C (critical threshold)

VOLT_MIN_THR = 675  # 675mV
VOLT_MAX_THR = 825  # 825mV


@dataclass
class RemoteRegion:
    gpa: bytes
    size: int
    fd: int
    mm: mmap.mmap


@dataclass
class MockFwState:
    num_remote_regions: int
    remote_regions: list[RemoteRegion]
    conn: socket.socket | None = None
    _host_owns_nic: bool = False
    eeprom_manager: EEPROMManager = field(default_factory=EEPROMManager)
    coredump_manager: CoredumpManager = field(default_factory=CoredumpManager)
    fw_upgrade_manager: FwUpgradeManager = field(default_factory=FwUpgradeManager)
    _sensor_temp: int = 30000  # ensure within healthy range
    _sensor_volt: int = 750  # ensure within healthy range
    _link_speed: LinkSpeed = LinkSpeed.FBNIC_100G
    _max_link_speed: LinkSpeed = LinkSpeed.FBNIC_100G
    _link_fec: LinkFec = LinkFec.FBNIC_FEC_RS

    # Uptime tracking (in milliseconds)
    _start_time_ms = int(time.time() * 1000)

    def remote_sysmem_reset(self) -> None:
        for region in self.remote_regions:
            logger.debug(f"Closing remote mmap for fd {region.fd}")
            region.mm.close()
            os.close(region.fd)
        self.num_remote_regions = 0
        self.remote_regions = []
        return

    def get_uptime_ms(self) -> int:
        # Get firmware uptime in milliseconds since initialization

        current_time_ms = int(time.time() * 1000)
        return current_time_ms - self._start_time_ms

    def get_fw_version(self) -> int:
        major, minor, patch, build = FW_VERSION
        version = (major << 24) | (minor << 16) | (patch << 8) | build  # 32 bits
        logger.info(f"Firmware version: {major}.{minor}.{patch}.{build}")
        return version

    def get_fw_version_commit_string(self) -> str:
        return FW_VERSION_COMMIT_STRING

    def get_active_fw_slot(self) -> int:
        return ACTIVE_PARTITION_ID

    def get_cmrt_version(self) -> int:
        year, month, day, build = CMRT_VERSION
        version = (year << 24) | (month << 16) | (day << 8) | build  # 32 bits
        logger.debug(f"CMRT version: {year}.{month}.{day}-{build:03d}")
        return version

    def get_cmrt_commit_string(self) -> str:
        return CMRT_VERSION_COMMIT_STRING

    def get_uefi_version(self) -> int:
        major, minor, patch, build = UEFI_VERSION
        version = (major << 24) | (minor << 16) | (patch << 8) | build
        logger.info(f"UEFI version: {major}.{minor}.{patch}-{build:03d}")
        return version

    def get_uefi_commit_string(self) -> str:
        return UEFI_VERSION_COMMIT_STRING

    def get_hardware_fw_state(self) -> int:
        return FW_STATE

    def set_comphy_link_speed(self, link_speed: LinkSpeed) -> None:
        logger.debug(f"Setting link speed to {link_speed.name}")
        self._link_speed = link_speed
        return

    def get_comphy_link_speed(self) -> int:
        return self._link_speed

    def get_comphy_link_fec(self) -> int:
        return self._link_fec

    def get_comphy_max_link_speed(self) -> int:
        return self._max_link_speed

    def get_anti_rollback_version(self) -> int:
        return ANTI_ROLLBACK_VERSION

    def get_temp_min(self) -> int:
        return TEMP_MIN_THR

    def get_temp_warn(self) -> int:
        return TEMP_WARN_THR

    def get_temp_crit(self) -> int:
        return TEMP_CRIT_THR

    def get_volt_min(self) -> int:
        return VOLT_MIN_THR

    def get_volt_max(self) -> int:
        return VOLT_MAX_THR

    def get_curr_temp(self) -> int:
        return self._sensor_temp

    def get_curr_volt(self) -> int:
        return self._sensor_volt

    def get_host_owns_nic(self) -> bool:
        return self._host_owns_nic

    def set_host_owns_nic(self, host_owns_nic: bool) -> None:
        if self.get_host_owns_nic() == host_owns_nic:
            logger.info(
                f"Host already {'owns' if host_owns_nic else 'released'} the NIC"
            )
            return

        logger.info(f"Host {'now owns' if host_owns_nic else 'released'} the NIC")
        self._host_owns_nic = host_owns_nic


fw_state = MockFwState(num_remote_regions=0, remote_regions=[])
