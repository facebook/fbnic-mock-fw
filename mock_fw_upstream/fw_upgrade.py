import errno
import logging

logger = logging.getLogger(__name__)


class FwUpgradeManager:
    def __init__(self):
        self.in_progress = False
        self.img_length = 0
        self.offset = 0
        self.requested_length = 0

    def start_firmware_upgrade(self, img_length: int) -> int:
        if img_length == 0:
            logger.error("Invalid image length")
            return errno.EINVAL

        if self.in_progress:
            logger.error("Firmware update already in progress")
            return errno.EBUSY

        self.in_progress = True
        self.img_length = img_length
        self.offset = 0

        return 0
