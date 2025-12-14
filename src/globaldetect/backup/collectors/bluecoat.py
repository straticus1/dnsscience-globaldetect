"""
Blue Coat (Symantec/Broadcom) ProxySG configuration collector.

Supports ProxySG appliances via CLI (SSH).

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import logging
from globaldetect.backup.base import ScreenScrapingCollector
from globaldetect.backup.models import DeviceVendor, BackupType

logger = logging.getLogger(__name__)


class BlueCoatCollector(ScreenScrapingCollector):
    """Collector for Blue Coat ProxySG appliances.

    Note: Blue Coat was acquired by Symantec, then Broadcom.
    Still widely deployed as ProxySG / Web Security Gateway.
    """

    VENDOR = DeviceVendor.BLUECOAT
    SUPPORTED_BACKUP_TYPES = [
        BackupType.FULL,
        BackupType.NETWORK,
        BackupType.SSL,
        BackupType.USERS,
        BackupType.DNS,
    ]

    PROMPT_PATTERNS = [r"[>#]", r"\(config.*\)#"]
    MORE_PROMPT = r"--More--"

    CONFIG_COMMANDS = {
        BackupType.FULL: [
            "show configuration",
        ],
        BackupType.NETWORK: [
            "show interface all",
            "show ip-route-table",
            "show static-routes",
            "show dns",
            "show wccp status",
            "show wccp services",
        ],
        BackupType.SSL: [
            "show ssl",
            "show ssl device-profile",
            "show ssl keyring",
            "show ssl ca-certificate",
            "show ssl ccl",
            "show ssl-intercept",
        ],
        BackupType.USERS: [
            "show admin",
            "show authentication",
            "show radius",
            "show ldap",
            "show local-user-list",
        ],
        BackupType.DNS: [
            "show dns",
            "show dns-forwarding",
            "show dns servers",
        ],
    }

    # Additional commands for comprehensive backup
    FULL_BACKUP_COMMANDS = [
        # System
        "show version",
        "show hardware",
        "show license",

        # Network
        "show interface all",
        "show ip-route-table",
        "show static-routes",
        "show dns",
        "show wccp status",

        # Proxy settings
        "show http",
        "show https",
        "show ftp",
        "show socks",
        "show transparent-proxy",
        "show proxy-services",

        # Policy
        "show policy",
        "show vpm",
        "show content-filter",
        "show url-filter",

        # SSL
        "show ssl",
        "show ssl device-profile",
        "show ssl-intercept",

        # Authentication
        "show authentication",
        "show admin",
        "show radius",
        "show ldap",

        # Logging
        "show access-log",
        "show event-log",

        # Health
        "show health-check",
        "show services",
    ]

    async def _disable_paging(self) -> None:
        """Disable paging on Blue Coat ProxySG."""
        await self.send_command("terminal length 0")

    async def get_config(self, backup_type: BackupType) -> str | None:
        """Retrieve configuration from Blue Coat ProxySG."""
        try:
            if backup_type == BackupType.FULL:
                # Get comprehensive configuration
                return await self._get_full_config()

            commands = self.CONFIG_COMMANDS.get(backup_type, [])
            if not commands:
                return None

            output_parts = []
            for cmd in commands:
                try:
                    output = await self.send_command(cmd, timeout=120)
                    output_parts.append(f"; === {cmd} ===\n{output}")
                except Exception as e:
                    logger.error(f"Command failed: {cmd}: {e}")

            return "\n\n".join(output_parts)

        except Exception as e:
            logger.error(f"Failed to get Blue Coat config: {e}")
            return None

    async def _get_full_config(self) -> str:
        """Get full configuration using show configuration and supplementary commands."""
        output_parts = []

        # Primary configuration dump
        try:
            config = await self.send_command("show configuration", timeout=300)
            output_parts.append(f"; === Full Configuration ===\n{config}")
        except Exception as e:
            logger.error(f"Failed to get full configuration: {e}")

        # Supplementary commands for additional context
        for cmd in self.FULL_BACKUP_COMMANDS:
            try:
                output = await self.send_command(cmd, timeout=60)
                if output and "command not found" not in output.lower():
                    output_parts.append(f"; === {cmd} ===\n{output}")
            except Exception as e:
                logger.debug(f"Optional command failed: {cmd}: {e}")

        return "\n\n".join(output_parts)


class BlueCoatAPICollector:
    """API-based collector for Blue Coat (placeholder for future implementation).

    Note: Blue Coat Management Center (BCMC) provides REST API for
    centralized management. This would require separate implementation.
    """

    VENDOR = DeviceVendor.BLUECOAT
    SUPPORTED_BACKUP_TYPES = [BackupType.FULL]

    def __init__(self, *args, **kwargs):
        raise NotImplementedError(
            "Blue Coat API collector not yet implemented. "
            "Use BlueCoatCollector (CLI/SSH) instead."
        )
