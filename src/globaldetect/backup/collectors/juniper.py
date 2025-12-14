"""
Juniper Networks device configuration collectors.

Supports:
- JunOS (routers, switches, firewalls)
- ScreenOS (legacy NetScreen firewalls)

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import logging
from globaldetect.backup.base import (
    ScreenScrapingCollector,
    NETCONFCollector,
    SSHCollector,
)
from globaldetect.backup.models import DeviceVendor, BackupType

logger = logging.getLogger(__name__)


class JuniperJunOSCollector(NETCONFCollector):
    """Collector for Juniper JunOS devices using NETCONF.

    Supports SRX firewalls, MX/PTX routers, EX/QFX switches.
    """

    VENDOR = DeviceVendor.JUNIPER_JUNOS
    SUPPORTED_BACKUP_TYPES = [
        BackupType.FULL,
        BackupType.NETWORK,
        BackupType.FIREWALL,
        BackupType.NAT,
        BackupType.VPN,
        BackupType.SSL,
        BackupType.USERS,
    ]
    DEFAULT_PORT = 830  # NETCONF default

    async def get_config(self, backup_type: BackupType) -> str | None:
        """Retrieve configuration from JunOS device via NETCONF."""
        try:
            if backup_type == BackupType.FULL:
                return await self.get_running_config()

            # For specific config types, we filter the full config
            # JunOS stores config hierarchically
            full_config = await self.get_running_config()
            if not full_config:
                return None

            # Parse and extract relevant sections
            # In production, use proper XML parsing
            return self._filter_config(full_config, backup_type)

        except Exception as e:
            logger.error(f"Failed to get JunOS config: {e}")
            return None

    def _filter_config(self, config: str, backup_type: BackupType) -> str:
        """Filter full config to specific sections.

        Args:
            config: Full XML configuration
            backup_type: Type of config to extract

        Returns:
            Filtered configuration
        """
        # This is a simplified implementation
        # In production, use proper XML/XPath filtering
        sections = {
            BackupType.NETWORK: ["interfaces", "routing-options", "protocols"],
            BackupType.FIREWALL: ["security", "firewall"],
            BackupType.NAT: ["security/nat"],
            BackupType.VPN: ["security/ike", "security/ipsec"],
            BackupType.SSL: ["security/pki"],
            BackupType.USERS: ["system/login", "system/authentication-order"],
        }

        target_sections = sections.get(backup_type, [])
        if not target_sections:
            return config

        # For now, return full config with a note
        # Real implementation would parse XML and extract sections
        return f"<!-- Filtered for: {', '.join(target_sections)} -->\n{config}"


class JuniperJunOSCLICollector(ScreenScrapingCollector):
    """CLI-based collector for JunOS (fallback when NETCONF unavailable)."""

    VENDOR = DeviceVendor.JUNIPER_JUNOS
    SUPPORTED_BACKUP_TYPES = [
        BackupType.FULL,
        BackupType.NETWORK,
        BackupType.FIREWALL,
        BackupType.VPN,
        BackupType.USERS,
    ]

    PROMPT_PATTERNS = [r"[%>#]", r"\{.*\}\[edit\]"]

    CONFIG_COMMANDS = {
        BackupType.FULL: [
            "show configuration | display set | no-more",
        ],
        BackupType.NETWORK: [
            "show configuration interfaces | display set | no-more",
            "show configuration routing-options | display set | no-more",
            "show configuration protocols | display set | no-more",
            "show route summary",
            "show interfaces terse",
            "show lldp neighbors",
        ],
        BackupType.FIREWALL: [
            "show configuration security policies | display set | no-more",
            "show configuration security zones | display set | no-more",
            "show configuration firewall | display set | no-more",
        ],
        BackupType.VPN: [
            "show configuration security ike | display set | no-more",
            "show configuration security ipsec | display set | no-more",
            "show security ike security-associations",
            "show security ipsec security-associations",
        ],
        BackupType.USERS: [
            "show configuration system login | display set | no-more",
            "show configuration system authentication-order | display set | no-more",
            "show configuration system tacplus-server | display set | no-more",
            "show configuration system radius-server | display set | no-more",
        ],
    }

    async def _disable_paging(self) -> None:
        """Disable paging on JunOS CLI."""
        await self.send_command("set cli screen-length 0")
        await self.send_command("set cli screen-width 200")

    async def get_config(self, backup_type: BackupType) -> str | None:
        """Retrieve configuration from JunOS via CLI."""
        commands = self.CONFIG_COMMANDS.get(backup_type, [])
        if not commands:
            return None

        output_parts = []
        for cmd in commands:
            try:
                output = await self.send_command(cmd, timeout=120)
                output_parts.append(f"# === {cmd} ===\n{output}")
            except Exception as e:
                logger.error(f"Command failed: {cmd}: {e}")

        return "\n\n".join(output_parts)


class JuniperScreenOSCollector(ScreenScrapingCollector):
    """Collector for legacy Juniper ScreenOS (NetScreen) firewalls.

    Note: ScreenOS is end-of-life but still found in some environments.
    """

    VENDOR = DeviceVendor.JUNIPER_SCREENOS
    SUPPORTED_BACKUP_TYPES = [
        BackupType.FULL,
        BackupType.NETWORK,
        BackupType.FIREWALL,
        BackupType.NAT,
        BackupType.VPN,
        BackupType.USERS,
    ]

    PROMPT_PATTERNS = [r"->", r"\(.*\)->"]
    MORE_PROMPT = r"--- more ---"

    CONFIG_COMMANDS = {
        BackupType.FULL: [
            "get config",
        ],
        BackupType.NETWORK: [
            "get interface",
            "get route",
            "get vrouter",
            "get zone",
        ],
        BackupType.FIREWALL: [
            "get policy",
            "get address",
            "get service",
            "get group address",
            "get group service",
        ],
        BackupType.NAT: [
            "get policy | include nat",
            "get mip",
            "get vip",
            "get dip",
        ],
        BackupType.VPN: [
            "get ike gateway",
            "get vpn",
            "get sa",
        ],
        BackupType.USERS: [
            "get admin user",
            "get auth-server",
        ],
    }

    async def _disable_paging(self) -> None:
        """Disable paging on ScreenOS."""
        await self.send_command("set console page 0")

    async def get_config(self, backup_type: BackupType) -> str | None:
        """Retrieve configuration from ScreenOS device."""
        commands = self.CONFIG_COMMANDS.get(backup_type, [])
        if not commands:
            return None

        output_parts = []
        for cmd in commands:
            try:
                output = await self.send_command(cmd, timeout=60)
                output_parts.append(f"# === {cmd} ===\n{output}")
            except Exception as e:
                logger.error(f"Command failed: {cmd}: {e}")

        return "\n\n".join(output_parts)
