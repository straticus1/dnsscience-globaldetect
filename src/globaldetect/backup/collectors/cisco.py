"""
Cisco device configuration collectors.

Supports:
- IOS/IOS-XE (routers, switches)
- NX-OS (Nexus switches)
- ASA (firewalls)

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import logging
from globaldetect.backup.base import ScreenScrapingCollector, SSHCollector
from globaldetect.backup.models import DeviceVendor, BackupType

logger = logging.getLogger(__name__)


class CiscoIOSCollector(ScreenScrapingCollector):
    """Collector for Cisco IOS and IOS-XE devices."""

    VENDOR = DeviceVendor.CISCO_IOS
    SUPPORTED_BACKUP_TYPES = [
        BackupType.FULL,
        BackupType.NETWORK,
        BackupType.FIREWALL,  # ACLs
        BackupType.VPN,
        BackupType.USERS,
    ]

    PROMPT_PATTERNS = [r"[>#]", r"\(config.*\)#"]

    # Commands to retrieve different config types
    CONFIG_COMMANDS = {
        BackupType.FULL: [
            "show running-config",
        ],
        BackupType.NETWORK: [
            "show running-config | section interface",
            "show running-config | section router",
            "show running-config | section ip route",
            "show ip route",
            "show ip interface brief",
            "show cdp neighbors detail",
            "show lldp neighbors detail",
        ],
        BackupType.FIREWALL: [
            "show running-config | section access-list",
            "show access-lists",
            "show ip access-lists",
        ],
        BackupType.VPN: [
            "show running-config | section crypto",
            "show crypto isakmp sa",
            "show crypto ipsec sa",
        ],
        BackupType.USERS: [
            "show running-config | section username",
            "show running-config | section aaa",
            "show running-config | section tacacs",
            "show running-config | section radius",
        ],
    }

    async def _disable_paging(self) -> None:
        """Disable --More-- prompts on Cisco IOS."""
        await self.send_command("terminal length 0")
        await self.send_command("terminal width 500")

    async def get_config(self, backup_type: BackupType) -> str | None:
        """Retrieve configuration from Cisco IOS device.

        Args:
            backup_type: Type of configuration to retrieve

        Returns:
            Configuration content or None
        """
        commands = self.CONFIG_COMMANDS.get(backup_type, [])
        if not commands:
            logger.warning(f"No commands defined for backup type: {backup_type}")
            return None

        output_parts = []
        for cmd in commands:
            try:
                output = await self.send_command(cmd, timeout=60)
                output_parts.append(f"! === {cmd} ===\n{output}")
            except Exception as e:
                logger.error(f"Command failed: {cmd}: {e}")
                output_parts.append(f"! === {cmd} === (FAILED: {e})")

        return "\n\n".join(output_parts)


class CiscoNXOSCollector(ScreenScrapingCollector):
    """Collector for Cisco NX-OS devices (Nexus switches)."""

    VENDOR = DeviceVendor.CISCO_NXOS
    SUPPORTED_BACKUP_TYPES = [
        BackupType.FULL,
        BackupType.NETWORK,
        BackupType.FIREWALL,
        BackupType.VPN,
        BackupType.USERS,
    ]

    PROMPT_PATTERNS = [r"[>#]", r"\(config.*\)#"]

    CONFIG_COMMANDS = {
        BackupType.FULL: [
            "show running-config",
        ],
        BackupType.NETWORK: [
            "show running-config interface",
            "show running-config | section 'router|routing'",
            "show ip route vrf all",
            "show interface brief",
            "show vpc",
            "show port-channel summary",
            "show vlan",
            "show cdp neighbors detail",
            "show lldp neighbors detail",
        ],
        BackupType.FIREWALL: [
            "show running-config aclmgr",
            "show access-lists",
            "show running-config copp",
        ],
        BackupType.VPN: [
            "show running-config | section 'tunnel|nve'",
        ],
        BackupType.USERS: [
            "show running-config | section 'username|role|aaa|tacacs|radius'",
        ],
    }

    async def _disable_paging(self) -> None:
        """Disable paging on NX-OS."""
        await self.send_command("terminal length 0")
        await self.send_command("terminal width 511")

    async def get_config(self, backup_type: BackupType) -> str | None:
        """Retrieve configuration from NX-OS device."""
        commands = self.CONFIG_COMMANDS.get(backup_type, [])
        if not commands:
            return None

        output_parts = []
        for cmd in commands:
            try:
                output = await self.send_command(cmd, timeout=60)
                output_parts.append(f"! === {cmd} ===\n{output}")
            except Exception as e:
                logger.error(f"Command failed: {cmd}: {e}")

        return "\n\n".join(output_parts)


class CiscoASACollector(ScreenScrapingCollector):
    """Collector for Cisco ASA firewalls."""

    VENDOR = DeviceVendor.CISCO_ASA
    SUPPORTED_BACKUP_TYPES = [
        BackupType.FULL,
        BackupType.NETWORK,
        BackupType.FIREWALL,
        BackupType.NAT,
        BackupType.VPN,
        BackupType.SSL,
        BackupType.USERS,
    ]

    PROMPT_PATTERNS = [r"[>#]", r"\(config.*\)#"]

    CONFIG_COMMANDS = {
        BackupType.FULL: [
            "show running-config",
        ],
        BackupType.NETWORK: [
            "show running-config interface",
            "show running-config route",
            "show running-config router",
            "show interface ip brief",
            "show route",
        ],
        BackupType.FIREWALL: [
            "show running-config access-list",
            "show running-config access-group",
            "show running-config object",
            "show running-config object-group",
            "show access-list",
        ],
        BackupType.NAT: [
            "show running-config nat",
            "show running-config object | include nat",
            "show nat detail",
            "show xlate",
        ],
        BackupType.VPN: [
            "show running-config crypto",
            "show running-config tunnel-group",
            "show running-config group-policy",
            "show running-config webvpn",
            "show vpn-sessiondb",
            "show crypto isakmp sa",
            "show crypto ipsec sa",
        ],
        BackupType.SSL: [
            "show running-config ssl",
            "show crypto ca certificates",
            "show crypto key mypubkey rsa",
        ],
        BackupType.USERS: [
            "show running-config username",
            "show running-config aaa",
            "show running-config aaa-server",
        ],
    }

    async def _disable_paging(self) -> None:
        """Disable paging on ASA."""
        await self.send_command("terminal pager 0")

    async def get_config(self, backup_type: BackupType) -> str | None:
        """Retrieve configuration from ASA firewall."""
        commands = self.CONFIG_COMMANDS.get(backup_type, [])
        if not commands:
            return None

        output_parts = []
        for cmd in commands:
            try:
                output = await self.send_command(cmd, timeout=120)
                output_parts.append(f"! === {cmd} ===\n{output}")
            except Exception as e:
                logger.error(f"Command failed: {cmd}: {e}")

        return "\n\n".join(output_parts)


class CiscoIOSXRCollector(ScreenScrapingCollector):
    """Collector for Cisco IOS-XR devices (high-end routers)."""

    VENDOR = DeviceVendor.CISCO_IOS_XR
    SUPPORTED_BACKUP_TYPES = [
        BackupType.FULL,
        BackupType.NETWORK,
        BackupType.FIREWALL,
        BackupType.VPN,
        BackupType.USERS,
    ]

    PROMPT_PATTERNS = [r"[>#]", r"\(config.*\)#", r"RP/\d+/.*#"]

    CONFIG_COMMANDS = {
        BackupType.FULL: [
            "show running-config",
        ],
        BackupType.NETWORK: [
            "show running-config interface",
            "show running-config router",
            "show running-config route-policy",
            "show route",
            "show interface brief",
            "show bgp summary",
            "show isis neighbors",
            "show ospf neighbor",
            "show lldp neighbors",
        ],
        BackupType.FIREWALL: [
            "show running-config ipv4 access-list",
            "show running-config ipv6 access-list",
            "show access-lists",
        ],
        BackupType.VPN: [
            "show running-config crypto",
            "show running-config l2vpn",
            "show running-config segment-routing",
        ],
        BackupType.USERS: [
            "show running-config username",
            "show running-config aaa",
            "show running-config tacacs",
            "show running-config radius",
        ],
    }

    async def _disable_paging(self) -> None:
        """Disable paging on IOS-XR."""
        await self.send_command("terminal length 0")
        await self.send_command("terminal width 512")

    async def get_config(self, backup_type: BackupType) -> str | None:
        """Retrieve configuration from IOS-XR device."""
        commands = self.CONFIG_COMMANDS.get(backup_type, [])
        if not commands:
            return None

        output_parts = []
        for cmd in commands:
            try:
                output = await self.send_command(cmd, timeout=120)
                output_parts.append(f"!! === {cmd} ===\n{output}")
            except Exception as e:
                logger.error(f"Command failed: {cmd}: {e}")

        return "\n\n".join(output_parts)
