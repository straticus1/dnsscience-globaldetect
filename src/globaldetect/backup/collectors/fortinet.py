"""
Fortinet FortiGate device configuration collector.

Supports FortiOS firewalls via API and CLI.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import logging
from globaldetect.backup.base import APICollector, ScreenScrapingCollector
from globaldetect.backup.models import DeviceVendor, BackupType, DeviceCredential
from globaldetect.backup.storage import BackupStorage

logger = logging.getLogger(__name__)


class FortiGateCollector(APICollector):
    """Collector for Fortinet FortiGate firewalls using REST API."""

    VENDOR = DeviceVendor.FORTINET
    SUPPORTED_BACKUP_TYPES = [
        BackupType.FULL,
        BackupType.NETWORK,
        BackupType.FIREWALL,
        BackupType.NAT,
        BackupType.VPN,
        BackupType.SSL,
        BackupType.USERS,
        BackupType.DHCP,
        BackupType.DNS,
    ]
    DEFAULT_PORT = 443

    def __init__(self, credential: DeviceCredential, storage: BackupStorage, **kwargs):
        super().__init__(credential, storage, **kwargs)
        host = credential.device_ip or credential.device_hostname
        self.BASE_URL = f"https://{host}/api/v2/"

    def _get_auth_headers(self) -> dict:
        """FortiGate uses API token in Authorization header."""
        headers = {"Content-Type": "application/json"}
        if self.credential.api_token:
            headers["Authorization"] = f"Bearer {self.credential.api_token}"
        return headers

    async def _verify_api(self) -> bool:
        """Verify API connectivity."""
        try:
            result = await self.api_get("monitor/system/status")
            return "results" in result or "version" in result
        except Exception as e:
            logger.error(f"API verification failed: {e}")
            return False

    async def get_config(self, backup_type: BackupType) -> str | None:
        """Retrieve configuration from FortiGate firewall."""
        try:
            if backup_type == BackupType.FULL:
                # Get full backup
                result = await self.api_get("monitor/system/config/backup", {
                    "scope": "global"
                })
                return str(result) if result else None

            elif backup_type == BackupType.NETWORK:
                parts = []

                # Interfaces
                result = await self.api_get("cmdb/system/interface")
                if result:
                    parts.append(f"# Interfaces\n{self._format_result(result)}")

                # Static routes
                result = await self.api_get("cmdb/router/static")
                if result:
                    parts.append(f"# Static Routes\n{self._format_result(result)}")

                # BGP
                result = await self.api_get("cmdb/router/bgp")
                if result:
                    parts.append(f"# BGP Configuration\n{self._format_result(result)}")

                # OSPF
                result = await self.api_get("cmdb/router/ospf")
                if result:
                    parts.append(f"# OSPF Configuration\n{self._format_result(result)}")

                # Zones
                result = await self.api_get("cmdb/system/zone")
                if result:
                    parts.append(f"# Zones\n{self._format_result(result)}")

                return "\n\n".join(parts)

            elif backup_type == BackupType.FIREWALL:
                parts = []

                # Firewall policies
                result = await self.api_get("cmdb/firewall/policy")
                if result:
                    parts.append(f"# Firewall Policies\n{self._format_result(result)}")

                # Address objects
                result = await self.api_get("cmdb/firewall/address")
                if result:
                    parts.append(f"# Address Objects\n{self._format_result(result)}")

                # Address groups
                result = await self.api_get("cmdb/firewall/addrgrp")
                if result:
                    parts.append(f"# Address Groups\n{self._format_result(result)}")

                # Service objects
                result = await self.api_get("cmdb/firewall.service/custom")
                if result:
                    parts.append(f"# Service Objects\n{self._format_result(result)}")

                # Service groups
                result = await self.api_get("cmdb/firewall.service/group")
                if result:
                    parts.append(f"# Service Groups\n{self._format_result(result)}")

                return "\n\n".join(parts)

            elif backup_type == BackupType.NAT:
                parts = []

                # Central NAT
                result = await self.api_get("cmdb/firewall/central-snat-map")
                if result:
                    parts.append(f"# Central SNAT\n{self._format_result(result)}")

                # VIPs (DNAT)
                result = await self.api_get("cmdb/firewall/vip")
                if result:
                    parts.append(f"# Virtual IPs (DNAT)\n{self._format_result(result)}")

                # IP pools
                result = await self.api_get("cmdb/firewall/ippool")
                if result:
                    parts.append(f"# IP Pools\n{self._format_result(result)}")

                return "\n\n".join(parts)

            elif backup_type == BackupType.VPN:
                parts = []

                # IPsec Phase1
                result = await self.api_get("cmdb/vpn.ipsec/phase1-interface")
                if result:
                    parts.append(f"# IPsec Phase1\n{self._format_result(result)}")

                # IPsec Phase2
                result = await self.api_get("cmdb/vpn.ipsec/phase2-interface")
                if result:
                    parts.append(f"# IPsec Phase2\n{self._format_result(result)}")

                # SSL VPN settings
                result = await self.api_get("cmdb/vpn.ssl/settings")
                if result:
                    parts.append(f"# SSL VPN Settings\n{self._format_result(result)}")

                # SSL VPN portals
                result = await self.api_get("cmdb/vpn.ssl.web/portal")
                if result:
                    parts.append(f"# SSL VPN Portals\n{self._format_result(result)}")

                return "\n\n".join(parts)

            elif backup_type == BackupType.SSL:
                parts = []

                # Certificates
                result = await self.api_get("cmdb/certificate/local")
                if result:
                    parts.append(f"# Local Certificates\n{self._format_result(result)}")

                # CA certificates
                result = await self.api_get("cmdb/certificate/ca")
                if result:
                    parts.append(f"# CA Certificates\n{self._format_result(result)}")

                # SSL inspection
                result = await self.api_get("cmdb/firewall/ssl-ssh-profile")
                if result:
                    parts.append(f"# SSL Inspection Profiles\n{self._format_result(result)}")

                return "\n\n".join(parts)

            elif backup_type == BackupType.USERS:
                parts = []

                # Admin users
                result = await self.api_get("cmdb/system/admin")
                if result:
                    parts.append(f"# Admin Users\n{self._format_result(result)}")

                # Local users
                result = await self.api_get("cmdb/user/local")
                if result:
                    parts.append(f"# Local Users\n{self._format_result(result)}")

                # User groups
                result = await self.api_get("cmdb/user/group")
                if result:
                    parts.append(f"# User Groups\n{self._format_result(result)}")

                # LDAP servers
                result = await self.api_get("cmdb/user/ldap")
                if result:
                    parts.append(f"# LDAP Servers\n{self._format_result(result)}")

                # RADIUS servers
                result = await self.api_get("cmdb/user/radius")
                if result:
                    parts.append(f"# RADIUS Servers\n{self._format_result(result)}")

                return "\n\n".join(parts)

            elif backup_type == BackupType.DHCP:
                result = await self.api_get("cmdb/system.dhcp/server")
                return f"# DHCP Servers\n{self._format_result(result)}" if result else None

            elif backup_type == BackupType.DNS:
                parts = []

                # DNS settings
                result = await self.api_get("cmdb/system/dns")
                if result:
                    parts.append(f"# DNS Settings\n{self._format_result(result)}")

                # DNS database
                result = await self.api_get("cmdb/system/dns-database")
                if result:
                    parts.append(f"# DNS Database\n{self._format_result(result)}")

                return "\n\n".join(parts)

            else:
                logger.warning(f"Unsupported backup type: {backup_type}")
                return None

        except Exception as e:
            logger.error(f"Failed to get FortiGate config: {e}")
            return None

    def _format_result(self, result: dict) -> str:
        """Format API result for storage."""
        import json
        return json.dumps(result, indent=2)


class FortiGateCLICollector(ScreenScrapingCollector):
    """CLI-based collector for FortiGate (fallback when API not available)."""

    VENDOR = DeviceVendor.FORTINET
    SUPPORTED_BACKUP_TYPES = [
        BackupType.FULL,
        BackupType.NETWORK,
        BackupType.FIREWALL,
        BackupType.VPN,
        BackupType.USERS,
    ]

    PROMPT_PATTERNS = [r"[#$]", r"\(.+\)\s*[#$]"]

    CONFIG_COMMANDS = {
        BackupType.FULL: [
            "show full-configuration",
        ],
        BackupType.NETWORK: [
            "show system interface",
            "show router static",
            "show router bgp",
            "show router ospf",
            "get router info routing-table all",
        ],
        BackupType.FIREWALL: [
            "show firewall policy",
            "show firewall address",
            "show firewall addrgrp",
            "show firewall service custom",
            "show firewall service group",
        ],
        BackupType.VPN: [
            "show vpn ipsec phase1-interface",
            "show vpn ipsec phase2-interface",
            "show vpn ssl settings",
            "diagnose vpn ike gateway list",
            "diagnose vpn tunnel list",
        ],
        BackupType.USERS: [
            "show system admin",
            "show user local",
            "show user group",
            "show user ldap",
            "show user radius",
        ],
    }

    async def _disable_paging(self) -> None:
        """Disable paging on FortiOS."""
        await self.send_command("config system console")
        await self.send_command("set output standard")
        await self.send_command("end")

    async def get_config(self, backup_type: BackupType) -> str | None:
        """Retrieve configuration from FortiGate via CLI."""
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
