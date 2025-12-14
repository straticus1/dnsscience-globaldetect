"""
Palo Alto Networks device configuration collector.

Supports PAN-OS firewalls via both API and CLI.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import logging
import xml.etree.ElementTree as ET
from globaldetect.backup.base import APICollector, ScreenScrapingCollector
from globaldetect.backup.models import DeviceVendor, BackupType, DeviceCredential
from globaldetect.backup.storage import BackupStorage

logger = logging.getLogger(__name__)


class PaloAltoCollector(APICollector):
    """Collector for Palo Alto Networks firewalls using XML API."""

    VENDOR = DeviceVendor.PALO_ALTO
    SUPPORTED_BACKUP_TYPES = [
        BackupType.FULL,
        BackupType.NETWORK,
        BackupType.FIREWALL,
        BackupType.NAT,
        BackupType.VPN,
        BackupType.SSL,
        BackupType.USERS,
    ]
    DEFAULT_PORT = 443

    def __init__(self, credential: DeviceCredential, storage: BackupStorage, **kwargs):
        super().__init__(credential, storage, **kwargs)
        host = credential.device_ip or credential.device_hostname
        self.BASE_URL = f"https://{host}/api/"

    def _get_auth_headers(self) -> dict:
        """Palo Alto uses API key in URL parameter, not headers."""
        return {"Content-Type": "application/xml"}

    async def _verify_api(self) -> bool:
        """Verify API connectivity by getting system info."""
        try:
            result = await self._api_request("op", "<show><system><info></info></system></show>")
            return result is not None
        except Exception as e:
            logger.error(f"API verification failed: {e}")
            return False

    async def _api_request(self, req_type: str, cmd: str) -> str | None:
        """Make PAN-OS API request.

        Args:
            req_type: Request type (op, config, export, etc.)
            cmd: XML command

        Returns:
            Response XML or None
        """
        if not self._session:
            raise RuntimeError("Not connected")

        params = {
            "type": req_type,
            "key": self.credential.api_key or self.credential.api_token,
        }

        if req_type == "config":
            params["action"] = "show"
            params["xpath"] = cmd
        elif req_type == "export":
            params["category"] = cmd
        else:
            params["cmd"] = cmd

        async with self._session.get(
            self.BASE_URL,
            params=params,
            headers=self._get_auth_headers(),
            ssl=False
        ) as resp:
            if resp.status != 200:
                logger.error(f"API request failed: {resp.status}")
                return None
            return await resp.text()

    async def get_config(self, backup_type: BackupType) -> str | None:
        """Retrieve configuration from Palo Alto firewall."""
        try:
            if backup_type == BackupType.FULL:
                # Export full running config
                return await self._api_request("export", "configuration")

            elif backup_type == BackupType.NETWORK:
                parts = []
                # Network interfaces
                result = await self._api_request(
                    "config", "/config/devices/entry/network"
                )
                if result:
                    parts.append(f"<!-- Network Configuration -->\n{result}")

                # Virtual routers
                result = await self._api_request(
                    "config", "/config/devices/entry/network/virtual-router"
                )
                if result:
                    parts.append(f"<!-- Virtual Routers -->\n{result}")

                # Zones
                result = await self._api_request(
                    "config", "/config/devices/entry/vsys/entry/zone"
                )
                if result:
                    parts.append(f"<!-- Zones -->\n{result}")

                return "\n\n".join(parts)

            elif backup_type == BackupType.FIREWALL:
                parts = []
                # Security policies
                result = await self._api_request(
                    "config", "/config/devices/entry/vsys/entry/rulebase/security"
                )
                if result:
                    parts.append(f"<!-- Security Policies -->\n{result}")

                # Address objects
                result = await self._api_request(
                    "config", "/config/devices/entry/vsys/entry/address"
                )
                if result:
                    parts.append(f"<!-- Address Objects -->\n{result}")

                # Address groups
                result = await self._api_request(
                    "config", "/config/devices/entry/vsys/entry/address-group"
                )
                if result:
                    parts.append(f"<!-- Address Groups -->\n{result}")

                # Service objects
                result = await self._api_request(
                    "config", "/config/devices/entry/vsys/entry/service"
                )
                if result:
                    parts.append(f"<!-- Service Objects -->\n{result}")

                return "\n\n".join(parts)

            elif backup_type == BackupType.NAT:
                result = await self._api_request(
                    "config", "/config/devices/entry/vsys/entry/rulebase/nat"
                )
                return f"<!-- NAT Policies -->\n{result}" if result else None

            elif backup_type == BackupType.VPN:
                parts = []
                # IKE gateways
                result = await self._api_request(
                    "config", "/config/devices/entry/network/ike/gateway"
                )
                if result:
                    parts.append(f"<!-- IKE Gateways -->\n{result}")

                # IPsec tunnels
                result = await self._api_request(
                    "config", "/config/devices/entry/network/tunnel/ipsec"
                )
                if result:
                    parts.append(f"<!-- IPsec Tunnels -->\n{result}")

                # GlobalProtect
                result = await self._api_request(
                    "config", "/config/devices/entry/vsys/entry/global-protect"
                )
                if result:
                    parts.append(f"<!-- GlobalProtect -->\n{result}")

                return "\n\n".join(parts)

            elif backup_type == BackupType.SSL:
                parts = []
                # SSL/TLS profiles
                result = await self._api_request(
                    "config", "/config/devices/entry/network/profiles/ssl-tls-service-profile"
                )
                if result:
                    parts.append(f"<!-- SSL/TLS Profiles -->\n{result}")

                # Certificates
                result = await self._api_request("op", "<show><certificate></certificate></show>")
                if result:
                    parts.append(f"<!-- Certificates -->\n{result}")

                return "\n\n".join(parts)

            elif backup_type == BackupType.USERS:
                parts = []
                # Admin users
                result = await self._api_request(
                    "config", "/config/mgt-config/users"
                )
                if result:
                    parts.append(f"<!-- Admin Users -->\n{result}")

                # Auth profiles
                result = await self._api_request(
                    "config", "/config/devices/entry/vsys/entry/authentication-profile"
                )
                if result:
                    parts.append(f"<!-- Authentication Profiles -->\n{result}")

                return "\n\n".join(parts)

            else:
                logger.warning(f"Unsupported backup type: {backup_type}")
                return None

        except Exception as e:
            logger.error(f"Failed to get config: {e}")
            return None


class PaloAltoCLICollector(ScreenScrapingCollector):
    """Collector for Palo Alto firewalls via CLI (fallback when API not available)."""

    VENDOR = DeviceVendor.PALO_ALTO
    SUPPORTED_BACKUP_TYPES = [
        BackupType.FULL,
        BackupType.NETWORK,
        BackupType.FIREWALL,
        BackupType.VPN,
    ]

    PROMPT_PATTERNS = [r"[>#]", r"\(config.*\)#", r"admin@.*>"]

    CONFIG_COMMANDS = {
        BackupType.FULL: [
            "set cli config-output-format set",
            "show config running",
        ],
        BackupType.NETWORK: [
            "show interface all",
            "show routing route",
            "show routing protocol bgp summary",
            "show zone",
        ],
        BackupType.FIREWALL: [
            "show running security-policy",
            "show running nat-policy",
        ],
        BackupType.VPN: [
            "show vpn ike-sa",
            "show vpn ipsec-sa",
            "show global-protect-gateway current-user",
        ],
    }

    async def _disable_paging(self) -> None:
        """Disable paging on PAN-OS CLI."""
        await self.send_command("set cli pager off")

    async def get_config(self, backup_type: BackupType) -> str | None:
        """Retrieve configuration from PAN-OS CLI."""
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
