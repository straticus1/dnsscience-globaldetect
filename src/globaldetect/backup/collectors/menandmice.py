"""
Men & Mice DDI configuration collector.

Supports Men & Mice Micetro (formerly Men & Mice Suite) via REST API.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import logging
import base64
from globaldetect.backup.base import APICollector
from globaldetect.backup.models import DeviceVendor, BackupType, DeviceCredential
from globaldetect.backup.storage import BackupStorage

logger = logging.getLogger(__name__)


class MenAndMiceCollector(APICollector):
    """Collector for Men & Mice Micetro DDI platform."""

    VENDOR = DeviceVendor.MEN_AND_MICE
    SUPPORTED_BACKUP_TYPES = [
        BackupType.FULL,
        BackupType.DNS,
        BackupType.DHCP,
        BackupType.NETWORK,  # IPAM
        BackupType.USERS,
    ]
    DEFAULT_PORT = 443

    def __init__(self, credential: DeviceCredential, storage: BackupStorage, **kwargs):
        super().__init__(credential, storage, **kwargs)
        host = credential.device_ip or credential.device_hostname
        self.BASE_URL = f"https://{host}/mmws/api/"

    def _get_auth_headers(self) -> dict:
        """Men & Mice uses HTTP Basic Auth."""
        headers = {"Content-Type": "application/json"}
        if self.credential.username and self.credential.password:
            auth_string = f"{self.credential.username}:{self.credential.password}"
            auth_bytes = base64.b64encode(auth_string.encode()).decode()
            headers["Authorization"] = f"Basic {auth_bytes}"
        return headers

    async def _verify_api(self) -> bool:
        """Verify API connectivity."""
        try:
            result = await self.api_get("Users/1")
            return result is not None
        except Exception as e:
            logger.error(f"API verification failed: {e}")
            return False

    async def get_config(self, backup_type: BackupType) -> str | None:
        """Retrieve configuration from Men & Mice."""
        import json

        try:
            if backup_type == BackupType.FULL:
                parts = []

                # DNS servers
                servers = await self._get_dns_servers()
                parts.append(f"# DNS Servers\n{json.dumps(servers, indent=2)}")

                # DNS zones
                zones = await self._get_dns_zones()
                parts.append(f"# DNS Zones\n{json.dumps(zones, indent=2)}")

                # DHCP servers
                dhcp_servers = await self._get_dhcp_servers()
                parts.append(f"# DHCP Servers\n{json.dumps(dhcp_servers, indent=2)}")

                # DHCP scopes
                scopes = await self._get_dhcp_scopes()
                parts.append(f"# DHCP Scopes\n{json.dumps(scopes, indent=2)}")

                # IP ranges
                ranges = await self._get_ip_ranges()
                parts.append(f"# IP Ranges\n{json.dumps(ranges, indent=2)}")

                return "\n\n".join(parts)

            elif backup_type == BackupType.DNS:
                parts = []

                # DNS servers
                servers = await self._get_dns_servers()
                parts.append(f"# DNS Servers\n{json.dumps(servers, indent=2)}")

                # DNS views
                views = await self._get_dns_views()
                parts.append(f"# DNS Views\n{json.dumps(views, indent=2)}")

                # DNS zones with records
                zones = await self._get_dns_zones()
                for zone in zones:
                    zone_ref = zone.get("ref", "")
                    if zone_ref:
                        records = await self._get_zone_records(zone_ref)
                        zone["records"] = records
                parts.append(f"# DNS Zones\n{json.dumps(zones, indent=2)}")

                return "\n\n".join(parts)

            elif backup_type == BackupType.DHCP:
                parts = []

                # DHCP servers
                servers = await self._get_dhcp_servers()
                parts.append(f"# DHCP Servers\n{json.dumps(servers, indent=2)}")

                # DHCP scopes
                scopes = await self._get_dhcp_scopes()
                parts.append(f"# DHCP Scopes\n{json.dumps(scopes, indent=2)}")

                # DHCP reservations
                reservations = await self._get_dhcp_reservations()
                parts.append(f"# DHCP Reservations\n{json.dumps(reservations, indent=2)}")

                # DHCP options
                options = await self._get_dhcp_options()
                parts.append(f"# DHCP Options\n{json.dumps(options, indent=2)}")

                return "\n\n".join(parts)

            elif backup_type == BackupType.NETWORK:
                parts = []

                # IP ranges (IPAM)
                ranges = await self._get_ip_ranges()
                parts.append(f"# IP Ranges\n{json.dumps(ranges, indent=2)}")

                # IP address claims
                claims = await self._get_ip_claims()
                parts.append(f"# IP Address Claims\n{json.dumps(claims, indent=2)}")

                return "\n\n".join(parts)

            elif backup_type == BackupType.USERS:
                parts = []

                # Users
                users = await self._get_users()
                parts.append(f"# Users\n{json.dumps(users, indent=2)}")

                # Groups
                groups = await self._get_groups()
                parts.append(f"# Groups\n{json.dumps(groups, indent=2)}")

                # Roles
                roles = await self._get_roles()
                parts.append(f"# Roles\n{json.dumps(roles, indent=2)}")

                return "\n\n".join(parts)

            else:
                logger.warning(f"Unsupported backup type: {backup_type}")
                return None

        except Exception as e:
            logger.error(f"Failed to get Men & Mice config: {e}")
            return None

    async def _get_dns_servers(self) -> list:
        """Get all DNS servers."""
        try:
            result = await self.api_get("DNSServers")
            return result.get("result", {}).get("dnsServers", [])
        except Exception:
            return []

    async def _get_dns_views(self) -> list:
        """Get all DNS views."""
        try:
            result = await self.api_get("DNSViews")
            return result.get("result", {}).get("dnsViews", [])
        except Exception:
            return []

    async def _get_dns_zones(self) -> list:
        """Get all DNS zones."""
        try:
            result = await self.api_get("DNSZones")
            return result.get("result", {}).get("dnsZones", [])
        except Exception:
            return []

    async def _get_zone_records(self, zone_ref: str) -> list:
        """Get records for a specific zone."""
        try:
            result = await self.api_get(f"DNSZones/{zone_ref}/DNSRecords")
            return result.get("result", {}).get("dnsRecords", [])
        except Exception:
            return []

    async def _get_dhcp_servers(self) -> list:
        """Get all DHCP servers."""
        try:
            result = await self.api_get("DHCPServers")
            return result.get("result", {}).get("dhcpServers", [])
        except Exception:
            return []

    async def _get_dhcp_scopes(self) -> list:
        """Get all DHCP scopes."""
        try:
            result = await self.api_get("DHCPScopes")
            return result.get("result", {}).get("dhcpScopes", [])
        except Exception:
            return []

    async def _get_dhcp_reservations(self) -> list:
        """Get all DHCP reservations."""
        try:
            result = await self.api_get("DHCPReservations")
            return result.get("result", {}).get("dhcpReservations", [])
        except Exception:
            return []

    async def _get_dhcp_options(self) -> list:
        """Get DHCP option definitions."""
        try:
            result = await self.api_get("DHCPOptionDefinitions")
            return result.get("result", {}).get("dhcpOptionDefinitions", [])
        except Exception:
            return []

    async def _get_ip_ranges(self) -> list:
        """Get all IP ranges."""
        try:
            result = await self.api_get("Ranges")
            return result.get("result", {}).get("ranges", [])
        except Exception:
            return []

    async def _get_ip_claims(self) -> list:
        """Get IP address claims/allocations."""
        try:
            result = await self.api_get("IPAMRecords")
            return result.get("result", {}).get("ipamRecords", [])
        except Exception:
            return []

    async def _get_users(self) -> list:
        """Get all users."""
        try:
            result = await self.api_get("Users")
            return result.get("result", {}).get("users", [])
        except Exception:
            return []

    async def _get_groups(self) -> list:
        """Get all groups."""
        try:
            result = await self.api_get("Groups")
            return result.get("result", {}).get("groups", [])
        except Exception:
            return []

    async def _get_roles(self) -> list:
        """Get all roles."""
        try:
            result = await self.api_get("Roles")
            return result.get("result", {}).get("roles", [])
        except Exception:
            return []
