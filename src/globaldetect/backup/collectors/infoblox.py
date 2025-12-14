"""
Infoblox NIOS configuration collector.

Supports Infoblox DDI (DNS, DHCP, IPAM) appliances via WAPI REST API.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import logging
import base64
from globaldetect.backup.base import APICollector
from globaldetect.backup.models import DeviceVendor, BackupType, DeviceCredential
from globaldetect.backup.storage import BackupStorage

logger = logging.getLogger(__name__)


class InfobloxCollector(APICollector):
    """Collector for Infoblox NIOS appliances using WAPI."""

    VENDOR = DeviceVendor.INFOBLOX
    SUPPORTED_BACKUP_TYPES = [
        BackupType.FULL,
        BackupType.DNS,
        BackupType.DHCP,
        BackupType.NETWORK,  # IPAM data
        BackupType.USERS,
    ]
    DEFAULT_PORT = 443
    WAPI_VERSION = "v2.12"  # Adjust based on NIOS version

    def __init__(self, credential: DeviceCredential, storage: BackupStorage, **kwargs):
        super().__init__(credential, storage, **kwargs)
        host = credential.device_ip or credential.device_hostname
        self.BASE_URL = f"https://{host}/wapi/{self.WAPI_VERSION}/"

    def _get_auth_headers(self) -> dict:
        """Infoblox WAPI uses HTTP Basic Auth."""
        headers = {"Content-Type": "application/json"}
        if self.credential.username and self.credential.password:
            auth_string = f"{self.credential.username}:{self.credential.password}"
            auth_bytes = base64.b64encode(auth_string.encode()).decode()
            headers["Authorization"] = f"Basic {auth_bytes}"
        return headers

    async def _verify_api(self) -> bool:
        """Verify API connectivity by getting grid info."""
        try:
            result = await self.api_get("grid")
            return isinstance(result, list) and len(result) > 0
        except Exception as e:
            logger.error(f"API verification failed: {e}")
            return False

    async def get_config(self, backup_type: BackupType) -> str | None:
        """Retrieve configuration from Infoblox NIOS."""
        import json

        try:
            if backup_type == BackupType.FULL:
                # Export full database via fileop
                parts = []

                # Grid settings
                result = await self.api_get("grid", {"_return_fields+": "name,ntp_setting,dns_resolver_setting"})
                if result:
                    parts.append(f"# Grid Configuration\n{json.dumps(result, indent=2)}")

                # All zones
                zones = await self._get_all_dns_zones()
                parts.append(f"# DNS Zones\n{json.dumps(zones, indent=2)}")

                # All networks
                networks = await self._get_all_networks()
                parts.append(f"# Networks\n{json.dumps(networks, indent=2)}")

                # DHCP ranges
                dhcp = await self._get_all_dhcp()
                parts.append(f"# DHCP Configuration\n{json.dumps(dhcp, indent=2)}")

                return "\n\n".join(parts)

            elif backup_type == BackupType.DNS:
                parts = []

                # DNS views
                result = await self.api_get("view", {"_return_fields": "name,is_default,network_view"})
                if result:
                    parts.append(f"# DNS Views\n{json.dumps(result, indent=2)}")

                # All zones with records
                zones = await self._get_all_dns_zones()
                parts.append(f"# DNS Zones\n{json.dumps(zones, indent=2)}")

                # DNS members/servers
                result = await self.api_get("member:dns", {"_return_fields+": "host_name,enable_dns"})
                if result:
                    parts.append(f"# DNS Members\n{json.dumps(result, indent=2)}")

                return "\n\n".join(parts)

            elif backup_type == BackupType.DHCP:
                parts = []

                # DHCP ranges
                result = await self.api_get("range", {
                    "_return_fields+": "network,start_addr,end_addr,member,options"
                })
                if result:
                    parts.append(f"# DHCP Ranges\n{json.dumps(result, indent=2)}")

                # Fixed addresses (reservations)
                result = await self.api_get("fixedaddress", {
                    "_return_fields+": "ipv4addr,mac,name,options"
                })
                if result:
                    parts.append(f"# Fixed Addresses\n{json.dumps(result, indent=2)}")

                # DHCP failover associations
                result = await self.api_get("dhcpfailover", {"_return_fields+": "name,primary,secondary"})
                if result:
                    parts.append(f"# DHCP Failover\n{json.dumps(result, indent=2)}")

                return "\n\n".join(parts)

            elif backup_type == BackupType.NETWORK:
                parts = []

                # Network views
                result = await self.api_get("networkview", {"_return_fields": "name,is_default"})
                if result:
                    parts.append(f"# Network Views\n{json.dumps(result, indent=2)}")

                # All networks (IPAM)
                networks = await self._get_all_networks()
                parts.append(f"# Networks\n{json.dumps(networks, indent=2)}")

                # Network containers
                result = await self.api_get("networkcontainer", {
                    "_return_fields+": "network,comment,extensible_attributes"
                })
                if result:
                    parts.append(f"# Network Containers\n{json.dumps(result, indent=2)}")

                return "\n\n".join(parts)

            elif backup_type == BackupType.USERS:
                parts = []

                # Admin users
                result = await self.api_get("adminuser", {
                    "_return_fields+": "name,admin_groups,email,auth_type"
                })
                if result:
                    parts.append(f"# Admin Users\n{json.dumps(result, indent=2)}")

                # Admin groups
                result = await self.api_get("admingroup", {
                    "_return_fields+": "name,roles,superuser"
                })
                if result:
                    parts.append(f"# Admin Groups\n{json.dumps(result, indent=2)}")

                # Auth policies
                result = await self.api_get("ldap_auth_service")
                if result:
                    parts.append(f"# LDAP Auth Services\n{json.dumps(result, indent=2)}")

                return "\n\n".join(parts)

            else:
                logger.warning(f"Unsupported backup type: {backup_type}")
                return None

        except Exception as e:
            logger.error(f"Failed to get Infoblox config: {e}")
            return None

    async def _get_all_dns_zones(self) -> list:
        """Get all DNS zones with their records."""
        zones = []

        # Authoritative zones
        result = await self.api_get("zone_auth", {
            "_return_fields+": "fqdn,view,zone_format,ns_group"
        })
        if result:
            for zone in result:
                zone["type"] = "authoritative"
                # Get records for each zone
                zone["records"] = await self._get_zone_records(zone.get("_ref", ""))
            zones.extend(result)

        # Delegated zones
        result = await self.api_get("zone_delegated", {
            "_return_fields+": "fqdn,delegate_to"
        })
        if result:
            for zone in result:
                zone["type"] = "delegated"
            zones.extend(result)

        # Forward zones
        result = await self.api_get("zone_forward", {
            "_return_fields+": "fqdn,forward_to"
        })
        if result:
            for zone in result:
                zone["type"] = "forward"
            zones.extend(result)

        return zones

    async def _get_zone_records(self, zone_ref: str) -> list:
        """Get all records for a zone."""
        records = []

        record_types = [
            "record:a", "record:aaaa", "record:cname",
            "record:mx", "record:txt", "record:srv",
            "record:ptr", "record:ns"
        ]

        for record_type in record_types:
            try:
                result = await self.api_get(record_type, {
                    "zone": zone_ref,
                    "_max_results": 10000
                })
                if result:
                    records.extend(result)
            except Exception:
                pass

        return records

    async def _get_all_networks(self) -> list:
        """Get all networks/subnets."""
        networks = []

        # IPv4 networks
        result = await self.api_get("network", {
            "_return_fields+": "network,comment,members,options,extensible_attributes",
            "_max_results": 10000
        })
        if result:
            networks.extend(result)

        # IPv6 networks
        result = await self.api_get("ipv6network", {
            "_return_fields+": "network,comment,members,options",
            "_max_results": 10000
        })
        if result:
            networks.extend(result)

        return networks

    async def _get_all_dhcp(self) -> dict:
        """Get all DHCP configuration."""
        return {
            "ranges": await self.api_get("range", {"_max_results": 10000}) or [],
            "fixed_addresses": await self.api_get("fixedaddress", {"_max_results": 10000}) or [],
            "leases": [],  # Skip leases for backup (too large, dynamic)
        }
