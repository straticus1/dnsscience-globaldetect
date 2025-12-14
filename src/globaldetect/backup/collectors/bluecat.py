"""
BlueCat Address Manager configuration collector.

Supports BlueCat DDI appliances via REST API.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import logging
from globaldetect.backup.base import APICollector
from globaldetect.backup.models import DeviceVendor, BackupType, DeviceCredential
from globaldetect.backup.storage import BackupStorage

logger = logging.getLogger(__name__)


class BlueCatCollector(APICollector):
    """Collector for BlueCat Address Manager appliances."""

    VENDOR = DeviceVendor.BLUECAT
    SUPPORTED_BACKUP_TYPES = [
        BackupType.FULL,
        BackupType.DNS,
        BackupType.DHCP,
        BackupType.NETWORK,  # IPAM
        BackupType.USERS,
    ]
    DEFAULT_PORT = 443
    API_VERSION = "v1"

    def __init__(self, credential: DeviceCredential, storage: BackupStorage, **kwargs):
        super().__init__(credential, storage, **kwargs)
        host = credential.device_ip or credential.device_hostname
        self.BASE_URL = f"https://{host}/api/{self.API_VERSION}/"
        self._token = None

    async def connect(self) -> bool:
        """Connect and authenticate to BlueCat API."""
        try:
            import aiohttp
            self._session = aiohttp.ClientSession()

            # Authenticate and get token
            auth_url = f"{self.BASE_URL}login"
            async with self._session.get(
                auth_url,
                params={
                    "username": self.credential.username,
                    "password": self.credential.password
                },
                ssl=False
            ) as resp:
                if resp.status == 200:
                    data = await resp.text()
                    # Token is returned as: "Session Token-> BAMAuthToken: <token>"
                    if "BAMAuthToken:" in data:
                        self._token = data.split("BAMAuthToken:")[1].strip()
                        return True
                logger.error(f"BlueCat auth failed: {resp.status}")
                return False

        except ImportError:
            logger.error("aiohttp not installed")
            return False
        except Exception as e:
            logger.error(f"BlueCat connection failed: {e}")
            return False

    async def disconnect(self) -> None:
        """Logout and close session."""
        if self._session and self._token:
            try:
                await self.api_get("logout")
            except Exception:
                pass
        await super().disconnect()
        self._token = None

    def _get_auth_headers(self) -> dict:
        """BlueCat uses token in Authorization header."""
        headers = {"Content-Type": "application/json"}
        if self._token:
            headers["Authorization"] = f"BAMAuthToken: {self._token}"
        return headers

    async def _verify_api(self) -> bool:
        """Verify API connectivity."""
        return self._token is not None

    async def get_config(self, backup_type: BackupType) -> str | None:
        """Retrieve configuration from BlueCat Address Manager."""
        import json

        try:
            if backup_type == BackupType.FULL:
                parts = []

                # Get all configurations
                configs = await self._get_configurations()
                parts.append(f"# Configurations\n{json.dumps(configs, indent=2)}")

                # For each configuration, get DNS and IPAM data
                for config in configs:
                    config_id = config.get("id")
                    if config_id:
                        # DNS zones
                        zones = await self._get_dns_zones(config_id)
                        parts.append(f"# DNS Zones (Config: {config.get('name')})\n{json.dumps(zones, indent=2)}")

                        # IP blocks and networks
                        networks = await self._get_ip_blocks(config_id)
                        parts.append(f"# IP Blocks (Config: {config.get('name')})\n{json.dumps(networks, indent=2)}")

                return "\n\n".join(parts)

            elif backup_type == BackupType.DNS:
                parts = []
                configs = await self._get_configurations()

                for config in configs:
                    config_id = config.get("id")
                    if config_id:
                        # DNS views
                        views = await self._get_dns_views(config_id)
                        parts.append(f"# DNS Views (Config: {config.get('name')})\n{json.dumps(views, indent=2)}")

                        # DNS zones
                        zones = await self._get_dns_zones(config_id)
                        parts.append(f"# DNS Zones (Config: {config.get('name')})\n{json.dumps(zones, indent=2)}")

                return "\n\n".join(parts)

            elif backup_type == BackupType.DHCP:
                parts = []
                configs = await self._get_configurations()

                for config in configs:
                    config_id = config.get("id")
                    if config_id:
                        # DHCP ranges
                        ranges = await self._get_dhcp_ranges(config_id)
                        parts.append(f"# DHCP Ranges (Config: {config.get('name')})\n{json.dumps(ranges, indent=2)}")

                return "\n\n".join(parts)

            elif backup_type == BackupType.NETWORK:
                parts = []
                configs = await self._get_configurations()

                for config in configs:
                    config_id = config.get("id")
                    if config_id:
                        # IP blocks
                        blocks = await self._get_ip_blocks(config_id)
                        parts.append(f"# IP Blocks (Config: {config.get('name')})\n{json.dumps(blocks, indent=2)}")

                return "\n\n".join(parts)

            elif backup_type == BackupType.USERS:
                # Users and groups
                users = await self._get_users()
                return f"# Users\n{json.dumps(users, indent=2)}"

            else:
                logger.warning(f"Unsupported backup type: {backup_type}")
                return None

        except Exception as e:
            logger.error(f"Failed to get BlueCat config: {e}")
            return None

    async def _get_configurations(self) -> list:
        """Get all configurations."""
        try:
            result = await self.api_get("getEntities", {
                "parentId": 0,
                "type": "Configuration",
                "start": 0,
                "count": 1000
            })
            return result if isinstance(result, list) else []
        except Exception:
            return []

    async def _get_dns_views(self, config_id: int) -> list:
        """Get DNS views for a configuration."""
        try:
            result = await self.api_get("getEntities", {
                "parentId": config_id,
                "type": "View",
                "start": 0,
                "count": 1000
            })
            return result if isinstance(result, list) else []
        except Exception:
            return []

    async def _get_dns_zones(self, config_id: int) -> list:
        """Get DNS zones for a configuration."""
        zones = []
        views = await self._get_dns_views(config_id)

        for view in views:
            view_id = view.get("id")
            if view_id:
                try:
                    result = await self.api_get("getEntities", {
                        "parentId": view_id,
                        "type": "Zone",
                        "start": 0,
                        "count": 10000
                    })
                    if isinstance(result, list):
                        for zone in result:
                            zone["view_name"] = view.get("name")
                        zones.extend(result)
                except Exception:
                    pass

        return zones

    async def _get_ip_blocks(self, config_id: int) -> list:
        """Get IP blocks and networks for a configuration."""
        try:
            # Get top-level IP blocks
            blocks = await self.api_get("getEntities", {
                "parentId": config_id,
                "type": "IP4Block",
                "start": 0,
                "count": 10000
            })

            # Also get networks
            networks = await self.api_get("getEntities", {
                "parentId": config_id,
                "type": "IP4Network",
                "start": 0,
                "count": 10000
            })

            result = []
            if isinstance(blocks, list):
                result.extend(blocks)
            if isinstance(networks, list):
                result.extend(networks)

            return result
        except Exception:
            return []

    async def _get_dhcp_ranges(self, config_id: int) -> list:
        """Get DHCP ranges for a configuration."""
        ranges = []
        blocks = await self._get_ip_blocks(config_id)

        for block in blocks:
            block_id = block.get("id")
            if block_id:
                try:
                    result = await self.api_get("getEntities", {
                        "parentId": block_id,
                        "type": "DHCP4Range",
                        "start": 0,
                        "count": 10000
                    })
                    if isinstance(result, list):
                        ranges.extend(result)
                except Exception:
                    pass

        return ranges

    async def _get_users(self) -> list:
        """Get users and access rights."""
        try:
            result = await self.api_get("getEntities", {
                "parentId": 0,
                "type": "User",
                "start": 0,
                "count": 1000
            })
            return result if isinstance(result, list) else []
        except Exception:
            return []
