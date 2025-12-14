"""
Configuration restore functionality for network devices.

Supports restoring configurations via:
- SCP/SFTP upload
- REST API POST/PUT
- NETCONF edit-config
- CLI paste (screen scraping)
- Vendor-specific methods

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import asyncio
import logging
import tempfile
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from globaldetect.backup.models import (
    DeviceCredential,
    DeviceVendor,
    BackupType,
)

logger = logging.getLogger(__name__)


class RestoreMethod(str, Enum):
    """Method to restore configuration."""
    SCP = "scp"
    SFTP = "sftp"
    TFTP = "tftp"
    FTP = "ftp"
    HTTP_POST = "http_post"
    HTTP_PUT = "http_put"
    REST_API = "rest_api"
    NETCONF = "netconf"
    CLI_PASTE = "cli_paste"
    CLI_LOAD = "cli_load"  # Load from device storage
    VENDOR_API = "vendor_api"


class RestoreMode(str, Enum):
    """How to apply the restored configuration."""
    MERGE = "merge"  # Merge with running config
    REPLACE = "replace"  # Replace running config
    OVERRIDE = "override"  # Complete override (wipe + load)
    CANDIDATE = "candidate"  # Load to candidate config (commit separately)


@dataclass
class RestoreResult:
    """Result of a restore operation."""
    success: bool = False
    method: RestoreMethod | None = None
    mode: RestoreMode | None = None

    # What was restored
    backup_file: str | None = None
    backup_type: BackupType | None = None

    # Timing
    started_at: datetime | None = None
    completed_at: datetime | None = None
    duration_seconds: float | None = None

    # Status
    error_message: str | None = None
    warnings: list[str] | None = None
    changes_applied: int | None = None

    # Verification
    verified: bool = False
    verification_output: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "method": self.method.value if self.method else None,
            "mode": self.mode.value if self.mode else None,
            "backup_file": self.backup_file,
            "backup_type": self.backup_type.value if self.backup_type else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "error_message": self.error_message,
            "warnings": self.warnings,
            "changes_applied": self.changes_applied,
            "verified": self.verified,
            "verification_output": self.verification_output,
        }


class BaseRestorer(ABC):
    """Abstract base class for configuration restore."""

    VENDOR: DeviceVendor = DeviceVendor.UNKNOWN
    SUPPORTED_METHODS: list[RestoreMethod] = []
    DEFAULT_METHOD: RestoreMethod = RestoreMethod.SCP

    def __init__(self, credential: DeviceCredential):
        """Initialize restorer.

        Args:
            credential: Device credentials
        """
        self.credential = credential
        self._connection = None

    @property
    def hostname(self) -> str:
        return self.credential.device_hostname or self.credential.device_ip or "unknown"

    @abstractmethod
    async def restore(
        self,
        config_content: str | bytes,
        method: RestoreMethod | None = None,
        mode: RestoreMode = RestoreMode.MERGE,
        backup_type: BackupType = BackupType.FULL,
        verify: bool = True,
    ) -> RestoreResult:
        """Restore configuration to device.

        Args:
            config_content: Configuration content
            method: Restore method to use
            mode: How to apply the config
            backup_type: Type of backup being restored
            verify: Whether to verify after restore

        Returns:
            RestoreResult
        """
        pass

    async def verify_restore(self) -> tuple[bool, str]:
        """Verify configuration was applied correctly.

        Returns:
            Tuple of (success, verification_output)
        """
        return True, "Verification not implemented"


class CiscoRestorer(BaseRestorer):
    """Restore configurations to Cisco devices."""

    VENDOR = DeviceVendor.CISCO_IOS
    SUPPORTED_METHODS = [
        RestoreMethod.SCP,
        RestoreMethod.TFTP,
        RestoreMethod.CLI_PASTE,
    ]
    DEFAULT_METHOD = RestoreMethod.SCP

    async def restore(
        self,
        config_content: str | bytes,
        method: RestoreMethod | None = None,
        mode: RestoreMode = RestoreMode.MERGE,
        backup_type: BackupType = BackupType.FULL,
        verify: bool = True,
    ) -> RestoreResult:
        """Restore config to Cisco IOS device."""
        method = method or self.DEFAULT_METHOD
        result = RestoreResult(
            method=method,
            mode=mode,
            backup_type=backup_type,
            started_at=datetime.now(),
        )

        try:
            if isinstance(config_content, bytes):
                config_content = config_content.decode('utf-8')

            if method == RestoreMethod.SCP:
                await self._restore_via_scp(config_content, mode, result)
            elif method == RestoreMethod.TFTP:
                await self._restore_via_tftp(config_content, mode, result)
            elif method == RestoreMethod.CLI_PASTE:
                await self._restore_via_cli(config_content, mode, result)
            else:
                result.error_message = f"Unsupported method: {method}"
                return result

            if verify and result.success:
                result.verified, result.verification_output = await self.verify_restore()

        except Exception as e:
            result.error_message = str(e)
            logger.exception(f"Restore failed for {self.hostname}")

        finally:
            result.completed_at = datetime.now()
            if result.started_at:
                result.duration_seconds = (result.completed_at - result.started_at).total_seconds()

        return result

    async def _restore_via_scp(
        self,
        config: str,
        mode: RestoreMode,
        result: RestoreResult
    ) -> None:
        """Restore via SCP upload."""
        import asyncssh

        # Write config to temp file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
            f.write(config)
            temp_path = f.name

        try:
            # Connect and upload
            async with asyncssh.connect(
                self.credential.device_ip or self.hostname,
                username=self.credential.username,
                password=self.credential.password,
                known_hosts=None,
            ) as conn:
                # Upload to device flash
                remote_path = "flash:restore_config.txt"
                await asyncssh.scp(temp_path, (conn, remote_path))

                # Apply configuration
                if mode == RestoreMode.REPLACE:
                    cmd = f"configure replace {remote_path} force"
                else:
                    cmd = f"copy {remote_path} running-config"

                result_output = await conn.run(cmd, check=False)

                if "error" not in result_output.stdout.lower():
                    result.success = True

                    # Save to startup-config
                    await conn.run("copy running-config startup-config", check=False)

        finally:
            Path(temp_path).unlink(missing_ok=True)

    async def _restore_via_tftp(
        self,
        config: str,
        mode: RestoreMode,
        result: RestoreResult
    ) -> None:
        """Restore via TFTP (requires TFTP server)."""
        result.error_message = "TFTP restore requires external TFTP server setup"
        # Would need to write config to TFTP server, then:
        # copy tftp://server/config running-config

    async def _restore_via_cli(
        self,
        config: str,
        mode: RestoreMode,
        result: RestoreResult
    ) -> None:
        """Restore by pasting config via CLI."""
        import pexpect
        from pexpect import pxssh

        ssh = pxssh.pxssh()
        ssh.login(
            self.hostname,
            self.credential.username,
            self.credential.password,
        )

        try:
            # Enter config mode
            ssh.sendline("configure terminal")
            ssh.expect(r"\(config\)#")

            # Paste config line by line
            lines_applied = 0
            for line in config.splitlines():
                line = line.strip()
                if not line or line.startswith("!"):
                    continue

                ssh.sendline(line)
                ssh.expect(r"[>#]", timeout=5)

                # Check for errors
                if "invalid" in ssh.after.lower() or "error" in ssh.after.lower():
                    result.warnings = result.warnings or []
                    result.warnings.append(f"Warning on: {line}")
                else:
                    lines_applied += 1

            ssh.sendline("end")
            ssh.expect(r"#")

            # Save config
            ssh.sendline("write memory")
            ssh.expect(r"#")

            result.success = True
            result.changes_applied = lines_applied

        finally:
            ssh.logout()


class PaloAltoRestorer(BaseRestorer):
    """Restore configurations to Palo Alto firewalls."""

    VENDOR = DeviceVendor.PALO_ALTO
    SUPPORTED_METHODS = [
        RestoreMethod.REST_API,
        RestoreMethod.SCP,
    ]
    DEFAULT_METHOD = RestoreMethod.REST_API

    async def restore(
        self,
        config_content: str | bytes,
        method: RestoreMethod | None = None,
        mode: RestoreMode = RestoreMode.MERGE,
        backup_type: BackupType = BackupType.FULL,
        verify: bool = True,
    ) -> RestoreResult:
        """Restore config to Palo Alto firewall."""
        method = method or self.DEFAULT_METHOD
        result = RestoreResult(
            method=method,
            mode=mode,
            backup_type=backup_type,
            started_at=datetime.now(),
        )

        try:
            if isinstance(config_content, bytes):
                config_content = config_content.decode('utf-8')

            if method == RestoreMethod.REST_API:
                await self._restore_via_api(config_content, mode, result)
            elif method == RestoreMethod.SCP:
                await self._restore_via_scp(config_content, mode, result)
            else:
                result.error_message = f"Unsupported method: {method}"
                return result

        except Exception as e:
            result.error_message = str(e)

        finally:
            result.completed_at = datetime.now()
            if result.started_at:
                result.duration_seconds = (result.completed_at - result.started_at).total_seconds()

        return result

    async def _restore_via_api(
        self,
        config: str,
        mode: RestoreMode,
        result: RestoreResult
    ) -> None:
        """Restore via PAN-OS API."""
        import aiohttp

        host = self.credential.device_ip or self.hostname
        base_url = f"https://{host}/api/"

        async with aiohttp.ClientSession() as session:
            # Import configuration
            params = {
                "type": "import",
                "category": "configuration",
                "key": self.credential.api_key or self.credential.api_token,
            }

            # Upload config file
            data = aiohttp.FormData()
            data.add_field('file', config, filename='restore.xml')

            async with session.post(base_url, params=params, data=data, ssl=False) as resp:
                if resp.status != 200:
                    result.error_message = f"Import failed: {resp.status}"
                    return

            # Load configuration
            params = {
                "type": "op",
                "cmd": "<load><config><from>restore.xml</from></config></load>",
                "key": self.credential.api_key or self.credential.api_token,
            }

            async with session.get(base_url, params=params, ssl=False) as resp:
                if resp.status != 200:
                    result.error_message = f"Load failed: {resp.status}"
                    return

            # Commit configuration
            params = {
                "type": "commit",
                "cmd": "<commit></commit>",
                "key": self.credential.api_key or self.credential.api_token,
            }

            async with session.get(base_url, params=params, ssl=False) as resp:
                if resp.status == 200:
                    result.success = True
                else:
                    result.error_message = f"Commit failed: {resp.status}"

    async def _restore_via_scp(
        self,
        config: str,
        mode: RestoreMode,
        result: RestoreResult
    ) -> None:
        """Restore via SCP to Palo Alto."""
        import asyncssh

        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            f.write(config)
            temp_path = f.name

        try:
            async with asyncssh.connect(
                self.credential.device_ip or self.hostname,
                username=self.credential.username,
                password=self.credential.password,
                known_hosts=None,
            ) as conn:
                # SCP to device
                await asyncssh.scp(temp_path, (conn, "/tmp/restore.xml"))

                # Load config via CLI
                load_cmd = "load config from /tmp/restore.xml"
                await conn.run(load_cmd, check=False)

                # Commit
                commit_cmd = "commit"
                commit_result = await conn.run(commit_cmd, check=False)

                if "successfully" in commit_result.stdout.lower():
                    result.success = True

        finally:
            Path(temp_path).unlink(missing_ok=True)


class JuniperRestorer(BaseRestorer):
    """Restore configurations to Juniper devices."""

    VENDOR = DeviceVendor.JUNIPER_JUNOS
    SUPPORTED_METHODS = [
        RestoreMethod.NETCONF,
        RestoreMethod.SCP,
        RestoreMethod.CLI_LOAD,
    ]
    DEFAULT_METHOD = RestoreMethod.NETCONF

    async def restore(
        self,
        config_content: str | bytes,
        method: RestoreMethod | None = None,
        mode: RestoreMode = RestoreMode.MERGE,
        backup_type: BackupType = BackupType.FULL,
        verify: bool = True,
    ) -> RestoreResult:
        """Restore config to Juniper JunOS device."""
        method = method or self.DEFAULT_METHOD
        result = RestoreResult(
            method=method,
            mode=mode,
            backup_type=backup_type,
            started_at=datetime.now(),
        )

        try:
            if isinstance(config_content, bytes):
                config_content = config_content.decode('utf-8')

            if method == RestoreMethod.NETCONF:
                await self._restore_via_netconf(config_content, mode, result)
            elif method == RestoreMethod.SCP:
                await self._restore_via_scp(config_content, mode, result)
            else:
                result.error_message = f"Unsupported method: {method}"

        except Exception as e:
            result.error_message = str(e)

        finally:
            result.completed_at = datetime.now()
            if result.started_at:
                result.duration_seconds = (result.completed_at - result.started_at).total_seconds()

        return result

    async def _restore_via_netconf(
        self,
        config: str,
        mode: RestoreMode,
        result: RestoreResult
    ) -> None:
        """Restore via NETCONF."""
        from ncclient import manager

        # Determine NETCONF operation
        if mode == RestoreMode.REPLACE:
            default_operation = "replace"
        elif mode == RestoreMode.OVERRIDE:
            default_operation = "replace"
        else:
            default_operation = "merge"

        loop = asyncio.get_event_loop()

        def do_netconf():
            with manager.connect(
                host=self.credential.device_ip or self.hostname,
                port=830,
                username=self.credential.username,
                password=self.credential.password,
                hostkey_verify=False,
            ) as m:
                # Lock config
                m.lock("candidate")

                try:
                    # Edit config
                    m.edit_config(
                        target="candidate",
                        config=config,
                        default_operation=default_operation,
                    )

                    # Validate
                    m.validate("candidate")

                    # Commit
                    m.commit()

                    return True, "Configuration committed successfully"

                except Exception as e:
                    m.discard_changes()
                    return False, str(e)

                finally:
                    m.unlock("candidate")

        success, message = await loop.run_in_executor(None, do_netconf)
        result.success = success
        if not success:
            result.error_message = message

    async def _restore_via_scp(
        self,
        config: str,
        mode: RestoreMode,
        result: RestoreResult
    ) -> None:
        """Restore via SCP and CLI load."""
        import asyncssh

        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
            f.write(config)
            temp_path = f.name

        try:
            async with asyncssh.connect(
                self.credential.device_ip or self.hostname,
                username=self.credential.username,
                password=self.credential.password,
                known_hosts=None,
            ) as conn:
                # Upload config
                await asyncssh.scp(temp_path, (conn, "/var/tmp/restore.conf"))

                # Load config
                if mode == RestoreMode.REPLACE:
                    load_cmd = "load override /var/tmp/restore.conf"
                elif mode == RestoreMode.OVERRIDE:
                    load_cmd = "load override /var/tmp/restore.conf"
                else:
                    load_cmd = "load merge /var/tmp/restore.conf"

                # Enter config mode and load
                cmds = [
                    "configure",
                    load_cmd,
                    "commit and-quit",
                ]

                for cmd in cmds:
                    output = await conn.run(cmd, check=False)
                    if "error" in output.stderr.lower():
                        result.error_message = f"Failed at: {cmd}"
                        return

                result.success = True

        finally:
            Path(temp_path).unlink(missing_ok=True)


class FortiGateRestorer(BaseRestorer):
    """Restore configurations to FortiGate firewalls."""

    VENDOR = DeviceVendor.FORTINET
    SUPPORTED_METHODS = [
        RestoreMethod.REST_API,
        RestoreMethod.SCP,
    ]
    DEFAULT_METHOD = RestoreMethod.REST_API

    async def restore(
        self,
        config_content: str | bytes,
        method: RestoreMethod | None = None,
        mode: RestoreMode = RestoreMode.MERGE,
        backup_type: BackupType = BackupType.FULL,
        verify: bool = True,
    ) -> RestoreResult:
        """Restore config to FortiGate firewall."""
        method = method or self.DEFAULT_METHOD
        result = RestoreResult(
            method=method,
            mode=mode,
            backup_type=backup_type,
            started_at=datetime.now(),
        )

        try:
            if method == RestoreMethod.REST_API:
                await self._restore_via_api(config_content, mode, result)
            else:
                result.error_message = f"Unsupported method: {method}"

        except Exception as e:
            result.error_message = str(e)

        finally:
            result.completed_at = datetime.now()
            if result.started_at:
                result.duration_seconds = (result.completed_at - result.started_at).total_seconds()

        return result

    async def _restore_via_api(
        self,
        config: str | bytes,
        mode: RestoreMode,
        result: RestoreResult
    ) -> None:
        """Restore via FortiGate REST API."""
        import aiohttp

        host = self.credential.device_ip or self.hostname
        base_url = f"https://{host}/api/v2/"

        headers = {
            "Authorization": f"Bearer {self.credential.api_token}",
        }

        async with aiohttp.ClientSession() as session:
            # Upload and restore config
            restore_url = f"{base_url}monitor/system/config/restore"

            data = aiohttp.FormData()
            if isinstance(config, str):
                config = config.encode('utf-8')
            data.add_field('file', config, filename='restore.conf')
            data.add_field('scope', 'global')

            async with session.post(
                restore_url,
                headers=headers,
                data=data,
                ssl=False
            ) as resp:
                if resp.status == 200:
                    result.success = True
                else:
                    text = await resp.text()
                    result.error_message = f"Restore failed: {resp.status} - {text}"


class InfobloxRestorer(BaseRestorer):
    """Restore configurations to Infoblox appliances."""

    VENDOR = DeviceVendor.INFOBLOX
    SUPPORTED_METHODS = [RestoreMethod.REST_API]
    DEFAULT_METHOD = RestoreMethod.REST_API

    async def restore(
        self,
        config_content: str | bytes,
        method: RestoreMethod | None = None,
        mode: RestoreMode = RestoreMode.MERGE,
        backup_type: BackupType = BackupType.FULL,
        verify: bool = True,
    ) -> RestoreResult:
        """Restore config to Infoblox via WAPI."""
        result = RestoreResult(
            method=RestoreMethod.REST_API,
            mode=mode,
            backup_type=backup_type,
            started_at=datetime.now(),
        )

        try:
            await self._restore_via_api(config_content, mode, result)
        except Exception as e:
            result.error_message = str(e)
        finally:
            result.completed_at = datetime.now()
            if result.started_at:
                result.duration_seconds = (result.completed_at - result.started_at).total_seconds()

        return result

    async def _restore_via_api(
        self,
        config: str | bytes,
        mode: RestoreMode,
        result: RestoreResult
    ) -> None:
        """Restore via Infoblox WAPI."""
        import aiohttp
        import base64

        host = self.credential.device_ip or self.hostname
        base_url = f"https://{host}/wapi/v2.12/"

        auth_string = f"{self.credential.username}:{self.credential.password}"
        auth_bytes = base64.b64encode(auth_string.encode()).decode()

        headers = {
            "Authorization": f"Basic {auth_bytes}",
            "Content-Type": "application/json",
        }

        async with aiohttp.ClientSession() as session:
            # Infoblox uses fileop for restore
            # First, upload the backup file
            upload_url = f"{base_url}fileop?_function=uploadinit"

            async with session.post(upload_url, headers=headers, ssl=False) as resp:
                if resp.status != 200:
                    result.error_message = "Failed to initialize upload"
                    return

                upload_data = await resp.json()
                token = upload_data.get("token")
                upload_path = upload_data.get("url")

            # Upload the file
            if isinstance(config, str):
                config = config.encode('utf-8')

            data = aiohttp.FormData()
            data.add_field('file', config, filename='restore.tar.gz')

            async with session.post(upload_path, data=data, ssl=False) as resp:
                if resp.status != 200:
                    result.error_message = "Failed to upload backup"
                    return

            # Trigger restore
            restore_url = f"{base_url}fileop?_function=restorebackup"
            restore_data = {"token": token}

            async with session.post(
                restore_url,
                headers=headers,
                json=restore_data,
                ssl=False
            ) as resp:
                if resp.status == 200:
                    result.success = True
                else:
                    result.error_message = f"Restore failed: {resp.status}"


# Mapping of vendors to restorer classes
RESTORER_MAP = {
    DeviceVendor.CISCO_IOS: CiscoRestorer,
    DeviceVendor.CISCO_IOS_XE: CiscoRestorer,
    DeviceVendor.CISCO_NXOS: CiscoRestorer,
    DeviceVendor.CISCO_ASA: CiscoRestorer,
    DeviceVendor.PALO_ALTO: PaloAltoRestorer,
    DeviceVendor.JUNIPER_JUNOS: JuniperRestorer,
    DeviceVendor.FORTINET: FortiGateRestorer,
    DeviceVendor.INFOBLOX: InfobloxRestorer,
}


def get_restorer_class(vendor: DeviceVendor):
    """Get the appropriate restorer class for a vendor.

    Args:
        vendor: Device vendor

    Returns:
        Restorer class or None
    """
    return RESTORER_MAP.get(vendor)
