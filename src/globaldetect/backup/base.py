"""
Base collector class for device configuration backup.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any

from globaldetect.backup.models import (
    DeviceCredential,
    DeviceVendor,
    BackupType,
    BackupResult,
    BackupStatus,
    DeviceLocation,
    CompressionType,
)
from globaldetect.backup.storage import BackupStorage

logger = logging.getLogger(__name__)


class BaseCollector(ABC):
    """Abstract base class for device configuration collectors."""

    # Subclasses must define these
    VENDOR: DeviceVendor = DeviceVendor.UNKNOWN
    SUPPORTED_BACKUP_TYPES: list[BackupType] = [BackupType.FULL]
    DEFAULT_PORT: int = 22  # SSH default

    def __init__(
        self,
        credential: DeviceCredential,
        storage: BackupStorage,
        location: DeviceLocation | None = None,
    ):
        """Initialize the collector.

        Args:
            credential: Device credentials
            storage: Backup storage handler
            location: Physical location of device
        """
        self.credential = credential
        self.storage = storage
        self.location = location
        self._connection: Any = None

    @property
    def hostname(self) -> str:
        """Get device hostname."""
        return self.credential.device_hostname or self.credential.device_ip or "unknown"

    @property
    def port(self) -> int:
        """Get connection port."""
        return self.credential.port or self.DEFAULT_PORT

    @abstractmethod
    async def connect(self) -> bool:
        """Establish connection to the device.

        Returns:
            True if connection successful
        """
        pass

    @abstractmethod
    async def disconnect(self) -> None:
        """Close connection to the device."""
        pass

    @abstractmethod
    async def get_config(self, backup_type: BackupType) -> str | None:
        """Retrieve configuration from the device.

        Args:
            backup_type: Type of configuration to retrieve

        Returns:
            Configuration content or None if failed
        """
        pass

    async def verify_connectivity(self) -> bool:
        """Verify we can reach the device.

        Returns:
            True if device is reachable
        """
        try:
            return await self.connect()
        except Exception as e:
            logger.error(f"Connectivity check failed for {self.hostname}: {e}")
            return False
        finally:
            await self.disconnect()

    async def backup(
        self,
        backup_types: list[BackupType] | None = None,
        compression: CompressionType = CompressionType.GZIP,
    ) -> BackupResult:
        """Perform backup of device configuration.

        Args:
            backup_types: Types to backup (defaults to all supported)
            compression: Compression to use

        Returns:
            BackupResult with status and file paths
        """
        if backup_types is None:
            backup_types = self.SUPPORTED_BACKUP_TYPES

        result = BackupResult(
            device_hostname=self.hostname,
            device_ip=self.credential.device_ip,
            device_vendor=self.VENDOR,
            backup_types=backup_types,
            compression=compression,
            started_at=datetime.now(),
            triggered_by="manual",
        )

        try:
            # Connect
            if not await self.connect():
                result.status = BackupStatus.FAILED
                result.error_message = "Failed to connect to device"
                result.completed_at = datetime.now()
                return result

            # Backup each type
            for backup_type in backup_types:
                if backup_type not in self.SUPPORTED_BACKUP_TYPES:
                    logger.warning(
                        f"Backup type {backup_type.value} not supported for {self.VENDOR.value}"
                    )
                    result.failed_types.append(backup_type)
                    continue

                try:
                    config = await self.get_config(backup_type)

                    if config:
                        # Save to storage
                        path, size = self.storage.save_backup(
                            content=config,
                            hostname=self.hostname,
                            backup_type=backup_type,
                            location=self.location,
                            compression=compression,
                        )

                        result.output_files.append(str(path))
                        result.total_size_bytes += size
                        result.successful_types.append(backup_type)

                        logger.info(
                            f"Backed up {backup_type.value} for {self.hostname}: {path}"
                        )
                    else:
                        result.failed_types.append(backup_type)
                        logger.warning(
                            f"No config returned for {backup_type.value} from {self.hostname}"
                        )

                except Exception as e:
                    logger.error(
                        f"Failed to backup {backup_type.value} for {self.hostname}: {e}"
                    )
                    result.failed_types.append(backup_type)

            # Determine overall status
            if len(result.successful_types) == len(backup_types):
                result.status = BackupStatus.SUCCESS
            elif result.successful_types:
                result.status = BackupStatus.PARTIAL
            else:
                result.status = BackupStatus.FAILED
                result.error_message = "All backup types failed"

        except Exception as e:
            result.status = BackupStatus.FAILED
            result.error_message = str(e)
            logger.exception(f"Backup failed for {self.hostname}")

        finally:
            await self.disconnect()
            result.completed_at = datetime.now()
            if result.started_at:
                result.duration_seconds = (
                    result.completed_at - result.started_at
                ).total_seconds()

        # Check for config changes
        if result.status in (BackupStatus.SUCCESS, BackupStatus.PARTIAL):
            for backup_type in result.successful_types:
                diff = self.storage.diff_configs(
                    self.hostname,
                    backup_type,
                    self.location,
                )
                if diff:
                    result.has_changes = True
                    result.diff_summary = diff[:1000]  # Truncate for summary
                    break

        return result

    async def run_command(self, command: str) -> str:
        """Run a command on the device (if supported).

        Args:
            command: Command to execute

        Returns:
            Command output
        """
        raise NotImplementedError(
            f"Command execution not implemented for {self.VENDOR.value}"
        )

    def get_backup_commands(self, backup_type: BackupType) -> list[str]:
        """Get the commands needed to retrieve a specific config type.

        Args:
            backup_type: Type of backup

        Returns:
            List of commands to execute
        """
        raise NotImplementedError(
            f"Must implement get_backup_commands for {self.VENDOR.value}"
        )


class SSHCollector(BaseCollector):
    """Base collector for SSH-based devices."""

    DEFAULT_PORT = 22

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None

    async def connect(self) -> bool:
        """Connect via SSH using asyncssh."""
        try:
            import asyncssh

            connect_kwargs = {
                "host": self.credential.device_ip or self.credential.device_hostname,
                "port": self.port,
                "username": self.credential.username,
                "known_hosts": None,  # Accept any host key (configure for production)
            }

            if self.credential.password:
                connect_kwargs["password"] = self.credential.password

            if self.credential.ssh_key:
                connect_kwargs["client_keys"] = [self.credential.ssh_key]
                if self.credential.ssh_key_passphrase:
                    connect_kwargs["passphrase"] = self.credential.ssh_key_passphrase

            self._connection = await asyncssh.connect(**connect_kwargs)
            return True

        except ImportError:
            logger.error("asyncssh not installed. Run: pip install asyncssh")
            return False
        except Exception as e:
            logger.error(f"SSH connection failed: {e}")
            return False

    async def disconnect(self) -> None:
        """Close SSH connection."""
        if self._connection:
            self._connection.close()
            await self._connection.wait_closed()
            self._connection = None

    async def run_command(self, command: str) -> str:
        """Run command over SSH.

        Args:
            command: Command to execute

        Returns:
            Command output
        """
        if not self._connection:
            raise RuntimeError("Not connected")

        result = await self._connection.run(command, check=False)
        return result.stdout or ""


class APICollector(BaseCollector):
    """Base collector for REST API-based devices."""

    DEFAULT_PORT = 443
    BASE_URL: str = ""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._session = None

    async def connect(self) -> bool:
        """Initialize API session."""
        try:
            import aiohttp

            self._session = aiohttp.ClientSession()
            # Verify connectivity with a simple API call
            return await self._verify_api()

        except ImportError:
            logger.error("aiohttp not installed. Run: pip install aiohttp")
            return False
        except Exception as e:
            logger.error(f"API connection failed: {e}")
            return False

    async def disconnect(self) -> None:
        """Close API session."""
        if self._session:
            await self._session.close()
            self._session = None

    async def _verify_api(self) -> bool:
        """Verify API connectivity. Override in subclass."""
        return True

    async def api_get(self, endpoint: str, params: dict | None = None) -> dict:
        """Make GET request to API.

        Args:
            endpoint: API endpoint
            params: Query parameters

        Returns:
            JSON response
        """
        if not self._session:
            raise RuntimeError("Not connected")

        url = f"{self.BASE_URL}{endpoint}"
        headers = self._get_auth_headers()

        async with self._session.get(url, params=params, headers=headers, ssl=False) as resp:
            resp.raise_for_status()
            return await resp.json()

    async def api_post(self, endpoint: str, data: dict | None = None) -> dict:
        """Make POST request to API.

        Args:
            endpoint: API endpoint
            data: POST data

        Returns:
            JSON response
        """
        if not self._session:
            raise RuntimeError("Not connected")

        url = f"{self.BASE_URL}{endpoint}"
        headers = self._get_auth_headers()

        async with self._session.post(url, json=data, headers=headers, ssl=False) as resp:
            resp.raise_for_status()
            return await resp.json()

    def _get_auth_headers(self) -> dict:
        """Get authentication headers. Override in subclass."""
        headers = {}
        if self.credential.api_token:
            headers["Authorization"] = f"Bearer {self.credential.api_token}"
        elif self.credential.api_key:
            headers["X-API-Key"] = self.credential.api_key
        return headers


class NETCONFCollector(BaseCollector):
    """Base collector for NETCONF-based devices (RFC 6241)."""

    DEFAULT_PORT = 830

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._manager = None

    async def connect(self) -> bool:
        """Establish NETCONF connection."""
        try:
            from ncclient import manager

            connect_kwargs = {
                "host": self.credential.device_ip or self.credential.device_hostname,
                "port": self.port,
                "username": self.credential.username,
                "password": self.credential.password,
                "hostkey_verify": False,
                "timeout": self.credential.timeout_seconds,
            }

            # Use async wrapper
            loop = asyncio.get_event_loop()
            self._manager = await loop.run_in_executor(
                None,
                lambda: manager.connect(**connect_kwargs)
            )
            return True

        except ImportError:
            logger.error("ncclient not installed. Run: pip install ncclient")
            return False
        except Exception as e:
            logger.error(f"NETCONF connection failed: {e}")
            return False

    async def disconnect(self) -> None:
        """Close NETCONF connection."""
        if self._manager:
            try:
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, self._manager.close_session)
            except Exception:
                pass
            self._manager = None

    async def get_running_config(self) -> str:
        """Get running configuration via NETCONF.

        Returns:
            Running configuration XML
        """
        if not self._manager:
            raise RuntimeError("Not connected")

        loop = asyncio.get_event_loop()
        config = await loop.run_in_executor(
            None,
            lambda: self._manager.get_config(source="running")
        )
        return config.data_xml

    async def get_candidate_config(self) -> str:
        """Get candidate configuration via NETCONF.

        Returns:
            Candidate configuration XML
        """
        if not self._manager:
            raise RuntimeError("Not connected")

        loop = asyncio.get_event_loop()
        config = await loop.run_in_executor(
            None,
            lambda: self._manager.get_config(source="candidate")
        )
        return config.data_xml

    async def get_schema(self, identifier: str) -> str:
        """Get YANG schema via NETCONF.

        Args:
            identifier: Schema identifier

        Returns:
            Schema content
        """
        if not self._manager:
            raise RuntimeError("Not connected")

        loop = asyncio.get_event_loop()
        schema = await loop.run_in_executor(
            None,
            lambda: self._manager.get_schema(identifier)
        )
        return schema.data

    async def rpc(self, rpc_command: str) -> str:
        """Execute raw RPC command.

        Args:
            rpc_command: XML RPC command

        Returns:
            RPC response XML
        """
        if not self._manager:
            raise RuntimeError("Not connected")

        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None,
            lambda: self._manager.rpc(rpc_command)
        )
        return result.data_xml


class ScreenScrapingCollector(BaseCollector):
    """Base collector for devices requiring screen scraping/expect-style interaction.

    Used for legacy devices that don't have APIs or require interactive CLI sessions.
    """

    DEFAULT_PORT = 22
    PROMPT_PATTERNS: list[str] = [r"[>#$]", r"\(config\)#"]
    LOGIN_PROMPT: str = r"[Uu]sername:|[Ll]ogin:"
    PASSWORD_PROMPT: str = r"[Pp]assword:"
    ENABLE_PROMPT: str = r"[>#]"
    MORE_PROMPT: str = r"--[Mm]ore--|<--- More --->|\[yes/no\]"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._channel = None
        self._expect = None

    async def connect(self) -> bool:
        """Establish SSH connection with expect-style interaction."""
        try:
            import pexpect
            from pexpect import pxssh

            # Use pxssh for cleaner SSH handling
            self._expect = pxssh.pxssh(
                options={
                    "StrictHostKeyChecking": "no",
                    "UserKnownHostsFile": "/dev/null"
                }
            )

            host = self.credential.device_ip or self.credential.device_hostname

            login_success = self._expect.login(
                host,
                self.credential.username,
                self.credential.password,
                port=self.port,
                login_timeout=self.credential.banner_timeout,
                auto_prompt_reset=False,
            )

            if not login_success:
                return False

            # Handle enable mode if needed
            if self.credential.enable_password:
                await self._enter_enable_mode()

            # Disable paging
            await self._disable_paging()

            return True

        except ImportError:
            logger.error("pexpect not installed. Run: pip install pexpect")
            return False
        except Exception as e:
            logger.error(f"Screen scraping connection failed: {e}")
            return False

    async def disconnect(self) -> None:
        """Close connection."""
        if self._expect:
            try:
                self._expect.logout()
            except Exception:
                pass
            self._expect = None

    async def _enter_enable_mode(self) -> None:
        """Enter privileged/enable mode."""
        if not self._expect:
            return

        self._expect.sendline("enable")
        i = self._expect.expect([self.PASSWORD_PROMPT, self.ENABLE_PROMPT])
        if i == 0:
            self._expect.sendline(self.credential.enable_password)
            self._expect.expect(self.ENABLE_PROMPT)

    async def _disable_paging(self) -> None:
        """Disable paging (--More-- prompts). Override per vendor."""
        pass

    async def send_command(
        self,
        command: str,
        timeout: int = 30,
        expect_string: str | None = None
    ) -> str:
        """Send command and capture output.

        Args:
            command: Command to send
            timeout: Command timeout
            expect_string: Pattern to expect (defaults to prompt)

        Returns:
            Command output
        """
        if not self._expect:
            raise RuntimeError("Not connected")

        self._expect.sendline(command)

        # Handle --More-- prompts
        output_parts = []
        while True:
            i = self._expect.expect(
                [self.MORE_PROMPT] + (self.PROMPT_PATTERNS if not expect_string else [expect_string]),
                timeout=timeout
            )

            output_parts.append(self._expect.before.decode('utf-8', errors='ignore'))

            if i == 0:
                # More prompt - send space to continue
                self._expect.send(" ")
            else:
                # Got our expected prompt
                break

        return "".join(output_parts).strip()

    async def send_commands(self, commands: list[str], timeout: int = 30) -> str:
        """Send multiple commands and capture all output.

        Args:
            commands: List of commands to send
            timeout: Per-command timeout

        Returns:
            Combined output from all commands
        """
        outputs = []
        for cmd in commands:
            output = await self.send_command(cmd, timeout)
            outputs.append(f"! Command: {cmd}\n{output}")
        return "\n\n".join(outputs)

    async def run_command(self, command: str) -> str:
        """Run a command (implements BaseCollector interface)."""
        return await self.send_command(command)


class TelnetCollector(ScreenScrapingCollector):
    """Collector for legacy devices using Telnet (not recommended).

    Only use when SSH is not available.
    """

    DEFAULT_PORT = 23

    async def connect(self) -> bool:
        """Establish Telnet connection."""
        try:
            import pexpect

            host = self.credential.device_ip or self.credential.device_hostname
            self._expect = pexpect.spawn(
                f"telnet {host} {self.port}",
                timeout=self.credential.banner_timeout
            )

            # Wait for login prompt
            self._expect.expect(self.LOGIN_PROMPT)
            self._expect.sendline(self.credential.username)

            # Wait for password prompt
            self._expect.expect(self.PASSWORD_PROMPT)
            self._expect.sendline(self.credential.password)

            # Wait for command prompt
            self._expect.expect(self.PROMPT_PATTERNS)

            # Enter enable mode if needed
            if self.credential.enable_password:
                await self._enter_enable_mode()

            # Disable paging
            await self._disable_paging()

            return True

        except ImportError:
            logger.error("pexpect not installed. Run: pip install pexpect")
            return False
        except Exception as e:
            logger.error(f"Telnet connection failed: {e}")
            return False
