"""
Data models for device configuration backup.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any
from pathlib import Path


class DeviceType(str, Enum):
    """Type of device being backed up."""
    ROUTER = "router"
    SWITCH = "switch"
    FIREWALL = "firewall"
    LOAD_BALANCER = "load_balancer"
    DNS_APPLIANCE = "dns_appliance"
    PROXY = "proxy"
    VPN_CONCENTRATOR = "vpn_concentrator"
    WIRELESS_CONTROLLER = "wireless_controller"
    LINUX_HOST = "linux_host"
    BSD_HOST = "bsd_host"
    UNKNOWN = "unknown"


class DeviceVendor(str, Enum):
    """Vendor/platform of the device."""
    # Network vendors
    CISCO_IOS = "cisco_ios"
    CISCO_NXOS = "cisco_nxos"
    CISCO_ASA = "cisco_asa"
    CISCO_IOS_XR = "cisco_ios_xr"
    CISCO_IOS_XE = "cisco_ios_xe"
    PALO_ALTO = "palo_alto"
    JUNIPER_JUNOS = "juniper_junos"
    JUNIPER_SCREENOS = "juniper_screenos"  # Legacy Netscreen
    FORTINET = "fortinet"

    # DNS appliances
    INFOBLOX = "infoblox"
    BLUECAT = "bluecat"
    MEN_AND_MICE = "men_and_mice"

    # Proxy/Security
    BLUECOAT = "bluecoat"  # Now Symantec/Broadcom

    # Linux/BSD
    IPTABLES = "iptables"
    NFTABLES = "nftables"
    PF_BSD = "pf_bsd"
    IPFW = "ipfw"

    # Generic
    BIND = "bind"
    UNBOUND = "unbound"
    GENERIC_LINUX = "generic_linux"
    GENERIC_BSD = "generic_bsd"

    UNKNOWN = "unknown"


class BackupType(str, Enum):
    """Type of configuration to backup."""
    FULL = "full"  # Complete system configuration
    DNS = "dns"  # DNS-related configs only
    SSL = "ssl"  # SSL/TLS certificates and configs
    NETWORK = "network"  # Network/routing configuration
    FIREWALL = "firewall"  # Firewall rules only
    NAT = "nat"  # NAT configuration
    VPN = "vpn"  # VPN configuration
    EMAIL = "email"  # Email/SMTP configuration
    DHCP = "dhcp"  # DHCP configuration
    USERS = "users"  # User accounts and authentication
    LICENSES = "licenses"  # License information
    CUSTOM = "custom"  # Custom selection


class CompressionType(str, Enum):
    """Compression algorithm for backups."""
    NONE = "none"
    GZIP = "gzip"
    BZIP2 = "bzip2"
    XZ = "xz"
    ZSTD = "zstd"


class ConnectionMethod(str, Enum):
    """Method to connect to the device."""
    SSH = "ssh"
    TELNET = "telnet"  # Legacy, not recommended
    API = "api"  # REST/SOAP API
    NETCONF = "netconf"
    SNMP = "snmp"
    LOCAL = "local"  # Local commands (for iptables, etc.)


class BackupStatus(str, Enum):
    """Status of a backup job."""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    PARTIAL = "partial"  # Some configs backed up, some failed
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class DeviceCredential:
    """Credentials for accessing a device."""
    id: str | None = None
    name: str | None = None

    # Device identification
    device_hostname: str | None = None
    device_ip: str | None = None
    device_vendor: DeviceVendor = DeviceVendor.UNKNOWN

    # Connection
    connection_method: ConnectionMethod = ConnectionMethod.SSH
    port: int | None = None  # None = use default for method

    # Authentication
    username: str | None = None
    password: str | None = None  # Encrypted at rest
    ssh_key: str | None = None  # Path to SSH key or key content
    ssh_key_passphrase: str | None = None

    # API credentials
    api_key: str | None = None
    api_secret: str | None = None
    api_token: str | None = None

    # SNMP
    snmp_community: str | None = None
    snmp_version: str = "2c"  # 1, 2c, 3
    snmp_auth_protocol: str | None = None  # MD5, SHA
    snmp_auth_password: str | None = None
    snmp_priv_protocol: str | None = None  # DES, AES
    snmp_priv_password: str | None = None

    # Enable/privilege mode
    enable_password: str | None = None
    privilege_level: int = 15

    # Connection settings
    timeout_seconds: int = 30
    banner_timeout: int = 15

    # Metadata
    notes: str | None = None
    tags: list[str] = field(default_factory=list)
    created_at: datetime | None = None
    updated_at: datetime | None = None
    last_used: datetime | None = None

    def to_dict(self, include_secrets: bool = False) -> dict[str, Any]:
        """Convert to dictionary, optionally excluding secrets."""
        data = {
            "id": self.id,
            "name": self.name,
            "device_hostname": self.device_hostname,
            "device_ip": self.device_ip,
            "device_vendor": self.device_vendor.value,
            "connection_method": self.connection_method.value,
            "port": self.port,
            "username": self.username,
            "privilege_level": self.privilege_level,
            "timeout_seconds": self.timeout_seconds,
            "banner_timeout": self.banner_timeout,
            "notes": self.notes,
            "tags": self.tags,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "last_used": self.last_used.isoformat() if self.last_used else None,
        }
        if include_secrets:
            data.update({
                "password": self.password,
                "ssh_key": self.ssh_key,
                "ssh_key_passphrase": self.ssh_key_passphrase,
                "api_key": self.api_key,
                "api_secret": self.api_secret,
                "api_token": self.api_token,
                "snmp_community": self.snmp_community,
                "snmp_version": self.snmp_version,
                "snmp_auth_protocol": self.snmp_auth_protocol,
                "snmp_auth_password": self.snmp_auth_password,
                "snmp_priv_protocol": self.snmp_priv_protocol,
                "snmp_priv_password": self.snmp_priv_password,
                "enable_password": self.enable_password,
            })
        return data


@dataclass
class DeviceLocation:
    """Physical location of a device in the hierarchy."""
    region: str | None = None
    site: str | None = None
    building: str | None = None
    floor: str | None = None
    room: str | None = None
    rack: str | None = None
    position: str | None = None  # U position in rack

    def to_path(self) -> str:
        """Convert location to filesystem path."""
        parts = []
        if self.region:
            parts.append(self.region)
        if self.site:
            parts.append(self.site)
        if self.building:
            parts.append(self.building)
        if self.floor:
            parts.append(f"floor-{self.floor}")
        if self.room:
            parts.append(f"room-{self.room}")
        if self.rack:
            parts.append(f"rack-{self.rack}")
        if self.position:
            parts.append(f"u{self.position}")
        return "/".join(parts) if parts else "unknown"

    def to_dict(self) -> dict[str, Any]:
        return {
            "region": self.region,
            "site": self.site,
            "building": self.building,
            "floor": self.floor,
            "room": self.room,
            "rack": self.rack,
            "position": self.position,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DeviceLocation":
        return cls(
            region=data.get("region"),
            site=data.get("site"),
            building=data.get("building"),
            floor=data.get("floor"),
            room=data.get("room"),
            rack=data.get("rack"),
            position=data.get("position"),
        )


@dataclass
class BackupJob:
    """Configuration backup job definition."""
    id: str | None = None
    name: str | None = None

    # Target device
    device_hostname: str | None = None
    device_ip: str | None = None
    device_type: DeviceType = DeviceType.UNKNOWN
    device_vendor: DeviceVendor = DeviceVendor.UNKNOWN

    # Location
    location: DeviceLocation | None = None

    # Backup configuration
    backup_types: list[BackupType] = field(default_factory=lambda: [BackupType.FULL])
    compression: CompressionType = CompressionType.GZIP

    # Credential reference
    credential_id: str | None = None

    # Scheduling
    schedule_cron: str | None = None  # Cron expression for recurring backups
    last_run: datetime | None = None
    next_run: datetime | None = None

    # Retention
    retention_days: int = 90  # How long to keep backups
    retention_count: int | None = None  # Max number of backups to keep

    # Status
    status: BackupStatus = BackupStatus.PENDING
    enabled: bool = True

    # Metadata
    notes: str | None = None
    tags: list[str] = field(default_factory=list)
    created_at: datetime | None = None
    updated_at: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "device_hostname": self.device_hostname,
            "device_ip": self.device_ip,
            "device_type": self.device_type.value,
            "device_vendor": self.device_vendor.value,
            "location": self.location.to_dict() if self.location else None,
            "backup_types": [bt.value for bt in self.backup_types],
            "compression": self.compression.value,
            "credential_id": self.credential_id,
            "schedule_cron": self.schedule_cron,
            "last_run": self.last_run.isoformat() if self.last_run else None,
            "next_run": self.next_run.isoformat() if self.next_run else None,
            "retention_days": self.retention_days,
            "retention_count": self.retention_count,
            "status": self.status.value,
            "enabled": self.enabled,
            "notes": self.notes,
            "tags": self.tags,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


@dataclass
class BackupResult:
    """Result of a backup operation."""
    id: str | None = None
    job_id: str | None = None

    # Device info
    device_hostname: str | None = None
    device_ip: str | None = None
    device_vendor: DeviceVendor = DeviceVendor.UNKNOWN

    # Status
    status: BackupStatus = BackupStatus.PENDING

    # What was backed up
    backup_types: list[BackupType] = field(default_factory=list)
    successful_types: list[BackupType] = field(default_factory=list)
    failed_types: list[BackupType] = field(default_factory=list)

    # Output files
    output_files: list[str] = field(default_factory=list)
    output_directory: str | None = None
    total_size_bytes: int = 0

    # Compression used
    compression: CompressionType = CompressionType.NONE

    # Timing
    started_at: datetime | None = None
    completed_at: datetime | None = None
    duration_seconds: float | None = None

    # Error information
    error_message: str | None = None
    error_details: str | None = None

    # Config diff (if previous backup exists)
    has_changes: bool | None = None
    diff_summary: str | None = None

    # Metadata
    triggered_by: str | None = None  # manual, scheduled, api
    notes: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "job_id": self.job_id,
            "device_hostname": self.device_hostname,
            "device_ip": self.device_ip,
            "device_vendor": self.device_vendor.value,
            "status": self.status.value,
            "backup_types": [bt.value for bt in self.backup_types],
            "successful_types": [bt.value for bt in self.successful_types],
            "failed_types": [bt.value for bt in self.failed_types],
            "output_files": self.output_files,
            "output_directory": self.output_directory,
            "total_size_bytes": self.total_size_bytes,
            "compression": self.compression.value,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "error_message": self.error_message,
            "error_details": self.error_details,
            "has_changes": self.has_changes,
            "diff_summary": self.diff_summary,
            "triggered_by": self.triggered_by,
            "notes": self.notes,
        }
