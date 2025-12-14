"""
Device configuration backup module.

Supports backing up configurations from:
- Network devices: Cisco, Palo Alto, Juniper/Netscreen, FortiNet, iptables
- DNS appliances: BlueCat, InfoBlox, Men and Mice
- Proxy/Security: BlueCoat

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

from globaldetect.backup.models import (
    DeviceType,
    DeviceVendor,
    BackupType,
    CompressionType,
    DeviceCredential,
    BackupJob,
    BackupResult,
)
from globaldetect.backup.storage import BackupStorage
from globaldetect.backup.credentials import CredentialVault
from globaldetect.backup.base import BaseCollector

__all__ = [
    "DeviceType",
    "DeviceVendor",
    "BackupType",
    "CompressionType",
    "DeviceCredential",
    "BackupJob",
    "BackupResult",
    "BackupStorage",
    "CredentialVault",
    "BaseCollector",
]
