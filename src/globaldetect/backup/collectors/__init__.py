"""
Vendor-specific configuration collectors.

Supported vendors:
- Network: Cisco (IOS/NX-OS/ASA), Palo Alto, Juniper, FortiNet, iptables
- DNS: InfoBlox, BlueCat, Men and Mice
- Proxy: BlueCoat

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

from globaldetect.backup.collectors.cisco import (
    CiscoIOSCollector,
    CiscoNXOSCollector,
    CiscoASACollector,
)
from globaldetect.backup.collectors.paloalto import PaloAltoCollector
from globaldetect.backup.collectors.juniper import JuniperJunOSCollector, JuniperScreenOSCollector
from globaldetect.backup.collectors.fortinet import FortiGateCollector
from globaldetect.backup.collectors.linux import IPTablesCollector, NFTablesCollector
from globaldetect.backup.collectors.infoblox import InfobloxCollector
from globaldetect.backup.collectors.bluecat import BlueCatCollector
from globaldetect.backup.collectors.menandmice import MenAndMiceCollector
from globaldetect.backup.collectors.bluecoat import BlueCoatCollector

from globaldetect.backup.models import DeviceVendor

# Map vendor enum to collector class
COLLECTOR_MAP = {
    DeviceVendor.CISCO_IOS: CiscoIOSCollector,
    DeviceVendor.CISCO_IOS_XE: CiscoIOSCollector,  # Same commands as IOS
    DeviceVendor.CISCO_NXOS: CiscoNXOSCollector,
    DeviceVendor.CISCO_ASA: CiscoASACollector,
    DeviceVendor.PALO_ALTO: PaloAltoCollector,
    DeviceVendor.JUNIPER_JUNOS: JuniperJunOSCollector,
    DeviceVendor.JUNIPER_SCREENOS: JuniperScreenOSCollector,
    DeviceVendor.FORTINET: FortiGateCollector,
    DeviceVendor.IPTABLES: IPTablesCollector,
    DeviceVendor.NFTABLES: NFTablesCollector,
    DeviceVendor.INFOBLOX: InfobloxCollector,
    DeviceVendor.BLUECAT: BlueCatCollector,
    DeviceVendor.MEN_AND_MICE: MenAndMiceCollector,
    DeviceVendor.BLUECOAT: BlueCoatCollector,
}


def get_collector_class(vendor: DeviceVendor):
    """Get the appropriate collector class for a vendor.

    Args:
        vendor: Device vendor enum

    Returns:
        Collector class or None if not supported
    """
    return COLLECTOR_MAP.get(vendor)


__all__ = [
    "CiscoIOSCollector",
    "CiscoNXOSCollector",
    "CiscoASACollector",
    "PaloAltoCollector",
    "JuniperJunOSCollector",
    "JuniperScreenOSCollector",
    "FortiGateCollector",
    "IPTablesCollector",
    "NFTablesCollector",
    "InfobloxCollector",
    "BlueCatCollector",
    "MenAndMiceCollector",
    "BlueCoatCollector",
    "COLLECTOR_MAP",
    "get_collector_class",
]
