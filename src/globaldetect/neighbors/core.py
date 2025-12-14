"""
CDP and LLDP neighbor discovery core functionality.

Implements passive listening for CDP (Cisco Discovery Protocol) v2
and LLDP (Link Layer Discovery Protocol) frames to discover adjacent
network devices.

Note: Requires root/admin privileges to capture raw frames.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Any
from enum import IntEnum


# Ethernet frame types
ETH_P_ALL = 0x0003
ETH_P_CDP = 0x2000  # CDP uses LLC/SNAP, not directly on Ethernet
ETH_P_LLDP = 0x88CC

# CDP multicast MAC
CDP_MULTICAST_MAC = bytes([0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc])

# LLDP multicast MACs
LLDP_MULTICAST_MACS = [
    bytes([0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e]),  # Bridge
    bytes([0x01, 0x80, 0xc2, 0x00, 0x00, 0x03]),  # 802.1D
    bytes([0x01, 0x80, 0xc2, 0x00, 0x00, 0x00]),  # STP
]


class CDPTLVType(IntEnum):
    """CDP TLV types."""
    DEVICE_ID = 0x0001
    ADDRESS = 0x0002
    PORT_ID = 0x0003
    CAPABILITIES = 0x0004
    SOFTWARE_VERSION = 0x0005
    PLATFORM = 0x0006
    IP_PREFIX = 0x0007
    VTP_MGMT_DOMAIN = 0x0009
    NATIVE_VLAN = 0x000a
    DUPLEX = 0x000b
    TRUST_BITMAP = 0x0012
    UNTRUSTED_COS = 0x0013
    MGMT_ADDRESS = 0x0016
    POWER_AVAILABLE = 0x001a


class LLDPTLVType(IntEnum):
    """LLDP TLV types."""
    END = 0
    CHASSIS_ID = 1
    PORT_ID = 2
    TTL = 3
    PORT_DESCRIPTION = 4
    SYSTEM_NAME = 5
    SYSTEM_DESCRIPTION = 6
    SYSTEM_CAPABILITIES = 7
    MANAGEMENT_ADDRESS = 8
    ORGANIZATION_SPECIFIC = 127


@dataclass
class CDPNeighbor:
    """Represents a CDP neighbor device."""
    device_id: str = ""
    port_id: str = ""
    platform: str = ""
    software_version: str = ""
    ip_addresses: list[str] = field(default_factory=list)
    native_vlan: int | None = None
    duplex: str | None = None
    vtp_domain: str | None = None
    capabilities: list[str] = field(default_factory=list)
    mgmt_addresses: list[str] = field(default_factory=list)
    local_interface: str = ""
    source_mac: str = ""
    timestamp: float = 0.0
    ttl: int = 180
    raw_data: dict[str, Any] = field(default_factory=dict)


@dataclass
class LLDPNeighbor:
    """Represents an LLDP neighbor device."""
    chassis_id: str = ""
    chassis_id_subtype: str = ""
    port_id: str = ""
    port_id_subtype: str = ""
    port_description: str = ""
    system_name: str = ""
    system_description: str = ""
    ttl: int = 120
    capabilities: list[str] = field(default_factory=list)
    mgmt_addresses: list[str] = field(default_factory=list)
    local_interface: str = ""
    source_mac: str = ""
    timestamp: float = 0.0
    raw_data: dict[str, Any] = field(default_factory=dict)


def _mac_to_str(mac_bytes: bytes) -> str:
    """Convert MAC address bytes to string."""
    return ":".join(f"{b:02x}" for b in mac_bytes)


def _parse_cdp_capabilities(cap_value: int) -> list[str]:
    """Parse CDP capability flags."""
    capabilities = []
    cap_names = [
        (0x01, "Router"),
        (0x02, "Transparent Bridge"),
        (0x04, "Source Route Bridge"),
        (0x08, "Switch"),
        (0x10, "Host"),
        (0x20, "IGMP"),
        (0x40, "Repeater"),
        (0x80, "VoIP Phone"),
        (0x100, "Remote Managed"),
        (0x200, "CVTA/STP Dispute"),
        (0x400, "Two-port MAC Relay"),
    ]
    for flag, name in cap_names:
        if cap_value & flag:
            capabilities.append(name)
    return capabilities


def _parse_lldp_capabilities(cap_value: int) -> list[str]:
    """Parse LLDP capability flags."""
    capabilities = []
    cap_names = [
        (0x01, "Other"),
        (0x02, "Repeater"),
        (0x04, "Bridge"),
        (0x08, "WLAN AP"),
        (0x10, "Router"),
        (0x20, "Telephone"),
        (0x40, "DOCSIS Cable Device"),
        (0x80, "Station Only"),
        (0x100, "C-VLAN"),
        (0x200, "S-VLAN"),
        (0x400, "Two-port MAC Relay"),
    ]
    for flag, name in cap_names:
        if cap_value & flag:
            capabilities.append(name)
    return capabilities


def _parse_cdp_address(data: bytes) -> list[str]:
    """Parse CDP address TLV."""
    addresses = []
    if len(data) < 4:
        return addresses

    offset = 0
    num_addresses = struct.unpack(">I", data[offset:offset+4])[0]
    offset += 4

    for _ in range(num_addresses):
        if offset + 2 > len(data):
            break

        proto_type = data[offset]
        proto_len = data[offset + 1]
        offset += 2

        if offset + proto_len > len(data):
            break

        # protocol = data[offset:offset + proto_len]
        offset += proto_len

        if offset + 2 > len(data):
            break

        addr_len = struct.unpack(">H", data[offset:offset+2])[0]
        offset += 2

        if offset + addr_len > len(data):
            break

        addr_bytes = data[offset:offset + addr_len]
        offset += addr_len

        # Parse as IPv4 if 4 bytes
        if addr_len == 4:
            addresses.append(".".join(str(b) for b in addr_bytes))
        elif addr_len == 16:
            # IPv6
            addr = ":".join(f"{addr_bytes[i]:02x}{addr_bytes[i+1]:02x}"
                           for i in range(0, 16, 2))
            addresses.append(addr)

    return addresses


def parse_cdp_frame(frame: bytes, interface: str = "") -> CDPNeighbor | None:
    """Parse a CDP frame and return neighbor info."""
    neighbor = CDPNeighbor()
    neighbor.local_interface = interface
    neighbor.timestamp = time.time()

    # Ethernet header (14 bytes)
    if len(frame) < 22:
        return None

    dst_mac = frame[0:6]
    src_mac = frame[6:12]
    neighbor.source_mac = _mac_to_str(src_mac)

    # Check for CDP multicast destination
    if dst_mac != CDP_MULTICAST_MAC:
        return None

    # LLC/SNAP header check (after ethernet)
    # CDP uses SNAP with OUI 0x00000C and protocol 0x2000
    offset = 12

    # Skip any VLAN tags (802.1Q)
    ethertype = struct.unpack(">H", frame[offset:offset+2])[0]
    if ethertype == 0x8100:  # VLAN tagged
        offset += 4

    # Check for LLC header
    if len(frame) < offset + 8:
        return None

    # LLC DSAP/SSAP should be 0xAA (SNAP)
    if frame[offset] != 0xAA or frame[offset+1] != 0xAA:
        return None

    offset += 3  # Skip LLC header (DSAP, SSAP, Control)

    # SNAP OUI should be 0x00000C (Cisco)
    if frame[offset:offset+3] != bytes([0x00, 0x00, 0x0C]):
        return None
    offset += 3

    # SNAP protocol ID should be 0x2000 (CDP)
    snap_proto = struct.unpack(">H", frame[offset:offset+2])[0]
    if snap_proto != 0x2000:
        return None
    offset += 2

    # CDP header
    if len(frame) < offset + 4:
        return None

    cdp_version = frame[offset]
    cdp_ttl = frame[offset + 1]
    # cdp_checksum = struct.unpack(">H", frame[offset+2:offset+4])[0]
    offset += 4

    neighbor.ttl = cdp_ttl
    neighbor.raw_data["version"] = cdp_version

    # Parse TLVs
    while offset + 4 <= len(frame):
        tlv_type = struct.unpack(">H", frame[offset:offset+2])[0]
        tlv_len = struct.unpack(">H", frame[offset+2:offset+4])[0]

        if tlv_len < 4 or offset + tlv_len > len(frame):
            break

        tlv_data = frame[offset+4:offset+tlv_len]
        offset += tlv_len

        try:
            if tlv_type == CDPTLVType.DEVICE_ID:
                neighbor.device_id = tlv_data.decode("utf-8", errors="replace").rstrip("\x00")
            elif tlv_type == CDPTLVType.PORT_ID:
                neighbor.port_id = tlv_data.decode("utf-8", errors="replace").rstrip("\x00")
            elif tlv_type == CDPTLVType.PLATFORM:
                neighbor.platform = tlv_data.decode("utf-8", errors="replace").rstrip("\x00")
            elif tlv_type == CDPTLVType.SOFTWARE_VERSION:
                neighbor.software_version = tlv_data.decode("utf-8", errors="replace").rstrip("\x00")
            elif tlv_type == CDPTLVType.ADDRESS:
                neighbor.ip_addresses = _parse_cdp_address(tlv_data)
            elif tlv_type == CDPTLVType.CAPABILITIES:
                if len(tlv_data) >= 4:
                    cap_val = struct.unpack(">I", tlv_data[:4])[0]
                    neighbor.capabilities = _parse_cdp_capabilities(cap_val)
            elif tlv_type == CDPTLVType.NATIVE_VLAN:
                if len(tlv_data) >= 2:
                    neighbor.native_vlan = struct.unpack(">H", tlv_data[:2])[0]
            elif tlv_type == CDPTLVType.DUPLEX:
                if len(tlv_data) >= 1:
                    neighbor.duplex = "Full" if tlv_data[0] else "Half"
            elif tlv_type == CDPTLVType.VTP_MGMT_DOMAIN:
                neighbor.vtp_domain = tlv_data.decode("utf-8", errors="replace").rstrip("\x00")
            elif tlv_type == CDPTLVType.MGMT_ADDRESS:
                neighbor.mgmt_addresses = _parse_cdp_address(tlv_data)
        except Exception:
            pass

    return neighbor


def parse_lldp_frame(frame: bytes, interface: str = "") -> LLDPNeighbor | None:
    """Parse an LLDP frame and return neighbor info."""
    neighbor = LLDPNeighbor()
    neighbor.local_interface = interface
    neighbor.timestamp = time.time()

    # Ethernet header (14 bytes)
    if len(frame) < 14:
        return None

    dst_mac = frame[0:6]
    src_mac = frame[6:12]
    neighbor.source_mac = _mac_to_str(src_mac)

    # Check for LLDP multicast destination
    if dst_mac not in LLDP_MULTICAST_MACS:
        return None

    offset = 12

    # Skip VLAN tags
    ethertype = struct.unpack(">H", frame[offset:offset+2])[0]
    while ethertype == 0x8100:  # VLAN tagged
        offset += 4
        if offset + 2 > len(frame):
            return None
        ethertype = struct.unpack(">H", frame[offset:offset+2])[0]

    # Verify LLDP ethertype
    if ethertype != ETH_P_LLDP:
        return None
    offset += 2

    # Parse LLDP TLVs
    while offset + 2 <= len(frame):
        tlv_header = struct.unpack(">H", frame[offset:offset+2])[0]
        tlv_type = (tlv_header >> 9) & 0x7F
        tlv_len = tlv_header & 0x1FF
        offset += 2

        if tlv_type == LLDPTLVType.END:
            break

        if offset + tlv_len > len(frame):
            break

        tlv_data = frame[offset:offset+tlv_len]
        offset += tlv_len

        try:
            if tlv_type == LLDPTLVType.CHASSIS_ID:
                if len(tlv_data) >= 1:
                    subtype = tlv_data[0]
                    chassis_data = tlv_data[1:]
                    subtypes = {
                        1: "Chassis Component",
                        2: "Interface Alias",
                        3: "Port Component",
                        4: "MAC Address",
                        5: "Network Address",
                        6: "Interface Name",
                        7: "Locally Assigned",
                    }
                    neighbor.chassis_id_subtype = subtypes.get(subtype, f"Unknown({subtype})")
                    if subtype == 4 and len(chassis_data) == 6:
                        neighbor.chassis_id = _mac_to_str(chassis_data)
                    else:
                        neighbor.chassis_id = chassis_data.decode("utf-8", errors="replace").rstrip("\x00")

            elif tlv_type == LLDPTLVType.PORT_ID:
                if len(tlv_data) >= 1:
                    subtype = tlv_data[0]
                    port_data = tlv_data[1:]
                    subtypes = {
                        1: "Interface Alias",
                        2: "Port Component",
                        3: "MAC Address",
                        4: "Network Address",
                        5: "Interface Name",
                        6: "Agent Circuit ID",
                        7: "Locally Assigned",
                    }
                    neighbor.port_id_subtype = subtypes.get(subtype, f"Unknown({subtype})")
                    if subtype == 3 and len(port_data) == 6:
                        neighbor.port_id = _mac_to_str(port_data)
                    else:
                        neighbor.port_id = port_data.decode("utf-8", errors="replace").rstrip("\x00")

            elif tlv_type == LLDPTLVType.TTL:
                if len(tlv_data) >= 2:
                    neighbor.ttl = struct.unpack(">H", tlv_data[:2])[0]

            elif tlv_type == LLDPTLVType.PORT_DESCRIPTION:
                neighbor.port_description = tlv_data.decode("utf-8", errors="replace").rstrip("\x00")

            elif tlv_type == LLDPTLVType.SYSTEM_NAME:
                neighbor.system_name = tlv_data.decode("utf-8", errors="replace").rstrip("\x00")

            elif tlv_type == LLDPTLVType.SYSTEM_DESCRIPTION:
                neighbor.system_description = tlv_data.decode("utf-8", errors="replace").rstrip("\x00")

            elif tlv_type == LLDPTLVType.SYSTEM_CAPABILITIES:
                if len(tlv_data) >= 4:
                    # capabilities = struct.unpack(">H", tlv_data[0:2])[0]
                    enabled = struct.unpack(">H", tlv_data[2:4])[0]
                    neighbor.capabilities = _parse_lldp_capabilities(enabled)

            elif tlv_type == LLDPTLVType.MANAGEMENT_ADDRESS:
                if len(tlv_data) >= 2:
                    addr_len = tlv_data[0]
                    if addr_len > 0 and len(tlv_data) >= 1 + addr_len:
                        addr_subtype = tlv_data[1]
                        addr_bytes = tlv_data[2:1+addr_len]
                        if addr_subtype == 1 and len(addr_bytes) == 4:  # IPv4
                            addr = ".".join(str(b) for b in addr_bytes)
                            neighbor.mgmt_addresses.append(addr)
                        elif addr_subtype == 2 and len(addr_bytes) == 16:  # IPv6
                            addr = ":".join(f"{addr_bytes[i]:02x}{addr_bytes[i+1]:02x}"
                                          for i in range(0, 16, 2))
                            neighbor.mgmt_addresses.append(addr)
        except Exception:
            pass

    return neighbor


class CDPListener:
    """Listens for CDP frames on a network interface."""

    def __init__(self, interface: str, timeout: float = 120.0):
        self.interface = interface
        self.timeout = timeout
        self._socket: socket.socket | None = None
        self.neighbors: dict[str, CDPNeighbor] = {}  # keyed by device_id

    def _create_socket(self) -> socket.socket:
        """Create a raw socket for packet capture."""
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        sock.bind((self.interface, 0))
        sock.settimeout(1.0)  # 1 second timeout for non-blocking
        return sock

    def listen(self, duration: float | None = None) -> list[CDPNeighbor]:
        """Listen for CDP frames for the specified duration."""
        duration = duration or self.timeout
        end_time = time.time() + duration

        try:
            self._socket = self._create_socket()

            while time.time() < end_time:
                try:
                    frame = self._socket.recv(65535)
                    neighbor = parse_cdp_frame(frame, self.interface)
                    if neighbor and neighbor.device_id:
                        self.neighbors[neighbor.device_id] = neighbor
                except socket.timeout:
                    continue
                except Exception:
                    continue

        finally:
            if self._socket:
                self._socket.close()

        return list(self.neighbors.values())


class LLDPListener:
    """Listens for LLDP frames on a network interface."""

    def __init__(self, interface: str, timeout: float = 120.0):
        self.interface = interface
        self.timeout = timeout
        self._socket: socket.socket | None = None
        self.neighbors: dict[str, LLDPNeighbor] = {}  # keyed by chassis_id+port_id

    def _create_socket(self) -> socket.socket:
        """Create a raw socket for packet capture."""
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        sock.bind((self.interface, 0))
        sock.settimeout(1.0)
        return sock

    def listen(self, duration: float | None = None) -> list[LLDPNeighbor]:
        """Listen for LLDP frames for the specified duration."""
        duration = duration or self.timeout
        end_time = time.time() + duration

        try:
            self._socket = self._create_socket()

            while time.time() < end_time:
                try:
                    frame = self._socket.recv(65535)
                    neighbor = parse_lldp_frame(frame, self.interface)
                    if neighbor and (neighbor.chassis_id or neighbor.system_name):
                        key = f"{neighbor.chassis_id}|{neighbor.port_id}"
                        self.neighbors[key] = neighbor
                except socket.timeout:
                    continue
                except Exception:
                    continue

        finally:
            if self._socket:
                self._socket.close()

        return list(self.neighbors.values())


class CombinedListener:
    """Listens for both CDP and LLDP frames simultaneously."""

    def __init__(self, interface: str, timeout: float = 120.0):
        self.interface = interface
        self.timeout = timeout
        self._socket: socket.socket | None = None
        self.cdp_neighbors: dict[str, CDPNeighbor] = {}
        self.lldp_neighbors: dict[str, LLDPNeighbor] = {}

    def _create_socket(self) -> socket.socket:
        """Create a raw socket for packet capture."""
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        sock.bind((self.interface, 0))
        sock.settimeout(1.0)
        return sock

    def listen(self, duration: float | None = None) -> tuple[list[CDPNeighbor], list[LLDPNeighbor]]:
        """Listen for CDP and LLDP frames for the specified duration."""
        duration = duration or self.timeout
        end_time = time.time() + duration

        try:
            self._socket = self._create_socket()

            while time.time() < end_time:
                try:
                    frame = self._socket.recv(65535)

                    # Try CDP first
                    cdp_neighbor = parse_cdp_frame(frame, self.interface)
                    if cdp_neighbor and cdp_neighbor.device_id:
                        self.cdp_neighbors[cdp_neighbor.device_id] = cdp_neighbor
                        continue

                    # Try LLDP
                    lldp_neighbor = parse_lldp_frame(frame, self.interface)
                    if lldp_neighbor and (lldp_neighbor.chassis_id or lldp_neighbor.system_name):
                        key = f"{lldp_neighbor.chassis_id}|{lldp_neighbor.port_id}"
                        self.lldp_neighbors[key] = lldp_neighbor

                except socket.timeout:
                    continue
                except Exception:
                    continue

        finally:
            if self._socket:
                self._socket.close()

        return list(self.cdp_neighbors.values()), list(self.lldp_neighbors.values())


def get_interfaces() -> list[str]:
    """Get list of available network interfaces.

    Supports:
    - Modern Linux (systemd/udev predictable naming): enp0s3, ens33, enx..., wlp2s0
    - Traditional Linux: eth0, eth1, wlan0, bond0, br0
    - macOS/Darwin: en0, en1, etc.
    - FreeBSD/OpenBSD/NetBSD: em0, igb0, bge0, re0, xl0, fxp0, dc0, rl0, sis0
    - Solaris/illumos: e1000g0, ixgbe0, nxge0, bge0
    """
    import os
    import platform
    import subprocess
    import re

    interfaces = []
    system = platform.system().lower()

    try:
        # Method 1: Linux sysfs (most reliable on Linux)
        if os.path.exists("/sys/class/net"):
            interfaces = os.listdir("/sys/class/net")

        # Method 2: BSD/macOS ifconfig -l
        if not interfaces and system in ("darwin", "freebsd", "openbsd", "netbsd", "dragonfly"):
            for ifconfig_path in ["/sbin/ifconfig", "/usr/sbin/ifconfig", "ifconfig"]:
                try:
                    result = subprocess.run([ifconfig_path, "-l"], capture_output=True, text=True)
                    if result.returncode == 0 and result.stdout.strip():
                        interfaces = result.stdout.strip().split()
                        break
                except (FileNotFoundError, PermissionError):
                    continue

        # Method 3: Parse ifconfig output (BSD/macOS/older systems)
        if not interfaces:
            for ifconfig_path in ["/sbin/ifconfig", "/usr/sbin/ifconfig", "ifconfig"]:
                try:
                    result = subprocess.run([ifconfig_path, "-a"], capture_output=True, text=True)
                    if result.returncode == 0:
                        # Match interface names at start of line (name: or name<space>)
                        interfaces = re.findall(r'^([a-zA-Z][a-zA-Z0-9_-]*)(?::|:\s|\s)', result.stdout, re.MULTILINE)
                        if interfaces:
                            break
                except (FileNotFoundError, PermissionError):
                    continue

        # Method 4: Linux ip command (modern Linux)
        if not interfaces:
            try:
                result = subprocess.run(["ip", "-o", "link", "show"], capture_output=True, text=True)
                if result.returncode == 0:
                    # Format: "1: lo: <LOOPBACK..."
                    interfaces = re.findall(r'^\d+:\s+([a-zA-Z][a-zA-Z0-9_@-]*)(?:@\S+)?:', result.stdout, re.MULTILINE)
            except (FileNotFoundError, PermissionError):
                pass

        # Method 5: Solaris/illumos dladm
        if not interfaces and system == "sunos":
            try:
                result = subprocess.run(["dladm", "show-link", "-p", "-o", "link"], capture_output=True, text=True)
                if result.returncode == 0:
                    interfaces = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
            except (FileNotFoundError, PermissionError):
                pass

        # Method 6: netstat -i fallback (very old systems)
        if not interfaces:
            try:
                result = subprocess.run(["netstat", "-i"], capture_output=True, text=True)
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    # Skip header lines
                    for line in lines[2:]:
                        parts = line.split()
                        if parts and re.match(r'^[a-zA-Z]', parts[0]):
                            iface = parts[0].rstrip('*')
                            if iface not in interfaces:
                                interfaces.append(iface)
            except (FileNotFoundError, PermissionError):
                pass

    except Exception:
        pass

    # Define interface patterns to exclude (virtual/pseudo interfaces)
    # These are typically not useful for CDP/LLDP discovery
    exclude_exact = {
        # Loopback
        "lo", "lo0",
        # Linux virtual
        "sit0", "ip6tnl0", "gre0", "tunl0", "ip6gre0",
    }

    exclude_prefixes = (
        # macOS virtual/system interfaces
        "utun",      # User tunnels (VPN)
        "awdl",      # Apple Wireless Direct Link
        "llw",       # Low Latency WLAN
        "bridge",    # Bridge interfaces (usually virtual)
        "gif",       # Generic tunnel
        "stf",       # 6to4 tunnel
        "ap",        # Access point
        "p2p",       # Point-to-point
        "ipsec",     # IPsec tunnels
        "ppp",       # PPP interfaces (unless physical)

        # Linux virtual interfaces
        "virbr",     # libvirt bridges
        "veth",      # Virtual ethernet (containers)
        "docker",    # Docker bridges
        "br-",       # Docker/container bridges
        "vnet",      # KVM/QEMU virtual NICs
        "tap",       # TAP devices
        "tun",       # TUN devices
        "dummy",     # Dummy interfaces
        "vboxnet",   # VirtualBox host-only
        "vmnet",     # VMware virtual networks

        # BSD virtual
        "pflog",     # PF logging
        "pfsync",    # PF sync
        "enc",       # IPsec encapsulation
        "faith",     # IPv6-to-IPv4 translation

        # VLAN sub-interfaces (keep parent, exclude sub)
        # These have format like eth0.100, but we want eth0
    )

    # Filter interfaces
    filtered = []
    for iface in interfaces:
        # Strip any trailing characters like '*' from netstat
        iface = iface.rstrip('*')

        # Skip exact matches
        if iface in exclude_exact:
            continue

        # Skip prefix matches
        if any(iface.startswith(prefix) for prefix in exclude_prefixes):
            continue

        # Skip VLAN sub-interfaces (e.g., eth0.100) - keep the parent
        if '.' in iface and iface.split('.')[0] in interfaces:
            continue

        # Skip interfaces that are clearly aliases (e.g., eth0:1)
        if ':' in iface:
            continue

        filtered.append(iface)

    # Remove duplicates while preserving order
    seen = set()
    result = []
    for iface in filtered:
        if iface not in seen:
            seen.add(iface)
            result.append(iface)

    return result


def get_physical_interfaces() -> list[str]:
    """Get list of physical network interfaces, excluding virtual ones.

    This is more aggressive filtering for interfaces likely to have
    physical neighbors (switches, routers) that speak CDP/LLDP.
    """
    import re
    all_interfaces = get_interfaces()

    # Patterns that indicate physical interfaces
    physical_patterns = [
        # Linux traditional
        r'^eth\d+$',
        r'^em\d+$',

        # Linux predictable naming (systemd/udev)
        r'^en[ops]\d+',      # enp0s3, ens33, eno1
        r'^enx[0-9a-f]+$',   # enx + MAC address

        # Wireless (may have LLDP on enterprise APs)
        r'^wl',              # wlan0, wlp2s0

        # macOS
        r'^en\d+$',

        # FreeBSD Intel drivers
        r'^em\d+$',          # Intel PRO/1000
        r'^igb\d+$',         # Intel I350/I210
        r'^ix\d+$',          # Intel 10GbE
        r'^ixl\d+$',         # Intel XL710
        r'^ixv\d+$',         # Intel 10GbE VF

        # FreeBSD Broadcom
        r'^bge\d+$',         # Broadcom BCM57xx
        r'^bce\d+$',         # Broadcom BCM5706/5708
        r'^bnxt\d+$',        # Broadcom NetXtreme-C/E

        # FreeBSD Realtek
        r'^re\d+$',          # Realtek 8139C+/8169
        r'^rl\d+$',          # Realtek 8129/8139

        # FreeBSD other common drivers
        r'^xl\d+$',          # 3Com 3c90x
        r'^fxp\d+$',         # Intel EtherExpress PRO/100
        r'^dc\d+$',          # DEC/Intel 21143
        r'^sis\d+$',         # SiS 900/7016
        r'^sk\d+$',          # SysKonnect/Marvell
        r'^msk\d+$',         # Marvell/SysKonnect Yukon II
        r'^nfe\d+$',         # NVIDIA nForce
        r'^age\d+$',         # Attansic/Atheros L1
        r'^alc\d+$',         # Atheros AR8131/8132
        r'^ale\d+$',         # Atheros AR8121/8113/8114
        r'^jme\d+$',         # JMicron JMC250/260
        r'^et\d+$',          # Agere ET1310
        r'^ed\d+$',          # NE2000 and clones
        r'^vr\d+$',          # VIA Rhine
        r'^sf\d+$',          # Adaptec Starfire
        r'^ste\d+$',         # Sundance ST201
        r'^tl\d+$',          # Texas Instruments ThunderLAN
        r'^tx\d+$',          # SMC EtherPower II
        r'^wb\d+$',          # Winbond W89C840F
        r'^vx\d+$',          # 3Com 3c59x
        r'^pcn\d+$',         # AMD PCnet
        r'^lge\d+$',         # Level 1 LXT1001
        r'^nge\d+$',         # National DP83820/DP83821
        r'^ti\d+$',          # Alteon Tigon I/II
        r'^my\d+$',          # Myson MTD803/MTD891
        r'^le\d+$',          # AMD LANCE
        r'^hme\d+$',         # Sun HME
        r'^gem\d+$',         # Sun GEM/ERI
        r'^cas\d+$',         # Sun Cassini

        # OpenBSD specific
        r'^vio\d+$',         # VirtIO
        r'^vmx\d+$',         # VMware VMXNET3
        r'^axe\d+$',         # ASIX USB
        r'^axen\d+$',        # ASIX USB 3.0
        r'^urndis\d+$',      # USB RNDIS
        r'^ure\d+$',         # Realtek USB
        r'^smsc\d+$',        # SMSC LAN95xx USB

        # NetBSD specific
        r'^wm\d+$',          # Intel PRO/1000
        r'^bnx\d+$',         # Broadcom BCM5706/5708

        # Solaris/illumos
        r'^e1000g\d+$',      # Intel PRO/1000
        r'^ixgbe\d+$',       # Intel 10GbE
        r'^nxge\d+$',        # Sun Neptune 10GbE
        r'^bnxe\d+$',        # Broadcom NetXtreme II
        r'^igb\d+$',         # Intel I350
        r'^bge\d+$',         # Broadcom BCM57xx
        r'^nge\d+$',         # National DP83820
        r'^rge\d+$',         # Realtek 8169
        r'^afe\d+$',         # ADMtek AN983
        r'^dmfe\d+$',        # Davicom DM9102
        r'^eri\d+$',         # Sun ERI
        r'^ge\d+$',          # Sun GEM
        r'^hme\d+$',         # Sun HME
        r'^qfe\d+$',         # Sun Quad FastEthernet
        r'^net\d+$',         # Generic network device

        # Bonding/teaming (these aggregate physical interfaces)
        r'^bond\d+$',
        r'^team\d+$',

        # Bridges that may have physical ports
        r'^br\d+$',
        r'^br-[a-zA-Z]',     # Named bridges (not docker hex ones)
    ]

    physical = []
    for iface in all_interfaces:
        for pattern in physical_patterns:
            if re.match(pattern, iface):
                physical.append(iface)
                break

    return physical if physical else all_interfaces


def discover_neighbors(
    interface: str | None = None,
    duration: float = 65.0,
    protocols: list[str] | None = None,
) -> dict[str, Any]:
    """
    Discover neighbors using CDP and/or LLDP.

    Args:
        interface: Network interface to listen on (None for auto-detect)
        duration: How long to listen (default 65s to catch CDP's 60s interval)
        protocols: List of protocols to use ["cdp", "lldp"] (default both)

    Returns:
        Dict with "cdp" and "lldp" keys containing neighbor lists
    """
    protocols = protocols or ["cdp", "lldp"]
    protocols = [p.lower() for p in protocols]

    # Auto-detect interface if not specified
    if not interface:
        interfaces = get_interfaces()
        if not interfaces:
            raise RuntimeError("No network interfaces found")
        # Prefer interfaces that look like physical (eth0, en0, etc.)
        for iface in interfaces:
            if iface.startswith(("eth", "en", "enp", "ens")):
                interface = iface
                break
        if not interface:
            interface = interfaces[0]

    results: dict[str, Any] = {"interface": interface, "cdp": [], "lldp": []}

    if "cdp" in protocols and "lldp" in protocols:
        listener = CombinedListener(interface, timeout=duration)
        cdp_neighbors, lldp_neighbors = listener.listen(duration)
        results["cdp"] = cdp_neighbors
        results["lldp"] = lldp_neighbors
    elif "cdp" in protocols:
        listener = CDPListener(interface, timeout=duration)
        results["cdp"] = listener.listen(duration)
    elif "lldp" in protocols:
        listener = LLDPListener(interface, timeout=duration)
        results["lldp"] = listener.listen(duration)

    return results
