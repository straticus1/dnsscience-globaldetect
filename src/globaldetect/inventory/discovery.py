"""
Network discovery for inventory cataloging.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import asyncio
import ipaddress
import socket
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from globaldetect.inventory.models import (
    Location,
    NetworkInterface,
    Switch,
    System,
    SystemStatus,
    SystemType,
)


@dataclass
class DiscoveryResult:
    """Result of a discovery operation."""
    systems: list[System] = field(default_factory=list)
    switches: list[Switch] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    scan_started: datetime | None = None
    scan_completed: datetime | None = None
    hosts_scanned: int = 0
    hosts_alive: int = 0


@dataclass
class HostInfo:
    """Information gathered about a host."""
    ip: str
    hostname: str | None = None
    mac_address: str | None = None
    open_ports: list[int] = field(default_factory=list)
    os_fingerprint: str | None = None
    services: dict[int, str] = field(default_factory=dict)
    is_network_device: bool = False
    cdp_info: dict[str, Any] | None = None
    lldp_info: dict[str, Any] | None = None


class NetworkDiscovery:
    """Discover and catalog network assets."""

    # Common ports to scan for service identification
    COMMON_PORTS = [
        22,    # SSH
        23,    # Telnet
        80,    # HTTP
        443,   # HTTPS
        161,   # SNMP
        179,   # BGP
        389,   # LDAP
        445,   # SMB
        3306,  # MySQL
        3389,  # RDP
        5432,  # PostgreSQL
        5900,  # VNC
        8080,  # HTTP Alt
        8443,  # HTTPS Alt
    ]

    # Ports that typically indicate network devices
    NETWORK_DEVICE_PORTS = {22, 23, 161, 179}

    def __init__(
        self,
        timeout: float = 2.0,
        max_concurrent: int = 50,
        ports: list[int] | None = None,
    ):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.ports = ports or self.COMMON_PORTS

    async def discover_subnet(
        self,
        subnet: str,
        ping_sweep: bool = True,
        port_scan: bool = True,
        resolve_dns: bool = True,
        get_geoip: bool = False,
    ) -> DiscoveryResult:
        """Discover hosts in a subnet.

        Args:
            subnet: CIDR notation subnet (e.g., "192.168.1.0/24")
            ping_sweep: Perform ICMP ping sweep first
            port_scan: Scan common ports
            resolve_dns: Resolve hostnames via reverse DNS
            get_geoip: Get GeoIP information for each host

        Returns:
            DiscoveryResult with discovered systems
        """
        result = DiscoveryResult(scan_started=datetime.now())

        try:
            network = ipaddress.ip_network(subnet, strict=False)
        except ValueError as e:
            result.errors.append(f"Invalid subnet: {e}")
            result.scan_completed = datetime.now()
            return result

        # Get list of hosts to scan
        if network.num_addresses > 65536:
            result.errors.append("Subnet too large (max /16)")
            result.scan_completed = datetime.now()
            return result

        hosts = list(network.hosts())
        result.hosts_scanned = len(hosts)

        # Ping sweep to find alive hosts
        alive_hosts: list[str] = []
        if ping_sweep:
            alive_hosts = await self._ping_sweep(hosts)
        else:
            alive_hosts = [str(h) for h in hosts]

        result.hosts_alive = len(alive_hosts)

        # Scan each alive host
        semaphore = asyncio.Semaphore(self.max_concurrent)

        async def scan_host(ip: str) -> HostInfo | None:
            async with semaphore:
                return await self._scan_host(
                    ip,
                    port_scan=port_scan,
                    resolve_dns=resolve_dns,
                )

        tasks = [scan_host(ip) for ip in alive_hosts]
        host_infos = await asyncio.gather(*tasks)

        # Convert to System objects
        for info in host_infos:
            if info is None:
                continue

            # Determine system type based on open ports and services
            system_type = self._classify_system(info)

            if info.is_network_device:
                # Create as switch
                switch = Switch(
                    hostname=info.hostname,
                    management_ip=info.ip,
                    platform=info.os_fingerprint,
                    last_seen=datetime.now(),
                )
                if info.cdp_info:
                    switch.platform = info.cdp_info.get("platform")
                    switch.capabilities = info.cdp_info.get("capabilities", [])
                result.switches.append(switch)
            else:
                # Create as system
                system = System(
                    hostname=info.hostname,
                    primary_ip=info.ip,
                    primary_mac=info.mac_address,
                    system_type=system_type,
                    status=SystemStatus.ACTIVE,
                    os_name=info.os_fingerprint,
                    discovered_at=datetime.now(),
                    discovered_via="scan",
                    last_seen=datetime.now(),
                )

                # Add interface
                iface = NetworkInterface(
                    name="eth0",  # Placeholder
                    ip_addresses=[info.ip],
                    mac_address=info.mac_address,
                    is_primary=True,
                    discovered_via="scan",
                    last_seen=datetime.now(),
                )
                system.interfaces.append(iface)

                # Add GeoIP if requested
                if get_geoip:
                    await self._add_geoip(system)

                result.systems.append(system)

        result.scan_completed = datetime.now()
        return result

    async def discover_host(
        self,
        host: str,
        full_scan: bool = True,
        get_geoip: bool = False,
    ) -> System | None:
        """Discover a single host.

        Args:
            host: IP address or hostname
            full_scan: Perform detailed port scan
            get_geoip: Get GeoIP information

        Returns:
            System object or None if host is unreachable
        """
        # Resolve hostname to IP if needed
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror:
            return None

        # Check if host is alive
        if not await self._ping_host(ip):
            return None

        # Scan the host
        info = await self._scan_host(
            ip,
            port_scan=full_scan,
            resolve_dns=True,
        )

        if info is None:
            return None

        system_type = self._classify_system(info)

        system = System(
            hostname=info.hostname or host,
            fqdn=host if "." in host else None,
            primary_ip=info.ip,
            primary_mac=info.mac_address,
            system_type=system_type,
            status=SystemStatus.ACTIVE,
            os_name=info.os_fingerprint,
            discovered_at=datetime.now(),
            discovered_via="scan",
            last_seen=datetime.now(),
        )

        # Add interface
        iface = NetworkInterface(
            name="eth0",
            ip_addresses=[info.ip],
            mac_address=info.mac_address,
            is_primary=True,
            discovered_via="scan",
            last_seen=datetime.now(),
        )
        system.interfaces.append(iface)

        if get_geoip:
            await self._add_geoip(system)

        return system

    async def _ping_sweep(self, hosts: list[ipaddress.IPv4Address | ipaddress.IPv6Address]) -> list[str]:
        """Perform parallel ping sweep."""
        semaphore = asyncio.Semaphore(self.max_concurrent)

        async def ping_with_semaphore(ip: str) -> str | None:
            async with semaphore:
                if await self._ping_host(ip):
                    return ip
                return None

        tasks = [ping_with_semaphore(str(h)) for h in hosts]
        results = await asyncio.gather(*tasks)
        return [r for r in results if r is not None]

    async def _ping_host(self, ip: str) -> bool:
        """Ping a single host."""
        try:
            # Use system ping command
            proc = await asyncio.create_subprocess_exec(
                "ping", "-c", "1", "-W", "1", ip,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.wait(), timeout=self.timeout)
            return proc.returncode == 0
        except (asyncio.TimeoutError, Exception):
            return False

    async def _scan_host(
        self,
        ip: str,
        port_scan: bool = True,
        resolve_dns: bool = True,
    ) -> HostInfo | None:
        """Scan a single host for information."""
        info = HostInfo(ip=ip)

        # Resolve hostname
        if resolve_dns:
            try:
                hostname, _, _ = socket.gethostbyaddr(ip)
                info.hostname = hostname
            except socket.herror:
                pass

        # Get MAC address (only works on local network)
        info.mac_address = await self._get_mac_address(ip)

        # Port scan
        if port_scan:
            info.open_ports = await self._scan_ports(ip, self.ports)
            info.services = await self._identify_services(ip, info.open_ports)

            # Check if this looks like a network device
            network_ports = set(info.open_ports) & self.NETWORK_DEVICE_PORTS
            if network_ports:
                info.is_network_device = True

        # Basic OS fingerprinting from open ports
        info.os_fingerprint = self._fingerprint_os(info.open_ports, info.services)

        return info

    async def _scan_ports(self, ip: str, ports: list[int]) -> list[int]:
        """Scan ports on a host."""
        open_ports = []

        async def check_port(port: int) -> int | None:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=self.timeout,
                )
                writer.close()
                await writer.wait_closed()
                return port
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return None

        tasks = [check_port(p) for p in ports]
        results = await asyncio.gather(*tasks)
        return [p for p in results if p is not None]

    async def _identify_services(self, ip: str, ports: list[int]) -> dict[int, str]:
        """Identify services running on open ports."""
        services = {}
        service_map = {
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            161: "SNMP",
            179: "BGP",
            389: "LDAP",
            443: "HTTPS",
            445: "SMB",
            465: "SMTPS",
            587: "Submission",
            636: "LDAPS",
            993: "IMAPS",
            995: "POP3S",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            6379: "Redis",
            8080: "HTTP-Alt",
            8443: "HTTPS-Alt",
            27017: "MongoDB",
        }

        for port in ports:
            if port in service_map:
                services[port] = service_map[port]
            else:
                services[port] = "unknown"

        return services

    async def _get_mac_address(self, ip: str) -> str | None:
        """Get MAC address from ARP cache."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "arp", "-n", ip,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=2.0)
            output = stdout.decode()

            # Parse ARP output (format varies by OS)
            for line in output.split("\n"):
                if ip in line:
                    # Look for MAC address pattern
                    import re
                    mac_match = re.search(r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', line)
                    if mac_match:
                        return mac_match.group().lower()
        except Exception:
            pass
        return None

    def _fingerprint_os(self, open_ports: list[int], services: dict[int, str]) -> str | None:
        """Basic OS fingerprinting based on open ports."""
        port_set = set(open_ports)

        # Windows indicators
        if {445, 3389} & port_set:
            return "Windows"

        # Linux indicators
        if 22 in port_set and 445 not in port_set:
            return "Linux/Unix"

        # Network device indicators
        if {22, 23, 161} & port_set and len(port_set) <= 5:
            if 179 in port_set:
                return "Router"
            return "Network Device"

        # Printer indicators
        if 9100 in port_set or 631 in port_set:
            return "Printer"

        return None

    def _classify_system(self, info: HostInfo) -> SystemType:
        """Classify system type based on scan info."""
        port_set = set(info.open_ports)

        # Network devices
        if info.is_network_device:
            if 179 in port_set:
                return SystemType.ROUTER
            return SystemType.SWITCH

        # Servers (multiple services)
        server_ports = {22, 80, 443, 3306, 5432, 8080}
        if len(port_set & server_ports) >= 2:
            return SystemType.SERVER

        # Windows workstation
        if {445, 3389} <= port_set:
            return SystemType.WORKSTATION

        # Single SSH could be server or workstation
        if 22 in port_set:
            return SystemType.SERVER

        return SystemType.UNKNOWN

    async def _add_geoip(self, system: System) -> None:
        """Add GeoIP information to system."""
        if not system.primary_ip:
            return

        try:
            # Use IPInfo.io
            import httpx
            import os

            token = os.environ.get("IPINFO_TOKEN", "")
            url = f"https://ipinfo.io/{system.primary_ip}/json"
            if token:
                url += f"?token={token}"

            async with httpx.AsyncClient() as client:
                resp = await client.get(url, timeout=5.0)
                if resp.status_code == 200:
                    data = resp.json()
                    system.ip_country = data.get("country")
                    system.ip_city = data.get("city")
                    system.ip_org = data.get("org")

                    # Parse ASN from org field
                    org = data.get("org", "")
                    if org.startswith("AS"):
                        parts = org.split(" ", 1)
                        try:
                            system.asn = int(parts[0][2:])
                            if len(parts) > 1:
                                system.as_name = parts[1]
                        except ValueError:
                            pass
        except Exception:
            pass


class AgentDiscovery:
    """Self-discovery for agent mode - gather info about the local system."""

    @classmethod
    def discover_self(cls) -> System:
        """Discover information about the local system."""
        import platform
        import os

        system = System(
            hostname=platform.node(),
            fqdn=socket.getfqdn(),
            system_type=SystemType.SERVER,
            status=SystemStatus.ACTIVE,
            os_name=platform.system(),
            os_version=platform.release(),
            kernel_version=platform.version(),
            discovered_at=datetime.now(),
            discovered_via="agent",
            last_seen=datetime.now(),
        )

        # Get CPU info
        try:
            system.cpu_cores = os.cpu_count()
        except Exception:
            pass

        # Get memory info (Linux)
        try:
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        # Convert from KB to GB
                        kb = int(line.split()[1])
                        system.ram_gb = round(kb / 1024 / 1024, 1)
                        break
        except Exception:
            pass

        # Get disk info
        try:
            import shutil
            total, _, _ = shutil.disk_usage("/")
            system.disk_gb = round(total / 1024 / 1024 / 1024, 1)
        except Exception:
            pass

        # Get network interfaces
        system.interfaces = cls._get_interfaces()

        # Set primary IP and MAC
        for iface in system.interfaces:
            if iface.is_primary:
                if iface.ip_addresses:
                    system.primary_ip = iface.ip_addresses[0]
                system.primary_mac = iface.mac_address
                break

        return system

    @classmethod
    def _get_interfaces(cls) -> list[NetworkInterface]:
        """Get network interface information."""
        interfaces = []

        try:
            import subprocess
            import re

            # Try ip command first (Linux)
            result = subprocess.run(
                ["ip", "-j", "addr"],
                capture_output=True,
                text=True,
            )

            if result.returncode == 0:
                import json
                data = json.loads(result.stdout)

                for iface_data in data:
                    name = iface_data.get("ifname", "")

                    # Skip loopback
                    if name == "lo":
                        continue

                    iface = NetworkInterface(
                        name=name,
                        is_up="UP" in iface_data.get("flags", []),
                        mtu=iface_data.get("mtu"),
                    )

                    # Get addresses
                    for addr_info in iface_data.get("addr_info", []):
                        if addr_info.get("family") == "inet":
                            iface.ip_addresses.append(addr_info.get("local", ""))
                        if addr_info.get("family") == "link":
                            iface.mac_address = addr_info.get("local", "")

                    # Get MAC from address if not in addr_info
                    if not iface.mac_address:
                        iface.mac_address = iface_data.get("address")

                    # Mark first interface with IP as primary
                    if iface.ip_addresses and not any(i.is_primary for i in interfaces):
                        iface.is_primary = True

                    interfaces.append(iface)

                return interfaces

        except Exception:
            pass

        # Fallback to ifconfig (macOS, BSD)
        try:
            result = subprocess.run(
                ["/sbin/ifconfig", "-a"],
                capture_output=True,
                text=True,
            )

            if result.returncode == 0:
                current_iface = None

                for line in result.stdout.split("\n"):
                    # New interface
                    if line and not line.startswith("\t") and not line.startswith(" "):
                        if ":" in line:
                            name = line.split(":")[0]
                            if name != "lo0":
                                current_iface = NetworkInterface(name=name)
                                interfaces.append(current_iface)
                            else:
                                current_iface = None

                    elif current_iface:
                        line = line.strip()

                        # MAC address
                        if "ether" in line:
                            parts = line.split()
                            idx = parts.index("ether")
                            if idx + 1 < len(parts):
                                current_iface.mac_address = parts[idx + 1]

                        # IPv4 address
                        if "inet " in line:
                            parts = line.split()
                            idx = parts.index("inet")
                            if idx + 1 < len(parts):
                                current_iface.ip_addresses.append(parts[idx + 1])

                        # MTU
                        if "mtu" in line:
                            match = re.search(r"mtu\s+(\d+)", line)
                            if match:
                                current_iface.mtu = int(match.group(1))

                        # Status
                        if "status:" in line:
                            current_iface.is_up = "active" in line

                # Mark first interface with IP as primary
                for iface in interfaces:
                    if iface.ip_addresses:
                        iface.is_primary = True
                        break

        except Exception:
            pass

        return interfaces
