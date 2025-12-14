"""
Linux/BSD firewall configuration collectors.

Supports:
- iptables (legacy Linux firewall)
- nftables (modern Linux firewall)
- pf (BSD packet filter)
- ipfw (FreeBSD firewall)

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import logging
from globaldetect.backup.base import SSHCollector
from globaldetect.backup.models import DeviceVendor, BackupType

logger = logging.getLogger(__name__)


class IPTablesCollector(SSHCollector):
    """Collector for Linux iptables firewall rules."""

    VENDOR = DeviceVendor.IPTABLES
    SUPPORTED_BACKUP_TYPES = [
        BackupType.FULL,
        BackupType.FIREWALL,
        BackupType.NAT,
        BackupType.NETWORK,
    ]

    async def get_config(self, backup_type: BackupType) -> str | None:
        """Retrieve iptables configuration."""
        try:
            parts = []

            if backup_type == BackupType.FULL:
                # Full iptables dump (restorable format)
                output = await self.run_command("sudo iptables-save")
                parts.append(f"# IPv4 iptables\n{output}")

                # IPv6 if available
                try:
                    output6 = await self.run_command("sudo ip6tables-save")
                    parts.append(f"# IPv6 ip6tables\n{output6}")
                except Exception:
                    pass

            elif backup_type == BackupType.FIREWALL:
                # Filter table
                output = await self.run_command("sudo iptables -L -v -n --line-numbers")
                parts.append(f"# Filter Table (IPv4)\n{output}")

                try:
                    output6 = await self.run_command("sudo ip6tables -L -v -n --line-numbers")
                    parts.append(f"# Filter Table (IPv6)\n{output6}")
                except Exception:
                    pass

            elif backup_type == BackupType.NAT:
                # NAT table
                output = await self.run_command("sudo iptables -t nat -L -v -n --line-numbers")
                parts.append(f"# NAT Table\n{output}")

                # Mangle table
                output = await self.run_command("sudo iptables -t mangle -L -v -n --line-numbers")
                parts.append(f"# Mangle Table\n{output}")

            elif backup_type == BackupType.NETWORK:
                # Network configuration
                output = await self.run_command("ip addr show")
                parts.append(f"# IP Addresses\n{output}")

                output = await self.run_command("ip route show")
                parts.append(f"# Routing Table\n{output}")

                output = await self.run_command("ip rule show")
                parts.append(f"# Policy Routing Rules\n{output}")

                # Sysctl network settings
                output = await self.run_command("sysctl net.ipv4 2>/dev/null | grep -E 'forward|rp_filter|icmp'")
                parts.append(f"# Sysctl IPv4 Settings\n{output}")

            return "\n\n".join(parts)

        except Exception as e:
            logger.error(f"Failed to get iptables config: {e}")
            return None


class NFTablesCollector(SSHCollector):
    """Collector for Linux nftables firewall rules."""

    VENDOR = DeviceVendor.NFTABLES
    SUPPORTED_BACKUP_TYPES = [
        BackupType.FULL,
        BackupType.FIREWALL,
        BackupType.NAT,
        BackupType.NETWORK,
    ]

    async def get_config(self, backup_type: BackupType) -> str | None:
        """Retrieve nftables configuration."""
        try:
            parts = []

            if backup_type == BackupType.FULL:
                # Full nftables ruleset (restorable format)
                output = await self.run_command("sudo nft list ruleset")
                parts.append(f"# nftables ruleset\n{output}")

            elif backup_type == BackupType.FIREWALL:
                # List filter chains
                output = await self.run_command("sudo nft list tables")
                parts.append(f"# Tables\n{output}")

                output = await self.run_command("sudo nft list ruleset | grep -A 100 'table.*filter'")
                parts.append(f"# Filter Rules\n{output}")

            elif backup_type == BackupType.NAT:
                output = await self.run_command("sudo nft list ruleset | grep -A 100 'table.*nat'")
                parts.append(f"# NAT Rules\n{output}")

            elif backup_type == BackupType.NETWORK:
                output = await self.run_command("ip addr show")
                parts.append(f"# IP Addresses\n{output}")

                output = await self.run_command("ip route show")
                parts.append(f"# Routing Table\n{output}")

            return "\n\n".join(parts)

        except Exception as e:
            logger.error(f"Failed to get nftables config: {e}")
            return None


class PFCollector(SSHCollector):
    """Collector for BSD pf (packet filter) firewall rules."""

    VENDOR = DeviceVendor.PF_BSD
    SUPPORTED_BACKUP_TYPES = [
        BackupType.FULL,
        BackupType.FIREWALL,
        BackupType.NAT,
        BackupType.NETWORK,
    ]

    async def get_config(self, backup_type: BackupType) -> str | None:
        """Retrieve pf configuration."""
        try:
            parts = []

            if backup_type == BackupType.FULL:
                # pf.conf file
                output = await self.run_command("sudo cat /etc/pf.conf")
                parts.append(f"# /etc/pf.conf\n{output}")

                # Active rules
                output = await self.run_command("sudo pfctl -sr")
                parts.append(f"# Active Filter Rules\n{output}")

                output = await self.run_command("sudo pfctl -sn")
                parts.append(f"# Active NAT Rules\n{output}")

            elif backup_type == BackupType.FIREWALL:
                output = await self.run_command("sudo pfctl -sr")
                parts.append(f"# Filter Rules\n{output}")

                output = await self.run_command("sudo pfctl -ss")
                parts.append(f"# State Table\n{output}")

            elif backup_type == BackupType.NAT:
                output = await self.run_command("sudo pfctl -sn")
                parts.append(f"# NAT Rules\n{output}")

            elif backup_type == BackupType.NETWORK:
                output = await self.run_command("ifconfig -a")
                parts.append(f"# Interfaces\n{output}")

                output = await self.run_command("netstat -rn")
                parts.append(f"# Routing Table\n{output}")

            return "\n\n".join(parts)

        except Exception as e:
            logger.error(f"Failed to get pf config: {e}")
            return None


class IPFWCollector(SSHCollector):
    """Collector for FreeBSD ipfw firewall rules."""

    VENDOR = DeviceVendor.IPFW
    SUPPORTED_BACKUP_TYPES = [
        BackupType.FULL,
        BackupType.FIREWALL,
        BackupType.NAT,
        BackupType.NETWORK,
    ]

    async def get_config(self, backup_type: BackupType) -> str | None:
        """Retrieve ipfw configuration."""
        try:
            parts = []

            if backup_type == BackupType.FULL:
                # All rules
                output = await self.run_command("sudo ipfw list")
                parts.append(f"# IPFW Rules\n{output}")

                # NAT instances
                output = await self.run_command("sudo ipfw nat show config")
                parts.append(f"# NAT Configuration\n{output}")

            elif backup_type == BackupType.FIREWALL:
                output = await self.run_command("sudo ipfw -a list")
                parts.append(f"# Firewall Rules with Counters\n{output}")

            elif backup_type == BackupType.NAT:
                output = await self.run_command("sudo ipfw nat show config")
                parts.append(f"# NAT Configuration\n{output}")

            elif backup_type == BackupType.NETWORK:
                output = await self.run_command("ifconfig -a")
                parts.append(f"# Interfaces\n{output}")

                output = await self.run_command("netstat -rn")
                parts.append(f"# Routing Table\n{output}")

            return "\n\n".join(parts)

        except Exception as e:
            logger.error(f"Failed to get ipfw config: {e}")
            return None
