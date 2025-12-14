"""
Neighbor Discovery CLI commands (CDP, LLDP).

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import time

from globaldetect.neighbors.core import (
    CDPListener,
    LLDPListener,
    CombinedListener,
    get_interfaces,
    get_physical_interfaces,
    discover_neighbors,
)


@click.group()
def neighbors():
    """Network neighbor discovery (CDP/LLDP)."""
    pass


@neighbors.command()
@click.option("--physical", "-p", is_flag=True, help="Show only physical interfaces")
@click.option("--all", "-a", "show_all", is_flag=True, help="Show all interfaces including virtual")
def interfaces(physical: bool, show_all: bool):
    """List available network interfaces.

    By default shows interfaces suitable for CDP/LLDP discovery,
    filtering out most virtual/pseudo interfaces.

    Supports interface naming conventions for:
    - Linux (eth0, enp0s3, ens33, wlan0, bond0)
    - macOS/Darwin (en0, en1)
    - FreeBSD (em0, igb0, bge0, re0, xl0)
    - OpenBSD (em0, vio0, vmx0)
    - NetBSD (wm0, bge0)
    - Solaris/illumos (e1000g0, ixgbe0, nxge0)

    Examples:
        globaldetect neighbors interfaces
        globaldetect neighbors interfaces --physical
        globaldetect neighbors interfaces --all
    """
    console = Console()

    if physical:
        ifaces = get_physical_interfaces()
        title = "Physical Network Interfaces"
    elif show_all:
        # Get raw list without filtering
        import os
        import platform
        import subprocess

        ifaces = []
        if os.path.exists("/sys/class/net"):
            ifaces = os.listdir("/sys/class/net")
        else:
            for path in ["/sbin/ifconfig", "/usr/sbin/ifconfig", "ifconfig"]:
                try:
                    result = subprocess.run([path, "-l"], capture_output=True, text=True)
                    if result.returncode == 0:
                        ifaces = result.stdout.strip().split()
                        break
                except (FileNotFoundError, PermissionError):
                    continue
        title = "All Network Interfaces (including virtual)"
    else:
        ifaces = get_interfaces()
        title = "Available Network Interfaces"

    if not ifaces:
        console.print("[yellow]No network interfaces found[/yellow]")
        return

    console.print(f"[cyan]{title}:[/cyan]\n")
    for iface in sorted(ifaces):
        console.print(f"  {iface}")

    console.print(f"\n[dim]Total: {len(ifaces)} interface(s)[/dim]")


@neighbors.command()
@click.option("-i", "--interface", help="Network interface to listen on")
@click.option("-t", "--timeout", default=65, help="Listen duration in seconds (default: 65)")
@click.option("--cdp-only", is_flag=True, help="Only listen for CDP")
@click.option("--lldp-only", is_flag=True, help="Only listen for LLDP")
def discover(interface: str | None, timeout: int, cdp_only: bool, lldp_only: bool):
    """Discover network neighbors using CDP and LLDP.

    Listens for neighbor discovery protocol frames on the specified interface.
    Default timeout is 65 seconds to catch CDP's 60-second announcement interval.

    Note: Requires root/admin privileges for raw socket access.

    Examples:
        sudo globaldetect neighbors discover
        sudo globaldetect neighbors discover -i en0 -t 120
        sudo globaldetect neighbors discover --cdp-only
    """
    console = Console()

    # Determine protocols
    protocols = []
    if cdp_only:
        protocols = ["cdp"]
    elif lldp_only:
        protocols = ["lldp"]
    else:
        protocols = ["cdp", "lldp"]

    # Auto-detect interface
    if not interface:
        ifaces = get_interfaces()
        if not ifaces:
            console.print("[red]Error:[/red] No network interfaces found")
            raise SystemExit(1)

        # Prefer common interface names
        for iface in ifaces:
            if iface.startswith(("eth", "en", "enp", "ens")):
                interface = iface
                break
        if not interface:
            interface = ifaces[0]

    proto_str = " and ".join(p.upper() for p in protocols)
    console.print(f"\n[cyan]Listening for {proto_str} on {interface}...[/cyan]")
    console.print(f"[dim]Timeout: {timeout} seconds. Press Ctrl+C to stop early.[/dim]\n")

    try:
        with console.status(f"[cyan]Listening for neighbor announcements ({timeout}s)...[/cyan]") as status:
            start_time = time.time()

            if "cdp" in protocols and "lldp" in protocols:
                listener = CombinedListener(interface, timeout=timeout)
                cdp_neighbors, lldp_neighbors = listener.listen(timeout)
            elif "cdp" in protocols:
                cdp_listener = CDPListener(interface, timeout=timeout)
                cdp_neighbors = cdp_listener.listen(timeout)
                lldp_neighbors = []
            else:
                lldp_listener = LLDPListener(interface, timeout=timeout)
                lldp_neighbors = lldp_listener.listen(timeout)
                cdp_neighbors = []

            elapsed = time.time() - start_time

    except PermissionError:
        console.print("[red]Error:[/red] Permission denied. Run with sudo/root privileges.")
        raise SystemExit(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopped by user[/yellow]")
        return
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise SystemExit(1)

    # Display results
    total = len(cdp_neighbors) + len(lldp_neighbors)
    console.print(f"[cyan]Discovery complete.[/cyan] Found {total} neighbor(s) in {elapsed:.1f}s\n")

    # CDP neighbors
    if cdp_neighbors:
        console.print("[cyan bold]CDP Neighbors:[/cyan bold]\n")
        table = Table(box=None)
        table.add_column("Device ID", style="white")
        table.add_column("Local Port", style="cyan")
        table.add_column("Remote Port", style="green")
        table.add_column("Platform", style="dim")
        table.add_column("IP Address", style="yellow")
        table.add_column("Capabilities", style="dim")

        for neighbor in cdp_neighbors:
            ip_str = ", ".join(neighbor.ip_addresses[:2]) if neighbor.ip_addresses else "-"
            cap_str = ", ".join(neighbor.capabilities[:3]) if neighbor.capabilities else "-"
            table.add_row(
                neighbor.device_id or "-",
                neighbor.local_interface or interface,
                neighbor.port_id or "-",
                neighbor.platform[:30] if neighbor.platform else "-",
                ip_str,
                cap_str,
            )

        console.print(table)
        console.print()

    # LLDP neighbors
    if lldp_neighbors:
        console.print("[cyan bold]LLDP Neighbors:[/cyan bold]\n")
        table = Table(box=None)
        table.add_column("System Name", style="white")
        table.add_column("Local Port", style="cyan")
        table.add_column("Remote Port", style="green")
        table.add_column("Chassis ID", style="dim")
        table.add_column("Mgmt Address", style="yellow")
        table.add_column("Capabilities", style="dim")

        for neighbor in lldp_neighbors:
            mgmt_str = ", ".join(neighbor.mgmt_addresses[:2]) if neighbor.mgmt_addresses else "-"
            cap_str = ", ".join(neighbor.capabilities[:3]) if neighbor.capabilities else "-"
            table.add_row(
                neighbor.system_name or "-",
                neighbor.local_interface or interface,
                neighbor.port_id or "-",
                neighbor.chassis_id[:17] if neighbor.chassis_id else "-",
                mgmt_str,
                cap_str,
            )

        console.print(table)
        console.print()

    if not cdp_neighbors and not lldp_neighbors:
        console.print("[yellow]No neighbors discovered.[/yellow]")
        console.print("[dim]Ensure you're connected to a network with CDP/LLDP-enabled devices.[/dim]")
        console.print("[dim]CDP announces every 60 seconds, LLDP every 30 seconds by default.[/dim]")


@neighbors.command()
@click.option("-i", "--interface", help="Network interface to listen on")
@click.option("-t", "--timeout", default=65, help="Listen duration in seconds")
def cdp(interface: str | None, timeout: int):
    """Listen for CDP (Cisco Discovery Protocol) frames.

    CDP is Cisco's proprietary neighbor discovery protocol.
    Default announcement interval is 60 seconds.

    Examples:
        sudo globaldetect neighbors cdp
        sudo globaldetect neighbors cdp -i eth0 -t 120
    """
    console = Console()

    if not interface:
        ifaces = get_interfaces()
        if not ifaces:
            console.print("[red]Error:[/red] No network interfaces found")
            raise SystemExit(1)
        for iface in ifaces:
            if iface.startswith(("eth", "en", "enp", "ens")):
                interface = iface
                break
        if not interface:
            interface = ifaces[0]

    console.print(f"\n[cyan]Listening for CDP on {interface}...[/cyan]")
    console.print(f"[dim]Timeout: {timeout}s (CDP interval is typically 60s)[/dim]\n")

    try:
        with console.status(f"[cyan]Listening ({timeout}s)...[/cyan]"):
            listener = CDPListener(interface, timeout=timeout)
            neighbors = listener.listen(timeout)
    except PermissionError:
        console.print("[red]Error:[/red] Permission denied. Run with sudo/root privileges.")
        raise SystemExit(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopped[/yellow]")
        return
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise SystemExit(1)

    if not neighbors:
        console.print("[yellow]No CDP neighbors found[/yellow]")
        return

    console.print(f"[green]Found {len(neighbors)} CDP neighbor(s):[/green]\n")

    for neighbor in neighbors:
        console.print(Panel(
            f"[cyan]Device ID:[/cyan] {neighbor.device_id}\n"
            f"[cyan]Platform:[/cyan] {neighbor.platform}\n"
            f"[cyan]Port ID:[/cyan] {neighbor.port_id}\n"
            f"[cyan]IP Addresses:[/cyan] {', '.join(neighbor.ip_addresses) or 'None'}\n"
            f"[cyan]Native VLAN:[/cyan] {neighbor.native_vlan or 'N/A'}\n"
            f"[cyan]Duplex:[/cyan] {neighbor.duplex or 'N/A'}\n"
            f"[cyan]Capabilities:[/cyan] {', '.join(neighbor.capabilities) or 'None'}\n"
            f"[cyan]VTP Domain:[/cyan] {neighbor.vtp_domain or 'N/A'}\n"
            f"[cyan]Software:[/cyan] {neighbor.software_version[:80] + '...' if len(neighbor.software_version) > 80 else neighbor.software_version}",
            title=f"[bold]{neighbor.device_id}[/bold]",
            border_style="cyan",
        ))


@neighbors.command()
@click.option("-i", "--interface", help="Network interface to listen on")
@click.option("-t", "--timeout", default=35, help="Listen duration in seconds")
def lldp(interface: str | None, timeout: int):
    """Listen for LLDP (Link Layer Discovery Protocol) frames.

    LLDP is a vendor-neutral IEEE 802.1AB standard.
    Default announcement interval is 30 seconds.

    Examples:
        sudo globaldetect neighbors lldp
        sudo globaldetect neighbors lldp -i eth0 -t 60
    """
    console = Console()

    if not interface:
        ifaces = get_interfaces()
        if not ifaces:
            console.print("[red]Error:[/red] No network interfaces found")
            raise SystemExit(1)
        for iface in ifaces:
            if iface.startswith(("eth", "en", "enp", "ens")):
                interface = iface
                break
        if not interface:
            interface = ifaces[0]

    console.print(f"\n[cyan]Listening for LLDP on {interface}...[/cyan]")
    console.print(f"[dim]Timeout: {timeout}s (LLDP interval is typically 30s)[/dim]\n")

    try:
        with console.status(f"[cyan]Listening ({timeout}s)...[/cyan]"):
            listener = LLDPListener(interface, timeout=timeout)
            neighbors = listener.listen(timeout)
    except PermissionError:
        console.print("[red]Error:[/red] Permission denied. Run with sudo/root privileges.")
        raise SystemExit(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopped[/yellow]")
        return
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise SystemExit(1)

    if not neighbors:
        console.print("[yellow]No LLDP neighbors found[/yellow]")
        return

    console.print(f"[green]Found {len(neighbors)} LLDP neighbor(s):[/green]\n")

    for neighbor in neighbors:
        console.print(Panel(
            f"[cyan]System Name:[/cyan] {neighbor.system_name or 'N/A'}\n"
            f"[cyan]Chassis ID:[/cyan] {neighbor.chassis_id} ({neighbor.chassis_id_subtype})\n"
            f"[cyan]Port ID:[/cyan] {neighbor.port_id} ({neighbor.port_id_subtype})\n"
            f"[cyan]Port Description:[/cyan] {neighbor.port_description or 'N/A'}\n"
            f"[cyan]Mgmt Addresses:[/cyan] {', '.join(neighbor.mgmt_addresses) or 'None'}\n"
            f"[cyan]Capabilities:[/cyan] {', '.join(neighbor.capabilities) or 'None'}\n"
            f"[cyan]TTL:[/cyan] {neighbor.ttl}s\n"
            f"[cyan]System Description:[/cyan] {neighbor.system_description[:100] + '...' if len(neighbor.system_description) > 100 else neighbor.system_description}",
            title=f"[bold]{neighbor.system_name or neighbor.chassis_id}[/bold]",
            border_style="green",
        ))
