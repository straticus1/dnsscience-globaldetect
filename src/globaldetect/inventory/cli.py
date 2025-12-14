"""
CLI for network inventory management.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import asyncio
import json
import os
from datetime import datetime

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree

from globaldetect.inventory.database import get_database, Database
from globaldetect.inventory.models import (
    Location,
    NetworkInterface,
    Switch,
    System,
    SystemStatus,
    SystemType,
)
from globaldetect.inventory.discovery import NetworkDiscovery, AgentDiscovery

console = Console()


def get_db() -> Database:
    """Get database instance from environment."""
    conn_str = os.environ.get("GLOBALDETECT_DB")
    db = get_database(conn_str)
    db.initialize()
    return db


# ============================================================================
# Catalog commands (discovery)
# ============================================================================

@click.group()
def catalog():
    """Network discovery and cataloging."""
    pass


@catalog.command("discover")
@click.argument("target")
@click.option("--type", "target_type", type=click.Choice(["subnet", "host"]), default="subnet",
              help="Target type: subnet (CIDR) or single host")
@click.option("--no-ping", is_flag=True, help="Skip ping sweep (scan all IPs)")
@click.option("--no-ports", is_flag=True, help="Skip port scanning")
@click.option("--geoip", is_flag=True, help="Include GeoIP information")
@click.option("--save", is_flag=True, help="Save discovered systems to inventory")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def discover_cmd(target: str, target_type: str, no_ping: bool, no_ports: bool,
                 geoip: bool, save: bool, json_output: bool):
    """Discover network assets.

    Examples:
        globaldetect catalog discover 192.168.1.0/24
        globaldetect catalog discover --type host 10.0.0.1
        globaldetect catalog discover 10.0.0.0/24 --geoip --save
    """
    discovery = NetworkDiscovery()

    if target_type == "subnet" or "/" in target:
        # Subnet discovery
        console.print(f"[cyan]Scanning subnet {target}...[/cyan]")

        result = asyncio.run(discovery.discover_subnet(
            target,
            ping_sweep=not no_ping,
            port_scan=not no_ports,
            get_geoip=geoip,
        ))

        if json_output:
            output = {
                "scan_started": result.scan_started.isoformat() if result.scan_started else None,
                "scan_completed": result.scan_completed.isoformat() if result.scan_completed else None,
                "hosts_scanned": result.hosts_scanned,
                "hosts_alive": result.hosts_alive,
                "systems": [s.to_dict() for s in result.systems],
                "switches": [s.to_dict() for s in result.switches],
                "errors": result.errors,
            }
            console.print_json(json.dumps(output, default=str))
            return

        # Display results
        if result.errors:
            for err in result.errors:
                console.print(f"[red]Error: {err}[/red]")

        console.print(f"\n[green]Scan completed![/green]")
        console.print(f"Hosts scanned: {result.hosts_scanned}")
        console.print(f"Hosts alive: {result.hosts_alive}")
        console.print(f"Systems found: {len(result.systems)}")
        console.print(f"Switches found: {len(result.switches)}")

        if result.systems:
            console.print("\n[bold]Discovered Systems:[/bold]")
            table = Table(show_header=True)
            table.add_column("IP Address")
            table.add_column("Hostname")
            table.add_column("Type")
            table.add_column("OS")
            table.add_column("Open Ports")

            for system in result.systems:
                ports = ", ".join(
                    str(p) for iface in system.interfaces
                    for p in getattr(iface, "open_ports", [])
                ) or "-"
                table.add_row(
                    system.primary_ip or "-",
                    system.hostname or "-",
                    system.system_type.value,
                    system.os_name or "-",
                    ports,
                )

            console.print(table)

        if result.switches:
            console.print("\n[bold]Discovered Network Devices:[/bold]")
            table = Table(show_header=True)
            table.add_column("IP Address")
            table.add_column("Hostname")
            table.add_column("Platform")

            for switch in result.switches:
                table.add_row(
                    switch.management_ip or "-",
                    switch.hostname or "-",
                    switch.platform or "-",
                )

            console.print(table)

        # Save to database if requested
        if save and (result.systems or result.switches):
            db = get_db()
            saved_systems = 0
            saved_switches = 0

            for system in result.systems:
                # Check if already exists
                existing = db.get_system_by_ip(system.primary_ip)
                if existing:
                    # Update last_seen
                    existing.last_seen = datetime.now()
                    db.update_system(existing)
                else:
                    db.create_system(system)
                    saved_systems += 1

            for switch in result.switches:
                existing = db.get_switch_by_ip(switch.management_ip)
                if existing:
                    existing.last_seen = datetime.now()
                    db.update_switch(existing)
                else:
                    db.create_switch(switch)
                    saved_switches += 1

            db.close()
            console.print(f"\n[green]Saved {saved_systems} new systems, {saved_switches} new switches[/green]")

    else:
        # Single host discovery
        console.print(f"[cyan]Scanning host {target}...[/cyan]")

        system = asyncio.run(discovery.discover_host(target, get_geoip=geoip))

        if system is None:
            console.print("[red]Host not reachable[/red]")
            return

        if json_output:
            console.print_json(json.dumps(system.to_dict(), default=str))
            return

        # Display system info
        _display_system(system)

        if save:
            db = get_db()
            existing = db.get_system_by_ip(system.primary_ip)
            if existing:
                console.print("[yellow]System already in inventory, updating last_seen[/yellow]")
                existing.last_seen = datetime.now()
                db.update_system(existing)
            else:
                db.create_system(system)
                console.print("[green]System saved to inventory[/green]")
            db.close()


@catalog.command("self")
@click.option("--save", is_flag=True, help="Save to inventory")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def self_discover(save: bool, json_output: bool):
    """Discover information about this system (for agent mode)."""
    system = AgentDiscovery.discover_self()

    if json_output:
        console.print_json(json.dumps(system.to_dict(), default=str))
        return

    _display_system(system)

    if save:
        db = get_db()
        existing = db.get_system_by_hostname(system.hostname)
        if existing:
            # Update existing
            existing.last_seen = datetime.now()
            existing.agent_last_checkin = datetime.now()
            db.update_system(existing)
            console.print("[yellow]System updated in inventory[/yellow]")
        else:
            db.create_system(system)
            console.print("[green]System saved to inventory[/green]")
        db.close()


# ============================================================================
# System CRUD commands
# ============================================================================

@click.group()
def system():
    """System inventory management."""
    pass


@system.command("list")
@click.option("--type", "system_type", type=click.Choice([t.value for t in SystemType]),
              help="Filter by system type")
@click.option("--status", type=click.Choice([s.value for s in SystemStatus]),
              help="Filter by status")
@click.option("--tag", help="Filter by tag")
@click.option("--switch", "switch_name", help="Show systems connected to this switch")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def system_list(system_type: str | None, status: str | None, tag: str | None,
                switch_name: str | None, json_output: bool):
    """List systems in inventory."""
    db = get_db()

    # Get switch ID if filtering by switch
    switch_id = None
    if switch_name:
        switch = db.get_switch_by_hostname(switch_name)
        if switch:
            switch_id = switch.id
        else:
            console.print(f"[red]Switch '{switch_name}' not found[/red]")
            return

    systems = db.list_systems(
        system_type=SystemType(system_type) if system_type else None,
        status=SystemStatus(status) if status else None,
        tag=tag,
        switch_id=switch_id,
    )

    if json_output:
        output = [s.to_dict() for s in systems]
        console.print_json(json.dumps(output, default=str))
        return

    if not systems:
        console.print("[yellow]No systems found[/yellow]")
        return

    table = Table(show_header=True, title=f"Systems ({len(systems)})")
    table.add_column("Hostname")
    table.add_column("IP Address")
    table.add_column("Type")
    table.add_column("Status")
    table.add_column("OS")
    table.add_column("Location")
    table.add_column("Last Seen")

    for sys in systems:
        location = "-"
        if sys.location:
            parts = []
            if sys.location.datacenter:
                parts.append(sys.location.datacenter)
            if sys.location.rack:
                parts.append(f"Rack {sys.location.rack}")
            location = " / ".join(parts) if parts else "-"

        last_seen = "-"
        if sys.last_seen:
            last_seen = sys.last_seen.strftime("%Y-%m-%d %H:%M")

        table.add_row(
            sys.hostname or "-",
            sys.primary_ip or "-",
            sys.system_type.value,
            sys.status.value,
            sys.os_name or "-",
            location,
            last_seen,
        )

    console.print(table)
    db.close()


@system.command("show")
@click.argument("identifier")
@click.option("--switch", is_flag=True, help="Show switch connectivity")
@click.option("--network", is_flag=True, help="Show network details")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def system_show(identifier: str, switch: bool, network: bool, json_output: bool):
    """Show system details.

    IDENTIFIER can be hostname, FQDN, or IP address.

    Examples:
        globaldetect system show webserver01
        globaldetect system show 192.168.1.100 --switch
        globaldetect system show webserver01.example.com --network
    """
    db = get_db()

    # Try to find system by hostname first, then IP
    sys = db.get_system_by_hostname(identifier)
    if sys is None:
        sys = db.get_system_by_ip(identifier)

    if sys is None:
        console.print(f"[red]System '{identifier}' not found[/red]")
        db.close()
        return

    # Load location if exists
    if sys.location_id:
        sys.location = db.get_location(sys.location_id)

    # Load switch info for interfaces
    for iface in sys.interfaces:
        if iface.connected_switch_id:
            iface.connected_switch = db.get_switch(iface.connected_switch_id)

    if json_output:
        console.print_json(json.dumps(sys.to_dict(), default=str))
        db.close()
        return

    _display_system(sys, show_switch=switch, show_network=network)
    db.close()


@system.command("add")
@click.option("--hostname", required=True, help="System hostname")
@click.option("--ip", "primary_ip", help="Primary IP address")
@click.option("--type", "system_type", type=click.Choice([t.value for t in SystemType]),
              default="server", help="System type")
@click.option("--status", type=click.Choice([s.value for s in SystemStatus]),
              default="active", help="System status")
@click.option("--os", "os_name", help="Operating system")
@click.option("--vendor", help="Hardware vendor")
@click.option("--model", help="Hardware model")
@click.option("--serial", "serial_number", help="Serial number")
@click.option("--datacenter", help="Datacenter name")
@click.option("--rack", help="Rack identifier")
@click.option("--rack-unit", type=int, help="Rack unit (U position)")
@click.option("--tag", multiple=True, help="Tags (can specify multiple)")
@click.option("--note", "notes", help="Notes")
def system_add(hostname: str, primary_ip: str | None, system_type: str, status: str,
               os_name: str | None, vendor: str | None, model: str | None,
               serial_number: str | None, datacenter: str | None, rack: str | None,
               rack_unit: int | None, tag: tuple, notes: str | None):
    """Add a system to inventory."""
    db = get_db()

    # Check if already exists
    existing = db.get_system_by_hostname(hostname)
    if existing:
        console.print(f"[red]System '{hostname}' already exists[/red]")
        db.close()
        return

    # Create location if specified
    location_id = None
    if datacenter or rack:
        location = Location(
            datacenter=datacenter,
            rack=rack,
            rack_unit=rack_unit,
        )
        location = db.create_location(location)
        location_id = location.id

    system = System(
        hostname=hostname,
        primary_ip=primary_ip,
        system_type=SystemType(system_type),
        status=SystemStatus(status),
        os_name=os_name,
        vendor=vendor,
        model=model,
        serial_number=serial_number,
        location_id=location_id,
        tags=list(tag),
        notes=notes,
        discovered_via="manual",
        discovered_at=datetime.now(),
        last_seen=datetime.now(),
    )

    system = db.create_system(system)
    console.print(f"[green]System '{hostname}' created with ID {system.id}[/green]")
    db.close()


@system.command("update")
@click.argument("identifier")
@click.option("--hostname", help="New hostname")
@click.option("--ip", "primary_ip", help="Primary IP address")
@click.option("--type", "system_type", type=click.Choice([t.value for t in SystemType]),
              help="System type")
@click.option("--status", type=click.Choice([s.value for s in SystemStatus]),
              help="System status")
@click.option("--os", "os_name", help="Operating system")
@click.option("--vendor", help="Hardware vendor")
@click.option("--model", help="Hardware model")
@click.option("--serial", "serial_number", help="Serial number")
@click.option("--rack", help="Rack identifier")
@click.option("--rack-unit", type=int, help="Rack unit (U position)")
@click.option("--add-tag", multiple=True, help="Add tags")
@click.option("--remove-tag", multiple=True, help="Remove tags")
@click.option("--note", "notes", help="Notes")
def system_update(identifier: str, **kwargs):
    """Update a system in inventory.

    IDENTIFIER can be hostname, FQDN, or IP address.
    """
    db = get_db()

    sys = db.get_system_by_hostname(identifier)
    if sys is None:
        sys = db.get_system_by_ip(identifier)

    if sys is None:
        console.print(f"[red]System '{identifier}' not found[/red]")
        db.close()
        return

    # Apply updates
    if kwargs.get("hostname"):
        sys.hostname = kwargs["hostname"]
    if kwargs.get("primary_ip"):
        sys.primary_ip = kwargs["primary_ip"]
    if kwargs.get("system_type"):
        sys.system_type = SystemType(kwargs["system_type"])
    if kwargs.get("status"):
        sys.status = SystemStatus(kwargs["status"])
    if kwargs.get("os_name"):
        sys.os_name = kwargs["os_name"]
    if kwargs.get("vendor"):
        sys.vendor = kwargs["vendor"]
    if kwargs.get("model"):
        sys.model = kwargs["model"]
    if kwargs.get("serial_number"):
        sys.serial_number = kwargs["serial_number"]
    if kwargs.get("notes"):
        sys.notes = kwargs["notes"]

    # Handle tags
    for tag in kwargs.get("add_tag", []):
        if tag not in sys.tags:
            sys.tags.append(tag)
    for tag in kwargs.get("remove_tag", []):
        if tag in sys.tags:
            sys.tags.remove(tag)

    # Handle location updates
    if kwargs.get("rack") or kwargs.get("rack_unit"):
        if sys.location_id:
            loc = db.get_location(sys.location_id)
            if loc:
                if kwargs.get("rack"):
                    loc.rack = kwargs["rack"]
                if kwargs.get("rack_unit"):
                    loc.rack_unit = kwargs["rack_unit"]
                db.update_location(loc)
        else:
            loc = Location(
                rack=kwargs.get("rack"),
                rack_unit=kwargs.get("rack_unit"),
            )
            loc = db.create_location(loc)
            sys.location_id = loc.id

    sys.last_seen = datetime.now()
    db.update_system(sys)

    console.print(f"[green]System '{identifier}' updated[/green]")
    db.close()


@system.command("delete")
@click.argument("identifier")
@click.option("--force", "-f", is_flag=True, help="Skip confirmation")
def system_delete(identifier: str, force: bool):
    """Delete a system from inventory.

    IDENTIFIER can be hostname, FQDN, or IP address.
    """
    db = get_db()

    sys = db.get_system_by_hostname(identifier)
    if sys is None:
        sys = db.get_system_by_ip(identifier)

    if sys is None:
        console.print(f"[red]System '{identifier}' not found[/red]")
        db.close()
        return

    if not force:
        if not click.confirm(f"Delete system '{sys.hostname}' ({sys.primary_ip})?"):
            db.close()
            return

    db.delete_system(sys.id)
    console.print(f"[green]System '{identifier}' deleted[/green]")
    db.close()


@system.command("search")
@click.argument("query")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def system_search(query: str, json_output: bool):
    """Search systems by hostname, IP, or notes."""
    db = get_db()
    systems = db.search_systems(query)

    if json_output:
        output = [s.to_dict() for s in systems]
        console.print_json(json.dumps(output, default=str))
        db.close()
        return

    if not systems:
        console.print(f"[yellow]No systems matching '{query}'[/yellow]")
        db.close()
        return

    table = Table(show_header=True, title=f"Search Results: '{query}' ({len(systems)} found)")
    table.add_column("Hostname")
    table.add_column("IP Address")
    table.add_column("Type")
    table.add_column("Status")

    for sys in systems:
        table.add_row(
            sys.hostname or "-",
            sys.primary_ip or "-",
            sys.system_type.value,
            sys.status.value,
        )

    console.print(table)
    db.close()


# ============================================================================
# Switch CRUD commands
# ============================================================================

@click.group()
def switch():
    """Switch inventory management."""
    pass


@switch.command("list")
@click.option("--vendor", help="Filter by vendor")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def switch_list(vendor: str | None, json_output: bool):
    """List switches in inventory."""
    db = get_db()
    switches = db.list_switches(vendor=vendor)

    if json_output:
        output = [s.to_dict() for s in switches]
        console.print_json(json.dumps(output, default=str))
        db.close()
        return

    if not switches:
        console.print("[yellow]No switches found[/yellow]")
        db.close()
        return

    table = Table(show_header=True, title=f"Switches ({len(switches)})")
    table.add_column("Hostname")
    table.add_column("Management IP")
    table.add_column("Vendor")
    table.add_column("Model")
    table.add_column("Ports")
    table.add_column("Last Seen")

    for sw in switches:
        last_seen = sw.last_seen.strftime("%Y-%m-%d %H:%M") if sw.last_seen else "-"
        table.add_row(
            sw.hostname or "-",
            sw.management_ip or "-",
            sw.vendor or "-",
            sw.model or "-",
            str(sw.total_ports) if sw.total_ports else "-",
            last_seen,
        )

    console.print(table)
    db.close()


@switch.command("show")
@click.argument("identifier")
@click.option("--systems", is_flag=True, help="Show connected systems")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def switch_show(identifier: str, systems: bool, json_output: bool):
    """Show switch details.

    IDENTIFIER can be hostname or management IP.
    """
    db = get_db()

    sw = db.get_switch_by_hostname(identifier)
    if sw is None:
        sw = db.get_switch_by_ip(identifier)

    if sw is None:
        console.print(f"[red]Switch '{identifier}' not found[/red]")
        db.close()
        return

    # Get connected interfaces
    interfaces = db.get_interfaces_on_switch(sw.id) if sw.id else []

    if json_output:
        output = sw.to_dict()
        output["connected_interfaces"] = [i.to_dict() for i in interfaces]
        console.print_json(json.dumps(output, default=str))
        db.close()
        return

    # Display switch info
    panel = Panel(
        f"[bold]Hostname:[/bold] {sw.hostname or 'N/A'}\n"
        f"[bold]Management IP:[/bold] {sw.management_ip or 'N/A'}\n"
        f"[bold]Vendor:[/bold] {sw.vendor or 'N/A'}\n"
        f"[bold]Model:[/bold] {sw.model or 'N/A'}\n"
        f"[bold]Serial:[/bold] {sw.serial_number or 'N/A'}\n"
        f"[bold]Platform:[/bold] {sw.platform or 'N/A'}\n"
        f"[bold]Firmware:[/bold] {sw.firmware_version or 'N/A'}\n"
        f"[bold]Total Ports:[/bold] {sw.total_ports or 'N/A'}\n"
        f"[bold]Last Seen:[/bold] {sw.last_seen.strftime('%Y-%m-%d %H:%M') if sw.last_seen else 'N/A'}",
        title=f"Switch: {sw.hostname or sw.management_ip}",
    )
    console.print(panel)

    if sw.capabilities:
        console.print(f"\n[bold]Capabilities:[/bold] {', '.join(sw.capabilities)}")

    if systems and interfaces:
        console.print("\n[bold]Connected Systems:[/bold]")
        table = Table(show_header=True)
        table.add_column("Port")
        table.add_column("System")
        table.add_column("Interface")
        table.add_column("MAC Address")
        table.add_column("VLAN")

        for iface in interfaces:
            # Get system for this interface
            sys = db.get_system(iface.system_id) if iface.system_id else None
            table.add_row(
                iface.switch_port or "-",
                sys.hostname if sys else "-",
                iface.name or "-",
                iface.mac_address or "-",
                str(iface.vlan_id) if iface.vlan_id else "-",
            )

        console.print(table)

    db.close()


@switch.command("add")
@click.option("--hostname", required=True, help="Switch hostname")
@click.option("--ip", "management_ip", help="Management IP address")
@click.option("--vendor", help="Vendor (Cisco, Juniper, etc.)")
@click.option("--model", help="Model number")
@click.option("--serial", "serial_number", help="Serial number")
@click.option("--ports", "total_ports", type=int, help="Total port count")
@click.option("--datacenter", help="Datacenter name")
@click.option("--rack", help="Rack identifier")
@click.option("--note", "notes", help="Notes")
def switch_add(hostname: str, management_ip: str | None, vendor: str | None,
               model: str | None, serial_number: str | None, total_ports: int | None,
               datacenter: str | None, rack: str | None, notes: str | None):
    """Add a switch to inventory."""
    db = get_db()

    # Check if already exists
    existing = db.get_switch_by_hostname(hostname)
    if existing:
        console.print(f"[red]Switch '{hostname}' already exists[/red]")
        db.close()
        return

    # Create location if specified
    location_id = None
    if datacenter or rack:
        location = Location(datacenter=datacenter, rack=rack)
        location = db.create_location(location)
        location_id = location.id

    switch = Switch(
        hostname=hostname,
        management_ip=management_ip,
        vendor=vendor,
        model=model,
        serial_number=serial_number,
        total_ports=total_ports,
        location_id=location_id,
        notes=notes,
        last_seen=datetime.now(),
    )

    switch = db.create_switch(switch)
    console.print(f"[green]Switch '{hostname}' created with ID {switch.id}[/green]")
    db.close()


@switch.command("delete")
@click.argument("identifier")
@click.option("--force", "-f", is_flag=True, help="Skip confirmation")
def switch_delete(identifier: str, force: bool):
    """Delete a switch from inventory."""
    db = get_db()

    sw = db.get_switch_by_hostname(identifier)
    if sw is None:
        sw = db.get_switch_by_ip(identifier)

    if sw is None:
        console.print(f"[red]Switch '{identifier}' not found[/red]")
        db.close()
        return

    if not force:
        if not click.confirm(f"Delete switch '{sw.hostname}' ({sw.management_ip})?"):
            db.close()
            return

    db.delete_switch(sw.id)
    console.print(f"[green]Switch '{identifier}' deleted[/green]")
    db.close()


# ============================================================================
# Location commands
# ============================================================================

@click.group()
def location():
    """Location/datacenter management."""
    pass


@location.command("list")
@click.option("--datacenter", help="Filter by datacenter")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def location_list(datacenter: str | None, json_output: bool):
    """List locations in inventory."""
    db = get_db()
    locations = db.list_locations(datacenter=datacenter)

    if json_output:
        output = [loc.to_dict() for loc in locations]
        console.print_json(json.dumps(output, default=str))
        db.close()
        return

    if not locations:
        console.print("[yellow]No locations found[/yellow]")
        db.close()
        return

    table = Table(show_header=True, title=f"Locations ({len(locations)})")
    table.add_column("ID")
    table.add_column("Datacenter")
    table.add_column("Rack")
    table.add_column("City")
    table.add_column("Country")

    for loc in locations:
        table.add_row(
            str(loc.id),
            loc.datacenter or "-",
            loc.rack or "-",
            loc.city or "-",
            loc.country or "-",
        )

    console.print(table)
    db.close()


@location.command("add")
@click.option("--datacenter", required=True, help="Datacenter name")
@click.option("--rack", help="Rack identifier")
@click.option("--country", help="Country")
@click.option("--state", help="State/Province")
@click.option("--city", help="City")
@click.option("--address", help="Street address")
@click.option("--building", help="Building name")
@click.option("--floor", help="Floor")
@click.option("--room", help="Room")
def location_add(datacenter: str, rack: str | None, country: str | None,
                 state: str | None, city: str | None, address: str | None,
                 building: str | None, floor: str | None, room: str | None):
    """Add a location to inventory."""
    db = get_db()

    loc = Location(
        datacenter=datacenter,
        rack=rack,
        country=country,
        state=state,
        city=city,
        address=address,
        building=building,
        floor=floor,
        room=room,
    )

    loc = db.create_location(loc)
    console.print(f"[green]Location created with ID {loc.id}[/green]")
    db.close()


@location.command("rack")
@click.argument("rack_id")
@click.option("--datacenter", help="Datacenter name (if rack IDs not unique)")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def location_rack(rack_id: str, datacenter: str | None, json_output: bool):
    """Show systems in a rack."""
    db = get_db()
    systems = db.get_systems_in_rack(rack_id, datacenter=datacenter)

    if json_output:
        output = [s.to_dict() for s in systems]
        console.print_json(json.dumps(output, default=str))
        db.close()
        return

    if not systems:
        console.print(f"[yellow]No systems in rack '{rack_id}'[/yellow]")
        db.close()
        return

    # Build rack visualization
    tree = Tree(f"[bold]Rack: {rack_id}[/bold]")

    for sys in systems:
        unit = f"U{sys.location.rack_unit}" if sys.location and sys.location.rack_unit else "?"
        tree.add(f"[{unit}] {sys.hostname} ({sys.primary_ip}) - {sys.system_type.value}")

    console.print(tree)
    db.close()


# ============================================================================
# Database management
# ============================================================================

@click.group()
def db():
    """Database management commands."""
    pass


@db.command("init")
def db_init():
    """Initialize the database schema."""
    database = get_db()
    database.initialize()
    database.close()
    console.print("[green]Database initialized[/green]")


@db.command("stats")
def db_stats():
    """Show database statistics."""
    database = get_db()

    systems = database.list_systems()
    switches = database.list_switches()
    locations = database.list_locations()

    console.print(Panel(
        f"[bold]Systems:[/bold] {len(systems)}\n"
        f"[bold]Switches:[/bold] {len(switches)}\n"
        f"[bold]Locations:[/bold] {len(locations)}",
        title="Inventory Statistics",
    ))

    # Show by type
    type_counts = {}
    for sys in systems:
        t = sys.system_type.value
        type_counts[t] = type_counts.get(t, 0) + 1

    if type_counts:
        console.print("\n[bold]Systems by Type:[/bold]")
        for t, count in sorted(type_counts.items()):
            console.print(f"  {t}: {count}")

    database.close()


# ============================================================================
# Helper functions
# ============================================================================

def _display_system(system: System, show_switch: bool = False, show_network: bool = False):
    """Display system details."""
    # Basic info panel
    info_lines = [
        f"[bold]Hostname:[/bold] {system.hostname or 'N/A'}",
        f"[bold]FQDN:[/bold] {system.fqdn or 'N/A'}",
        f"[bold]Primary IP:[/bold] {system.primary_ip or 'N/A'}",
        f"[bold]Primary MAC:[/bold] {system.primary_mac or 'N/A'}",
        f"[bold]Type:[/bold] {system.system_type.value}",
        f"[bold]Status:[/bold] {system.status.value}",
    ]

    if system.os_name:
        info_lines.append(f"[bold]OS:[/bold] {system.os_name} {system.os_version or ''}")
    if system.vendor:
        info_lines.append(f"[bold]Vendor:[/bold] {system.vendor}")
    if system.model:
        info_lines.append(f"[bold]Model:[/bold] {system.model}")
    if system.serial_number:
        info_lines.append(f"[bold]Serial:[/bold] {system.serial_number}")

    console.print(Panel("\n".join(info_lines), title=f"System: {system.hostname or system.primary_ip}"))

    # Resources
    if system.cpu_cores or system.ram_gb or system.disk_gb:
        resources = []
        if system.cpu_cores:
            resources.append(f"CPU: {system.cpu_cores} cores")
        if system.ram_gb:
            resources.append(f"RAM: {system.ram_gb} GB")
        if system.disk_gb:
            resources.append(f"Disk: {system.disk_gb} GB")
        console.print(f"\n[bold]Resources:[/bold] {' | '.join(resources)}")

    # Location
    if system.location or system.ip_country:
        loc_parts = []
        if system.location:
            if system.location.datacenter:
                loc_parts.append(f"DC: {system.location.datacenter}")
            if system.location.rack:
                unit = f" U{system.location.rack_unit}" if system.location.rack_unit else ""
                loc_parts.append(f"Rack: {system.location.rack}{unit}")
        if system.ip_city and system.ip_country:
            loc_parts.append(f"GeoIP: {system.ip_city}, {system.ip_country}")
        if system.ip_org:
            loc_parts.append(f"Org: {system.ip_org}")

        if loc_parts:
            console.print(f"\n[bold]Location:[/bold] {' | '.join(loc_parts)}")

    # Network interfaces
    if show_network and system.interfaces:
        console.print("\n[bold]Network Interfaces:[/bold]")
        table = Table(show_header=True)
        table.add_column("Interface")
        table.add_column("MAC Address")
        table.add_column("IP Addresses")
        table.add_column("VLAN")
        table.add_column("Speed")
        table.add_column("Status")

        for iface in system.interfaces:
            status = "[green]UP[/green]" if iface.is_up else "[red]DOWN[/red]"
            if iface.is_primary:
                status += " [bold](primary)[/bold]"

            speed = f"{iface.speed_mbps} Mbps" if iface.speed_mbps else "-"

            table.add_row(
                iface.name or "-",
                iface.mac_address or "-",
                ", ".join(iface.ip_addresses) if iface.ip_addresses else "-",
                str(iface.vlan_id) if iface.vlan_id else "-",
                speed,
                status,
            )

        console.print(table)

    # Switch connectivity
    if show_switch and system.interfaces:
        has_switch_info = any(i.connected_switch for i in system.interfaces)
        if has_switch_info:
            console.print("\n[bold]Switch Connectivity:[/bold]")
            for iface in system.interfaces:
                if iface.connected_switch:
                    sw = iface.connected_switch
                    console.print(
                        f"  {iface.name} -> {sw.hostname or sw.management_ip} "
                        f"port {iface.switch_port or '?'}"
                    )

    # Tags
    if system.tags:
        console.print(f"\n[bold]Tags:[/bold] {', '.join(system.tags)}")

    # Notes
    if system.notes:
        console.print(f"\n[bold]Notes:[/bold] {system.notes}")

    # Discovery info
    if system.discovered_via or system.discovered_at:
        disc_parts = []
        if system.discovered_via:
            disc_parts.append(f"via {system.discovered_via}")
        if system.discovered_at:
            disc_parts.append(f"on {system.discovered_at.strftime('%Y-%m-%d %H:%M')}")
        console.print(f"\n[dim]Discovered {' '.join(disc_parts)}[/dim]")

    if system.last_seen:
        console.print(f"[dim]Last seen: {system.last_seen.strftime('%Y-%m-%d %H:%M')}[/dim]")
