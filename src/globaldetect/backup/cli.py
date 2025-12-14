"""
CLI commands for device configuration backup.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import asyncio
import os
from pathlib import Path
from datetime import datetime

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from globaldetect.backup.models import (
    DeviceVendor,
    DeviceType,
    BackupType,
    CompressionType,
    DeviceCredential,
    DeviceLocation,
    ConnectionMethod,
)
from globaldetect.backup.storage import BackupStorage
from globaldetect.backup.credentials import CredentialVault
from globaldetect.backup.collectors import get_collector_class, COLLECTOR_MAP

console = Console()


def get_default_storage_path() -> Path:
    """Get default backup storage path."""
    return Path.home() / ".globaldetect" / "backups"


def get_default_vault_path() -> Path:
    """Get default credential vault path."""
    return Path.home() / ".globaldetect" / "vault"


@click.group()
@click.pass_context
def backup(ctx: click.Context) -> None:
    """Device configuration backup commands.

    Backup configurations from network devices, DNS appliances, and proxies.
    """
    ctx.ensure_object(dict)
    ctx.obj["console"] = console


# =============================================================================
# Device Backup Commands
# =============================================================================

@backup.command("run")
@click.argument("host")
@click.option("--vendor", "-v", type=click.Choice([v.value for v in DeviceVendor if v != DeviceVendor.UNKNOWN]),
              required=True, help="Device vendor/platform")
@click.option("--type", "-t", "backup_types", multiple=True,
              type=click.Choice([t.value for t in BackupType]),
              default=["full"], help="Backup type(s) to perform")
@click.option("--compression", "-c", type=click.Choice([c.value for c in CompressionType]),
              default="gzip", help="Compression type")
@click.option("--credential-id", "-C", help="Credential ID from vault")
@click.option("--username", "-u", help="Username (if not using vault)")
@click.option("--password", "-p", help="Password (if not using vault)", hide_input=True)
@click.option("--api-key", "-k", help="API key (for API-based devices)")
@click.option("--enable-password", help="Enable/privilege password")
@click.option("--region", help="Region for storage hierarchy")
@click.option("--site", help="Site for storage hierarchy")
@click.option("--building", help="Building for storage hierarchy")
@click.option("--floor", help="Floor for storage hierarchy")
@click.option("--rack", help="Rack for storage hierarchy")
@click.option("--position", help="Rack position for storage hierarchy")
@click.option("--storage-path", type=click.Path(), help="Custom backup storage path")
@click.option("--port", type=int, help="Custom port number")
@click.pass_context
def backup_run(
    ctx: click.Context,
    host: str,
    vendor: str,
    backup_types: tuple,
    compression: str,
    credential_id: str | None,
    username: str | None,
    password: str | None,
    api_key: str | None,
    enable_password: str | None,
    region: str | None,
    site: str | None,
    building: str | None,
    floor: str | None,
    rack: str | None,
    position: str | None,
    storage_path: str | None,
    port: int | None,
) -> None:
    """Backup configuration from a device.

    HOST is the hostname or IP address of the device.
    """
    vendor_enum = DeviceVendor(vendor)
    collector_class = get_collector_class(vendor_enum)

    if not collector_class:
        console.print(f"[red]No collector available for vendor: {vendor}[/red]")
        raise SystemExit(1)

    # Build credential
    credential = None
    if credential_id:
        vault_path = get_default_vault_path()
        vault_password = os.environ.get("GLOBALDETECT_VAULT_PASSWORD")
        if not vault_password:
            vault_password = click.prompt("Vault password", hide_input=True)

        vault = CredentialVault(vault_path, vault_password)
        vault.initialize()
        credential = vault.get_credential(credential_id)
        if not credential:
            console.print(f"[red]Credential not found: {credential_id}[/red]")
            raise SystemExit(1)
    else:
        if not username:
            username = click.prompt("Username")
        if not password and not api_key:
            password = click.prompt("Password", hide_input=True)

        credential = DeviceCredential(
            device_hostname=host,
            device_ip=host,
            device_vendor=vendor_enum,
            username=username,
            password=password,
            api_key=api_key,
            api_token=api_key,
            enable_password=enable_password,
            port=port,
        )

    # Build location
    location = None
    if any([region, site, building, floor, rack, position]):
        location = DeviceLocation(
            region=region,
            site=site,
            building=building,
            floor=floor,
            rack=rack,
            position=position,
        )

    # Initialize storage
    storage_dir = Path(storage_path) if storage_path else get_default_storage_path()
    storage = BackupStorage(storage_dir)
    storage.initialize()

    # Create collector and run backup
    collector = collector_class(credential, storage, location=location)

    backup_type_enums = [BackupType(t) for t in backup_types]
    compression_enum = CompressionType(compression)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task(f"Backing up {host}...", total=None)

        result = asyncio.run(collector.backup(backup_type_enums, compression_enum))

        progress.update(task, completed=True)

    # Display results
    if result.status.value == "success":
        console.print(Panel(
            f"[green]Backup successful![/green]\n\n"
            f"Device: {result.device_hostname}\n"
            f"Files: {len(result.output_files)}\n"
            f"Size: {result.total_size_bytes:,} bytes\n"
            f"Duration: {result.duration_seconds:.1f}s",
            title="Backup Complete"
        ))
        for f in result.output_files:
            console.print(f"  [dim]{f}[/dim]")
    elif result.status.value == "partial":
        console.print(Panel(
            f"[yellow]Backup partially successful[/yellow]\n\n"
            f"Successful: {[t.value for t in result.successful_types]}\n"
            f"Failed: {[t.value for t in result.failed_types]}",
            title="Partial Backup"
        ))
    else:
        console.print(Panel(
            f"[red]Backup failed![/red]\n\n"
            f"Error: {result.error_message}",
            title="Backup Failed"
        ))
        raise SystemExit(1)


@backup.command("list")
@click.option("--host", "-h", help="Filter by hostname")
@click.option("--type", "-t", "backup_type", type=click.Choice([t.value for t in BackupType]),
              help="Filter by backup type")
@click.option("--since", type=click.DateTime(), help="Show backups since date")
@click.option("--storage-path", type=click.Path(), help="Custom backup storage path")
@click.pass_context
def backup_list(
    ctx: click.Context,
    host: str | None,
    backup_type: str | None,
    since: datetime | None,
    storage_path: str | None,
) -> None:
    """List available backups."""
    storage_dir = Path(storage_path) if storage_path else get_default_storage_path()
    storage = BackupStorage(storage_dir)

    backup_type_enum = BackupType(backup_type) if backup_type else None

    backups = list(storage.list_backups(
        hostname=host,
        backup_type=backup_type_enum,
        since=since,
    ))

    if not backups:
        console.print("[yellow]No backups found[/yellow]")
        return

    table = Table(title="Available Backups")
    table.add_column("Hostname", style="cyan")
    table.add_column("Type", style="green")
    table.add_column("Timestamp", style="yellow")
    table.add_column("Size", justify="right")
    table.add_column("Compression")

    for backup in sorted(backups, key=lambda x: x.get("timestamp", ""), reverse=True):
        table.add_row(
            backup.get("hostname", "unknown"),
            backup.get("backup_type", "unknown"),
            backup.get("timestamp", "")[:19],
            f"{backup.get('compressed_size', 0):,}",
            backup.get("compression", "none"),
        )

    console.print(table)


@backup.command("diff")
@click.argument("host")
@click.option("--type", "-t", "backup_type", type=click.Choice([t.value for t in BackupType]),
              default="full", help="Backup type to diff")
@click.option("--storage-path", type=click.Path(), help="Custom backup storage path")
@click.pass_context
def backup_diff(
    ctx: click.Context,
    host: str,
    backup_type: str,
    storage_path: str | None,
) -> None:
    """Show changes between last two backups for a device."""
    storage_dir = Path(storage_path) if storage_path else get_default_storage_path()
    storage = BackupStorage(storage_dir)

    diff = storage.diff_configs(host, BackupType(backup_type))

    if diff:
        console.print(Panel(diff, title=f"Config Changes: {host}"))
    else:
        console.print("[yellow]No previous backup to compare (need at least 2 backups)[/yellow]")


@backup.command("restore")
@click.argument("backup_path", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.pass_context
def backup_restore(
    ctx: click.Context,
    backup_path: str,
    output: str | None,
) -> None:
    """Extract and display a backup file."""
    storage = BackupStorage(get_default_storage_path())
    content = storage.load_backup(Path(backup_path))

    if output:
        Path(output).write_bytes(content)
        console.print(f"[green]Backup extracted to: {output}[/green]")
    else:
        console.print(content.decode('utf-8', errors='replace'))


@backup.command("stats")
@click.option("--storage-path", type=click.Path(), help="Custom backup storage path")
@click.pass_context
def backup_stats(ctx: click.Context, storage_path: str | None) -> None:
    """Show backup storage statistics."""
    storage_dir = Path(storage_path) if storage_path else get_default_storage_path()
    storage = BackupStorage(storage_dir)

    stats = storage.get_storage_stats()

    console.print(Panel(
        f"Total Backups: {stats['total_backups']}\n"
        f"Total Size: {stats['total_size_human']}\n"
        f"Unique Devices: {stats['unique_devices']}\n"
        f"Regions: {stats['regions']}",
        title="Backup Storage Statistics"
    ))


@backup.command("cleanup")
@click.argument("host")
@click.option("--days", "-d", type=int, help="Remove backups older than N days")
@click.option("--keep", "-k", type=int, help="Keep only N most recent backups")
@click.option("--dry-run", is_flag=True, help="Show what would be removed")
@click.option("--storage-path", type=click.Path(), help="Custom backup storage path")
@click.pass_context
def backup_cleanup(
    ctx: click.Context,
    host: str,
    days: int | None,
    keep: int | None,
    dry_run: bool,
    storage_path: str | None,
) -> None:
    """Remove old backups based on retention policy."""
    if not days and not keep:
        console.print("[red]Specify --days or --keep[/red]")
        raise SystemExit(1)

    storage_dir = Path(storage_path) if storage_path else get_default_storage_path()
    storage = BackupStorage(storage_dir)

    if dry_run:
        console.print("[yellow]Dry run - no files will be removed[/yellow]")
        # List what would be removed
        backups = list(storage.list_backups(hostname=host))
        # ... implement dry run logic
        return

    removed = storage.cleanup_old_backups(
        hostname=host,
        retention_days=days,
        retention_count=keep,
    )

    console.print(f"[green]Removed {removed} old backup(s)[/green]")


# =============================================================================
# Credential Management Commands
# =============================================================================

@backup.group("creds")
@click.pass_context
def creds(ctx: click.Context) -> None:
    """Manage device credentials."""
    pass


@creds.command("add")
@click.option("--name", "-n", required=True, help="Credential name")
@click.option("--host", "-h", required=True, help="Device hostname")
@click.option("--ip", help="Device IP address")
@click.option("--vendor", "-v", type=click.Choice([v.value for v in DeviceVendor if v != DeviceVendor.UNKNOWN]),
              required=True, help="Device vendor")
@click.option("--username", "-u", required=True, help="Username")
@click.option("--password", "-p", help="Password", hide_input=True)
@click.option("--api-key", "-k", help="API key")
@click.option("--ssh-key", type=click.Path(exists=True), help="Path to SSH private key")
@click.option("--enable-password", help="Enable/privilege password")
@click.option("--method", "-m", type=click.Choice([m.value for m in ConnectionMethod]),
              default="ssh", help="Connection method")
@click.option("--port", type=int, help="Custom port number")
@click.option("--vault-path", type=click.Path(), help="Custom vault path")
@click.pass_context
def creds_add(
    ctx: click.Context,
    name: str,
    host: str,
    ip: str | None,
    vendor: str,
    username: str,
    password: str | None,
    api_key: str | None,
    ssh_key: str | None,
    enable_password: str | None,
    method: str,
    port: int | None,
    vault_path: str | None,
) -> None:
    """Add a new credential to the vault."""
    vault_dir = Path(vault_path) if vault_path else get_default_vault_path()
    vault_password = os.environ.get("GLOBALDETECT_VAULT_PASSWORD")
    if not vault_password:
        vault_password = click.prompt("Vault password", hide_input=True)

    vault = CredentialVault(vault_dir, vault_password)
    vault.initialize()

    # Prompt for password if not provided
    if not password and not api_key:
        password = click.prompt("Device password", hide_input=True, default="")

    # Read SSH key content if provided
    ssh_key_content = None
    if ssh_key:
        ssh_key_content = Path(ssh_key).read_text()

    credential = DeviceCredential(
        name=name,
        device_hostname=host,
        device_ip=ip or host,
        device_vendor=DeviceVendor(vendor),
        connection_method=ConnectionMethod(method),
        username=username,
        password=password,
        api_key=api_key,
        api_token=api_key,
        ssh_key=ssh_key_content,
        enable_password=enable_password,
        port=port,
    )

    cred_id = vault.add_credential(credential)
    console.print(f"[green]Credential added with ID: {cred_id}[/green]")


@creds.command("list")
@click.option("--vendor", "-v", type=click.Choice([v.value for v in DeviceVendor if v != DeviceVendor.UNKNOWN]),
              help="Filter by vendor")
@click.option("--vault-path", type=click.Path(), help="Custom vault path")
@click.pass_context
def creds_list(
    ctx: click.Context,
    vendor: str | None,
    vault_path: str | None,
) -> None:
    """List stored credentials."""
    vault_dir = Path(vault_path) if vault_path else get_default_vault_path()
    vault_password = os.environ.get("GLOBALDETECT_VAULT_PASSWORD")
    if not vault_password:
        vault_password = click.prompt("Vault password", hide_input=True)

    vault = CredentialVault(vault_dir, vault_password)
    vault.initialize()

    vendor_enum = DeviceVendor(vendor) if vendor else None
    creds = list(vault.list_credentials(vendor=vendor_enum))

    if not creds:
        console.print("[yellow]No credentials found[/yellow]")
        return

    table = Table(title="Stored Credentials")
    table.add_column("ID", style="cyan")
    table.add_column("Name", style="green")
    table.add_column("Host")
    table.add_column("Vendor")
    table.add_column("Username")
    table.add_column("Method")

    for cred in creds:
        table.add_row(
            cred.id or "",
            cred.name or "",
            cred.device_hostname or "",
            cred.device_vendor.value,
            cred.username or "",
            cred.connection_method.value,
        )

    console.print(table)


@creds.command("delete")
@click.argument("credential_id")
@click.option("--vault-path", type=click.Path(), help="Custom vault path")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation")
@click.pass_context
def creds_delete(
    ctx: click.Context,
    credential_id: str,
    vault_path: str | None,
    yes: bool,
) -> None:
    """Delete a credential from the vault."""
    if not yes:
        if not click.confirm(f"Delete credential {credential_id}?"):
            return

    vault_dir = Path(vault_path) if vault_path else get_default_vault_path()
    vault_password = os.environ.get("GLOBALDETECT_VAULT_PASSWORD")
    if not vault_password:
        vault_password = click.prompt("Vault password", hide_input=True)

    vault = CredentialVault(vault_dir, vault_password)
    vault.initialize()

    if vault.delete_credential(credential_id):
        console.print(f"[green]Credential {credential_id} deleted[/green]")
    else:
        console.print(f"[red]Credential {credential_id} not found[/red]")


# =============================================================================
# Supported Vendors Command
# =============================================================================

@backup.command("vendors")
@click.pass_context
def backup_vendors(ctx: click.Context) -> None:
    """List supported device vendors."""
    table = Table(title="Supported Device Vendors")
    table.add_column("Vendor", style="cyan")
    table.add_column("Type", style="green")
    table.add_column("Backup Types")

    vendor_info = {
        DeviceVendor.CISCO_IOS: ("Router/Switch", "full, network, firewall, vpn, users"),
        DeviceVendor.CISCO_IOS_XE: ("Router/Switch", "full, network, firewall, vpn, users"),
        DeviceVendor.CISCO_NXOS: ("Nexus Switch", "full, network, firewall, vpn, users"),
        DeviceVendor.CISCO_ASA: ("Firewall", "full, network, firewall, nat, vpn, ssl, users"),
        DeviceVendor.PALO_ALTO: ("Firewall", "full, network, firewall, nat, vpn, ssl, users"),
        DeviceVendor.JUNIPER_JUNOS: ("Router/Switch/Firewall", "full, network, firewall, nat, vpn, ssl, users"),
        DeviceVendor.JUNIPER_SCREENOS: ("Firewall (Legacy)", "full, network, firewall, nat, vpn, users"),
        DeviceVendor.FORTINET: ("Firewall", "full, network, firewall, nat, vpn, ssl, users, dhcp, dns"),
        DeviceVendor.IPTABLES: ("Linux Firewall", "full, firewall, nat, network"),
        DeviceVendor.NFTABLES: ("Linux Firewall", "full, firewall, nat, network"),
        DeviceVendor.PF_BSD: ("BSD Firewall", "full, firewall, nat, network"),
        DeviceVendor.INFOBLOX: ("DNS/DHCP/IPAM", "full, dns, dhcp, network, users"),
        DeviceVendor.BLUECAT: ("DNS/DHCP/IPAM", "full, dns, dhcp, network, users"),
        DeviceVendor.MEN_AND_MICE: ("DNS/DHCP/IPAM", "full, dns, dhcp, network, users"),
        DeviceVendor.BLUECOAT: ("Proxy", "full, network, ssl, users, dns"),
    }

    for vendor, collector in COLLECTOR_MAP.items():
        info = vendor_info.get(vendor, ("Unknown", "full"))
        table.add_row(vendor.value, info[0], info[1])

    console.print(table)


# Export the main group
def add_backup_commands(main_cli):
    """Add backup commands to main CLI."""
    main_cli.add_command(backup)
