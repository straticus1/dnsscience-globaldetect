"""
CLI commands for secrets management.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import os
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from globaldetect.backup.secrets.base import (
    BackendType,
    SecretEntry,
    SecretType,
    UserEntry,
    ARNLink,
    ResourceType,
)
from globaldetect.backup.secrets.config import SecretsConfig
from globaldetect.backup.secrets.manager import SecretsManager
from globaldetect.backup.secrets.mfa import TOTPGenerator, SSHKeyManager

console = Console()


def get_manager() -> SecretsManager:
    """Get configured secrets manager."""
    config = SecretsConfig.from_env()
    manager = SecretsManager(config)
    manager.initialize()
    return manager


@click.group()
@click.pass_context
def secrets(ctx: click.Context) -> None:
    """Secrets management commands.

    Manage credentials, users, ARNs, and resources with
    support for multiple backends (SQLite, PostgreSQL, Confidant).
    """
    ctx.ensure_object(dict)
    ctx.obj["console"] = console


# =============================================================================
# Secrets Commands
# =============================================================================

@secrets.group("secret")
def secret_group():
    """Manage secrets."""
    pass


@secret_group.command("add")
@click.option("--name", "-n", required=True, help="Secret name")
@click.option("--value", "-v", help="Secret value (prompts if not provided)")
@click.option("--type", "-t", "secret_type",
              type=click.Choice([t.value for t in SecretType]),
              default="generic", help="Secret type")
@click.option("--description", "-d", help="Description")
@click.option("--owner", "-o", help="Owner user ID")
@click.option("--tag", multiple=True, help="Tags (can specify multiple)")
@click.pass_context
def secret_add(
    ctx: click.Context,
    name: str,
    value: str | None,
    secret_type: str,
    description: str | None,
    owner: str | None,
    tag: tuple,
) -> None:
    """Add a new secret."""
    if not value:
        value = click.prompt("Secret value", hide_input=True)

    manager = get_manager()

    secret = SecretEntry(
        name=name,
        secret_value=value,
        secret_type=SecretType(secret_type),
        description=description,
        owner_user_id=owner,
        tags=list(tag),
    )

    try:
        secret_id = manager.create_secret(secret)
        console.print(f"[green]Secret created with ID: {secret_id}[/green]")
    finally:
        manager.close()


@secret_group.command("get")
@click.argument("name_or_id")
@click.option("--show-value", is_flag=True, help="Show secret value")
@click.pass_context
def secret_get(ctx: click.Context, name_or_id: str, show_value: bool) -> None:
    """Get a secret by name or ID."""
    manager = get_manager()

    try:
        secret = manager.get_secret(name_or_id)
        if not secret:
            secret = manager.get_secret_by_name(name_or_id)

        if not secret:
            console.print(f"[red]Secret not found: {name_or_id}[/red]")
            return

        data = secret.to_dict(include_secret=show_value)

        table = Table(title=f"Secret: {secret.name}")
        table.add_column("Field", style="cyan")
        table.add_column("Value")

        for key, value in data.items():
            if key == "secret_value" and not show_value:
                value = "***hidden***"
            table.add_row(key, str(value) if value is not None else "")

        console.print(table)
    finally:
        manager.close()


@secret_group.command("list")
@click.option("--type", "-t", "secret_type",
              type=click.Choice([t.value for t in SecretType]),
              help="Filter by type")
@click.option("--owner", "-o", help="Filter by owner")
@click.pass_context
def secret_list(ctx: click.Context, secret_type: str | None, owner: str | None) -> None:
    """List all secrets."""
    manager = get_manager()

    try:
        type_enum = SecretType(secret_type) if secret_type else None
        secrets_list = list(manager.list_secrets(secret_type=type_enum, owner_user_id=owner))

        if not secrets_list:
            console.print("[yellow]No secrets found[/yellow]")
            return

        table = Table(title="Secrets")
        table.add_column("ID", style="cyan")
        table.add_column("Name", style="green")
        table.add_column("Type")
        table.add_column("Enabled")
        table.add_column("Owner")

        for s in secrets_list:
            table.add_row(
                s.id or "",
                s.name or "",
                s.secret_type.value,
                "Yes" if s.enabled else "No",
                s.owner_user_id or "",
            )

        console.print(table)
    finally:
        manager.close()


@secret_group.command("delete")
@click.argument("secret_id")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation")
@click.pass_context
def secret_delete(ctx: click.Context, secret_id: str, yes: bool) -> None:
    """Delete a secret."""
    if not yes:
        if not click.confirm(f"Delete secret {secret_id}?"):
            return

    manager = get_manager()
    try:
        if manager.delete_secret(secret_id):
            console.print(f"[green]Secret {secret_id} deleted[/green]")
        else:
            console.print(f"[red]Secret {secret_id} not found[/red]")
    finally:
        manager.close()


# =============================================================================
# User Commands
# =============================================================================

@secrets.group("user")
def user_group():
    """Manage users."""
    pass


@user_group.command("add")
@click.option("--username", "-u", required=True, help="Username")
@click.option("--email", "-e", help="Email address")
@click.option("--full-name", "-n", help="Full name")
@click.option("--uid", type=int, help="Unix UID")
@click.option("--gid", type=int, help="Unix GID")
@click.option("--shell", default="/bin/bash", help="Login shell")
@click.option("--home", help="Home directory")
@click.option("--group", "-g", multiple=True, help="Groups (can specify multiple)")
@click.option("--password", "-p", help="Password (prompts if not provided)")
@click.option("--admin", is_flag=True, help="Make user an admin")
@click.pass_context
def user_add(
    ctx: click.Context,
    username: str,
    email: str | None,
    full_name: str | None,
    uid: int | None,
    gid: int | None,
    shell: str,
    home: str | None,
    group: tuple,
    password: str | None,
    admin: bool,
) -> None:
    """Add a new user."""
    manager = get_manager()

    try:
        # Hash password if provided
        password_hash = None
        if password:
            password_hash = manager.hash_password(password)
        elif click.confirm("Set password now?"):
            password = click.prompt("Password", hide_input=True, confirmation_prompt=True)
            password_hash = manager.hash_password(password)

        user = UserEntry(
            username=username,
            email=email,
            full_name=full_name,
            uid=uid,
            gid=gid or uid,
            shell=shell,
            home_directory=home or f"/home/{username}",
            groups=list(group),
            primary_group=group[0] if group else username,
            password_hash=password_hash,
            is_admin=admin,
        )

        user_id = manager.create_user(user)
        console.print(f"[green]User created with ID: {user_id}[/green]")
    finally:
        manager.close()


@user_group.command("list")
@click.option("--group", "-g", help="Filter by group")
@click.option("--enabled/--disabled", default=None, help="Filter by status")
@click.pass_context
def user_list(ctx: click.Context, group: str | None, enabled: bool | None) -> None:
    """List all users."""
    manager = get_manager()

    try:
        users = list(manager.list_users(group=group, enabled=enabled))

        if not users:
            console.print("[yellow]No users found[/yellow]")
            return

        table = Table(title="Users")
        table.add_column("ID", style="cyan")
        table.add_column("Username", style="green")
        table.add_column("UID")
        table.add_column("Groups")
        table.add_column("Enabled")
        table.add_column("Admin")

        for u in users:
            table.add_row(
                u.id or "",
                u.username or "",
                str(u.uid) if u.uid else "",
                ", ".join(u.groups[:3]) + ("..." if len(u.groups) > 3 else ""),
                "Yes" if u.enabled else "No",
                "Yes" if u.is_admin else "No",
            )

        console.print(table)
    finally:
        manager.close()


@user_group.command("set-password")
@click.argument("username")
@click.option("--password", "-p", help="New password")
@click.pass_context
def user_set_password(ctx: click.Context, username: str, password: str | None) -> None:
    """Set user password."""
    if not password:
        password = click.prompt("New password", hide_input=True, confirmation_prompt=True)

    manager = get_manager()
    try:
        if manager.set_user_password(username=username, password=password):
            console.print(f"[green]Password updated for {username}[/green]")
        else:
            console.print(f"[red]User not found: {username}[/red]")
    finally:
        manager.close()


@user_group.command("add-ssh-key")
@click.argument("username")
@click.option("--key", "-k", help="SSH public key")
@click.option("--key-file", "-f", type=click.Path(exists=True), help="SSH public key file")
@click.option("--generate", "-g", is_flag=True, help="Generate new keypair")
@click.option("--key-type", type=click.Choice(["ed25519", "rsa", "ecdsa"]),
              default="ed25519", help="Key type for generation")
@click.pass_context
def user_add_ssh_key(
    ctx: click.Context,
    username: str,
    key: str | None,
    key_file: str | None,
    generate: bool,
    key_type: str,
) -> None:
    """Add SSH key to user."""
    manager = get_manager()

    try:
        user = manager.get_user_by_username(username)
        if not user:
            console.print(f"[red]User not found: {username}[/red]")
            return

        if generate:
            # Generate new keypair
            private_key, public_key = SSHKeyManager.generate_keypair(
                key_type=key_type,
                comment=f"{username}@globaldetect"
            )
            console.print(Panel(private_key, title="Private Key (save securely!)"))
            key = public_key

        elif key_file:
            key = Path(key_file).read_text().strip()

        elif not key:
            key = click.prompt("SSH public key")

        user.ssh_public_keys.append(key)

        if manager.update_user(user):
            fingerprint = SSHKeyManager.get_fingerprint(key)
            console.print(f"[green]SSH key added: {fingerprint}[/green]")
        else:
            console.print("[red]Failed to update user[/red]")

    finally:
        manager.close()


@user_group.command("link-arn")
@click.argument("username")
@click.argument("arn")
@click.pass_context
def user_link_arn(ctx: click.Context, username: str, arn: str) -> None:
    """Link user to AWS ARN."""
    manager = get_manager()

    try:
        user = manager.get_user_by_username(username)
        if not user:
            console.print(f"[red]User not found: {username}[/red]")
            return

        # Create ARN link if it doesn't exist
        existing = manager.get_arn_link_by_arn(arn)
        if not existing:
            from globaldetect.backup.secrets.base import ARNLink
            arn_link = ARNLink(arn=arn, name=f"Link for {username}")
            manager.create_arn_link(arn_link)

        if manager.link_user_to_arn(user.id, arn):
            console.print(f"[green]Linked {username} to {arn}[/green]")
        else:
            console.print("[red]Failed to create link[/red]")

    finally:
        manager.close()


# =============================================================================
# MFA Commands
# =============================================================================

@secrets.group("mfa")
def mfa_group():
    """Manage multi-factor authentication."""
    pass


@mfa_group.command("setup-totp")
@click.argument("username")
@click.option("--issuer", default="GlobalDetect", help="Issuer name")
@click.pass_context
def mfa_setup_totp(ctx: click.Context, username: str, issuer: str) -> None:
    """Set up TOTP for a user."""
    manager = get_manager()

    try:
        user = manager.get_user_by_username(username)
        if not user:
            console.print(f"[red]User not found: {username}[/red]")
            return

        # Generate TOTP secret
        secret = TOTPGenerator.generate_secret()
        uri = TOTPGenerator.get_provisioning_uri(secret, username, issuer)

        console.print(Panel(
            f"Secret: {secret}\n\n"
            f"Provisioning URI:\n{uri}\n\n"
            "Scan the QR code or enter the secret in your authenticator app.",
            title="TOTP Setup"
        ))

        # Verify setup
        if click.confirm("Verify TOTP setup?"):
            code = click.prompt("Enter current code")
            if TOTPGenerator.verify_code(secret, code):
                console.print("[green]TOTP verified successfully![/green]")
                # Store secret in user's MFA config
                # (would need to add to user model)
            else:
                console.print("[red]Invalid code. Please try again.[/red]")

    finally:
        manager.close()


@mfa_group.command("verify-totp")
@click.argument("secret")
@click.argument("code")
def mfa_verify_totp(secret: str, code: str) -> None:
    """Verify a TOTP code."""
    if TOTPGenerator.verify_code(secret, code):
        console.print("[green]Code is valid![/green]")
    else:
        console.print("[red]Code is invalid![/red]")


# =============================================================================
# Password File Generation
# =============================================================================

@secrets.group("passwd")
def passwd_group():
    """Generate Unix password files."""
    pass


@passwd_group.command("generate")
@click.option("--output", "-o", type=click.Path(), help="Output directory")
@click.option("--group", "-g", help="Filter by group")
@click.option("--format", "-f", "fmt",
              type=click.Choice(["passwd", "shadow", "group", "all"]),
              default="all", help="File format")
@click.pass_context
def passwd_generate(
    ctx: click.Context,
    output: str | None,
    group: str | None,
    fmt: str,
) -> None:
    """Generate passwd/shadow/group files."""
    manager = get_manager()

    try:
        output_dir = Path(output) if output else Path.cwd()
        output_dir.mkdir(parents=True, exist_ok=True)

        files_written = []

        if fmt in ("passwd", "all"):
            content = manager.generate_passwd_file(group=group)
            path = output_dir / "passwd"
            path.write_text(content)
            os.chmod(path, 0o644)
            files_written.append(str(path))

        if fmt in ("shadow", "all"):
            content = manager.generate_shadow_file(group=group)
            path = output_dir / "shadow"
            path.write_text(content)
            os.chmod(path, 0o600)
            files_written.append(str(path))

        if fmt in ("group", "all"):
            content = manager.generate_group_file()
            path = output_dir / "group"
            path.write_text(content)
            os.chmod(path, 0o644)
            files_written.append(str(path))

        for f in files_written:
            console.print(f"[green]Generated: {f}[/green]")

    finally:
        manager.close()


@passwd_group.command("export-keys")
@click.option("--output", "-o", type=click.Path(), required=True, help="Output directory")
@click.option("--group", "-g", help="Filter by group")
@click.pass_context
def passwd_export_keys(ctx: click.Context, output: str, group: str | None) -> None:
    """Export authorized_keys files for all users."""
    manager = get_manager()

    try:
        count = manager.export_all_authorized_keys(output, group=group)
        console.print(f"[green]Exported authorized_keys for {count} users[/green]")
    finally:
        manager.close()


# =============================================================================
# Backend Configuration
# =============================================================================

@secrets.command("config")
@click.option("--show", is_flag=True, help="Show current configuration")
@click.pass_context
def secrets_config(ctx: click.Context, show: bool) -> None:
    """Show or manage secrets backend configuration."""
    config = SecretsConfig.from_env()

    if show:
        data = config.to_dict()

        table = Table(title="Secrets Backend Configuration")
        table.add_column("Setting", style="cyan")
        table.add_column("Value")

        for key, value in data.items():
            table.add_row(key, str(value) if value is not None else "")

        console.print(table)

        # Show validation
        errors = config.validate()
        if errors:
            console.print("\n[red]Configuration Errors:[/red]")
            for err in errors:
                console.print(f"  - {err}")
    else:
        console.print("Use --show to display current configuration")
        console.print("\nSet configuration via environment variables:")
        console.print("  GLOBALDETECT_SECRETS_BACKEND=sqlite|postgresql|confidant")
        console.print("  GLOBALDETECT_CONFIDANT_ENABLED=true")
        console.print("  GLOBALDETECT_CONFIDANT_URL=https://confidant.example.com")


def add_secrets_commands(main_cli):
    """Add secrets commands to main CLI."""
    main_cli.add_command(secrets)
