"""
CLI commands for Have I Been Pwned integration.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import asyncio
import os
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.text import Text
from rich.markdown import Markdown

from globaldetect.hibp.client import HIBPClient
from globaldetect.hibp.models import RiskLevel

console = Console()


def get_api_key() -> str | None:
    """Get HIBP API key from environment or config."""
    return os.environ.get("HIBP_API_KEY")


def risk_color(risk: RiskLevel) -> str:
    """Get color for risk level."""
    colors = {
        RiskLevel.SAFE: "green",
        RiskLevel.LOW: "yellow",
        RiskLevel.MEDIUM: "orange3",
        RiskLevel.HIGH: "red",
        RiskLevel.CRITICAL: "bold red",
    }
    return colors.get(risk, "white")


@click.group()
@click.pass_context
def hibp(ctx: click.Context) -> None:
    """Have I Been Pwned - breach checking commands.

    Check email addresses and passwords against known data breaches.
    Uses the HIBP API (https://haveibeenpwned.com).

    For email lookups, set HIBP_API_KEY environment variable.
    Password checks use k-anonymity and don't require an API key.
    """
    ctx.ensure_object(dict)
    ctx.obj["console"] = console


# =============================================================================
# Email Breach Checking
# =============================================================================

@hibp.command("email")
@click.argument("email")
@click.option("--api-key", "-k", envvar="HIBP_API_KEY", help="HIBP API key")
@click.option("--brief", "-b", is_flag=True, help="Show brief output")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
@click.pass_context
def check_email(
    ctx: click.Context,
    email: str,
    api_key: str | None,
    brief: bool,
    json_output: bool,
) -> None:
    """Check if an email has been in any data breaches.

    Requires HIBP API key (set HIBP_API_KEY or use --api-key).

    Example:
        globaldetect hibp email user@example.com
    """
    if not api_key:
        console.print("[red]HIBP API key required. Set HIBP_API_KEY or use --api-key[/red]")
        console.print("Get a key at: https://haveibeenpwned.com/API/Key")
        raise SystemExit(1)

    async def _check():
        async with HIBPClient(api_key=api_key) as client:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
                transient=True,
            ) as progress:
                progress.add_task(f"Checking {email}...", total=None)
                return await client.check_email(email)

    result = asyncio.run(_check())

    if result.error:
        console.print(f"[red]Error: {result.error}[/red]")
        raise SystemExit(1)

    if json_output:
        import json
        console.print(json.dumps(result.to_dict(), indent=2, default=str))
        return

    if not result.is_breached:
        console.print(Panel(
            f"[green]Good news![/green] No breaches found for [cyan]{email}[/cyan]",
            title="Breach Check Result"
        ))
        return

    # Show breach summary
    if brief:
        console.print(f"[red]Found in {result.breach_count} breach(es)[/red]")
        for breach in result.breaches:
            console.print(f"  - {breach.title} ({breach.breach_date.strftime('%Y-%m-%d') if breach.breach_date else 'unknown date'})")
        return

    # Detailed output
    console.print(Panel(
        f"[red]Oh no![/red] [cyan]{email}[/cyan] found in [bold red]{result.breach_count}[/bold red] breach(es)\n\n"
        f"Total compromised accounts across breaches: [yellow]{result.total_pwn_count:,}[/yellow]\n"
        f"Verified breaches: {len(result.verified_breaches)}\n"
        f"Sensitive breaches: {len(result.sensitive_breaches)}",
        title="Breach Check Result"
    ))

    # Data types compromised
    if result.compromised_data_types:
        console.print("\n[bold]Compromised Data Types:[/bold]")
        console.print(", ".join(sorted(result.compromised_data_types)))

    # Breach details table
    table = Table(title="\nBreach Details")
    table.add_column("Breach", style="cyan")
    table.add_column("Date", style="yellow")
    table.add_column("Accounts", justify="right")
    table.add_column("Data Exposed")
    table.add_column("Verified", justify="center")

    for breach in sorted(result.breaches, key=lambda b: b.breach_date or breach.added_date, reverse=True):
        date_str = breach.breach_date.strftime("%Y-%m-%d") if breach.breach_date else "Unknown"
        verified = "[green]Yes[/green]" if breach.is_verified else "[dim]No[/dim]"
        data_types = ", ".join(breach.data_classes[:3])
        if len(breach.data_classes) > 3:
            data_types += f" (+{len(breach.data_classes) - 3})"

        table.add_row(
            breach.title,
            date_str,
            f"{breach.pwn_count:,}",
            data_types,
            verified,
        )

    console.print(table)


@hibp.command("emails")
@click.argument("emails_file", type=click.Path(exists=True))
@click.option("--api-key", "-k", envvar="HIBP_API_KEY", help="HIBP API key")
@click.option("--output", "-o", type=click.Path(), help="Output file for results")
@click.pass_context
def check_emails_batch(
    ctx: click.Context,
    emails_file: str,
    api_key: str | None,
    output: str | None,
) -> None:
    """Check multiple emails from a file.

    File should contain one email per line.

    Example:
        globaldetect hibp emails emails.txt --output results.json
    """
    if not api_key:
        console.print("[red]HIBP API key required[/red]")
        raise SystemExit(1)

    emails = Path(emails_file).read_text().strip().split("\n")
    emails = [e.strip() for e in emails if e.strip() and "@" in e]

    if not emails:
        console.print("[yellow]No valid emails found in file[/yellow]")
        return

    console.print(f"Checking {len(emails)} email(s)...")

    async def _check_batch():
        results = []
        async with HIBPClient(api_key=api_key) as client:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("{task.completed}/{task.total}"),
                console=console,
            ) as progress:
                task = progress.add_task("Checking emails...", total=len(emails))

                async for result in client.check_emails_batch(emails):
                    results.append(result)
                    progress.advance(task)

        return results

    results = asyncio.run(_check_batch())

    # Summary
    breached = [r for r in results if r.is_breached]
    console.print(f"\n[bold]Results:[/bold] {len(breached)}/{len(results)} emails found in breaches")

    # Table of results
    table = Table(title="Batch Check Results")
    table.add_column("Email", style="cyan")
    table.add_column("Breached", justify="center")
    table.add_column("Breach Count", justify="right")

    for result in results:
        status = "[red]Yes[/red]" if result.is_breached else "[green]No[/green]"
        table.add_row(
            result.email,
            status,
            str(result.breach_count) if result.is_breached else "-",
        )

    console.print(table)

    # Save to file
    if output:
        import json
        output_data = [r.to_dict() for r in results]
        Path(output).write_text(json.dumps(output_data, indent=2, default=str))
        console.print(f"\n[green]Results saved to {output}[/green]")


# =============================================================================
# Password Checking
# =============================================================================

@hibp.command("password")
@click.option("--password", "-p", help="Password to check (or prompts securely)")
@click.option("--hash", "password_hash", help="SHA-1 hash to check instead")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
@click.pass_context
def check_password(
    ctx: click.Context,
    password: str | None,
    password_hash: str | None,
    json_output: bool,
) -> None:
    """Check if a password has been exposed in data breaches.

    Uses k-anonymity - only the first 5 characters of the SHA-1 hash
    are sent to the API. Your password never leaves your system.

    Example:
        globaldetect hibp password
        globaldetect hibp password --hash 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
    """
    if not password and not password_hash:
        password = click.prompt("Password to check", hide_input=True)

    async def _check():
        async with HIBPClient() as client:
            if password_hash:
                return await client.check_password_hash(password_hash)
            else:
                return await client.check_password(password)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("Checking password...", total=None)
        result = asyncio.run(_check())

    if result.error:
        console.print(f"[red]Error: {result.error}[/red]")
        raise SystemExit(1)

    if json_output:
        import json
        console.print(json.dumps(result.to_dict(), indent=2, default=str))
        return

    color = risk_color(result.risk_level)

    if not result.is_pwned:
        console.print(Panel(
            f"[green]Good news![/green] This password has NOT been found in any known data breaches.\n\n"
            f"Risk Level: [{color}]{result.risk_level.value.upper()}[/{color}]",
            title="Password Check Result"
        ))
    else:
        console.print(Panel(
            f"[red]Warning![/red] This password has been seen [bold]{result.occurrences:,}[/bold] times in data breaches!\n\n"
            f"Risk Level: [{color}]{result.risk_level.value.upper()}[/{color}]\n\n"
            f"{result.risk_description}",
            title="Password Check Result"
        ))


@hibp.command("passwords")
@click.argument("passwords_file", type=click.Path(exists=True))
@click.option("--hashes", is_flag=True, help="File contains SHA-1 hashes instead of passwords")
@click.option("--output", "-o", type=click.Path(), help="Output file for results")
@click.pass_context
def check_passwords_batch(
    ctx: click.Context,
    passwords_file: str,
    hashes: bool,
    output: str | None,
) -> None:
    """Check multiple passwords/hashes from a file.

    File should contain one password or SHA-1 hash per line.

    Example:
        globaldetect hibp passwords passwords.txt
        globaldetect hibp passwords hashes.txt --hashes
    """
    items = Path(passwords_file).read_text().strip().split("\n")
    items = [i.strip() for i in items if i.strip()]

    if not items:
        console.print("[yellow]No items found in file[/yellow]")
        return

    console.print(f"Checking {len(items)} {'hashes' if hashes else 'passwords'}...")

    async def _check_batch():
        results = []
        async with HIBPClient() as client:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("{task.completed}/{task.total}"),
                console=console,
            ) as progress:
                task = progress.add_task("Checking...", total=len(items))

                for item in items:
                    if hashes:
                        result = await client.check_password_hash(item)
                    else:
                        result = await client.check_password(item)
                    results.append((item if hashes else "***", result))
                    progress.advance(task)

        return results

    results = asyncio.run(_check_batch())

    # Summary
    pwned = [r for _, r in results if r.is_pwned]
    console.print(f"\n[bold]Results:[/bold] {len(pwned)}/{len(results)} passwords found in breaches")

    # Risk distribution
    risk_counts = {}
    for _, r in results:
        risk_counts[r.risk_level] = risk_counts.get(r.risk_level, 0) + 1

    console.print("\n[bold]Risk Distribution:[/bold]")
    for risk in RiskLevel:
        count = risk_counts.get(risk, 0)
        color = risk_color(risk)
        console.print(f"  [{color}]{risk.value.upper()}[/{color}]: {count}")

    # Save to file
    if output:
        import json
        output_data = [
            {"identifier": ident, "result": result.to_dict()}
            for ident, result in results
        ]
        Path(output).write_text(json.dumps(output_data, indent=2, default=str))
        console.print(f"\n[green]Results saved to {output}[/green]")


# =============================================================================
# Breach Database Commands
# =============================================================================

@hibp.command("breaches")
@click.option("--domain", "-d", help="Filter by domain")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
@click.pass_context
def list_breaches(
    ctx: click.Context,
    domain: str | None,
    json_output: bool,
) -> None:
    """List all breaches in the HIBP database.

    No API key required.

    Example:
        globaldetect hibp breaches
        globaldetect hibp breaches --domain adobe.com
    """
    async def _get():
        async with HIBPClient() as client:
            return await client.get_all_breaches(domain=domain)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("Fetching breach database...", total=None)
        breaches = asyncio.run(_get())

    if json_output:
        import json
        console.print(json.dumps([b.to_dict() for b in breaches], indent=2, default=str))
        return

    if not breaches:
        console.print("[yellow]No breaches found[/yellow]")
        return

    total_accounts = sum(b.pwn_count for b in breaches)
    console.print(f"\n[bold]Total Breaches:[/bold] {len(breaches)}")
    console.print(f"[bold]Total Compromised Accounts:[/bold] {total_accounts:,}\n")

    table = Table(title="Known Data Breaches")
    table.add_column("Name", style="cyan")
    table.add_column("Date", style="yellow")
    table.add_column("Accounts", justify="right")
    table.add_column("Domain")
    table.add_column("Data Exposed")

    for breach in sorted(breaches, key=lambda b: b.pwn_count, reverse=True)[:50]:
        date_str = breach.breach_date.strftime("%Y-%m-%d") if breach.breach_date else "Unknown"
        data_types = ", ".join(breach.data_classes[:2])
        if len(breach.data_classes) > 2:
            data_types += "..."

        table.add_row(
            breach.title[:30],
            date_str,
            f"{breach.pwn_count:,}",
            breach.domain or "-",
            data_types,
        )

    console.print(table)

    if len(breaches) > 50:
        console.print(f"\n[dim]Showing top 50 of {len(breaches)} breaches[/dim]")


@hibp.command("breach")
@click.argument("name")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
@click.pass_context
def get_breach(
    ctx: click.Context,
    name: str,
    json_output: bool,
) -> None:
    """Get details for a specific breach.

    Example:
        globaldetect hibp breach Adobe
        globaldetect hibp breach LinkedIn
    """
    async def _get():
        async with HIBPClient() as client:
            return await client.get_breach(name)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task(f"Fetching {name}...", total=None)
        breach = asyncio.run(_get())

    if not breach:
        console.print(f"[red]Breach not found: {name}[/red]")
        raise SystemExit(1)

    if json_output:
        import json
        console.print(json.dumps(breach.to_dict(), indent=2, default=str))
        return

    date_str = breach.breach_date.strftime("%B %d, %Y") if breach.breach_date else "Unknown"

    # Build flags
    flags = []
    if breach.is_verified:
        flags.append("[green]Verified[/green]")
    if breach.is_sensitive:
        flags.append("[red]Sensitive[/red]")
    if breach.is_spam_list:
        flags.append("[yellow]Spam List[/yellow]")
    if breach.is_malware:
        flags.append("[red]Malware[/red]")

    console.print(Panel(
        f"[bold]{breach.title}[/bold]\n\n"
        f"Domain: [cyan]{breach.domain or 'N/A'}[/cyan]\n"
        f"Breach Date: [yellow]{date_str}[/yellow]\n"
        f"Compromised Accounts: [red]{breach.pwn_count:,}[/red]\n"
        f"Flags: {' '.join(flags) if flags else 'None'}\n\n"
        f"[bold]Data Exposed:[/bold]\n"
        f"{', '.join(breach.data_classes)}\n\n"
        f"[bold]Description:[/bold]\n"
        f"{breach.description[:500]}{'...' if len(breach.description) > 500 else ''}",
        title=f"Breach Details: {breach.name}"
    ))


@hibp.command("pastes")
@click.argument("email")
@click.option("--api-key", "-k", envvar="HIBP_API_KEY", help="HIBP API key")
@click.pass_context
def check_pastes(
    ctx: click.Context,
    email: str,
    api_key: str | None,
) -> None:
    """Check if an email has appeared in any pastes.

    Requires HIBP API key.

    Example:
        globaldetect hibp pastes user@example.com
    """
    if not api_key:
        console.print("[red]HIBP API key required[/red]")
        raise SystemExit(1)

    async def _check():
        async with HIBPClient(api_key=api_key) as client:
            return await client.check_pastes(email)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task(f"Checking pastes for {email}...", total=None)
        pastes = asyncio.run(_check())

    if not pastes:
        console.print(f"[green]No pastes found for {email}[/green]")
        return

    console.print(f"\n[red]Found in {len(pastes)} paste(s)[/red]\n")

    table = Table(title="Paste Appearances")
    table.add_column("Source", style="cyan")
    table.add_column("ID")
    table.add_column("Title")
    table.add_column("Date", style="yellow")
    table.add_column("Email Count", justify="right")

    for paste in pastes:
        date_str = paste.date.strftime("%Y-%m-%d") if paste.date else "Unknown"
        table.add_row(
            paste.source,
            paste.id[:20],
            (paste.title or "Untitled")[:30],
            date_str,
            f"{paste.email_count:,}",
        )

    console.print(table)


# =============================================================================
# Configuration
# =============================================================================

@hibp.command("config")
@click.pass_context
def show_config(ctx: click.Context) -> None:
    """Show HIBP configuration and API key status."""
    api_key = get_api_key()

    table = Table(title="HIBP Configuration")
    table.add_column("Setting", style="cyan")
    table.add_column("Value")

    table.add_row(
        "API Key",
        f"[green]Set ({api_key[:8]}...)[/green]" if api_key else "[red]Not set[/red]"
    )
    table.add_row("API Base URL", HIBPClient.HIBP_API_BASE)
    table.add_row("Password API URL", HIBPClient.PWNED_PASSWORDS_API)

    console.print(table)

    if not api_key:
        console.print("\n[yellow]To enable email breach checking:[/yellow]")
        console.print("  export HIBP_API_KEY=your_api_key")
        console.print("  Get a key at: https://haveibeenpwned.com/API/Key")


def add_hibp_commands(main_cli):
    """Add HIBP commands to main CLI."""
    main_cli.add_command(hibp)
