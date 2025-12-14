"""
GlobalDetect CLI - Main entry point for the command-line interface.
"""

import click
from rich.console import Console

from globaldetect import __version__

console = Console()


@click.group()
@click.version_option(version=__version__, prog_name="globaldetect")
@click.pass_context
def main(ctx: click.Context) -> None:
    """GlobalDetect - ISP Network Engineering Utilities

    A comprehensive toolkit for network engineers providing tools for
    IP/CIDR management, BGP analysis, DNS utilities, and diagnostics.
    """
    ctx.ensure_object(dict)
    ctx.obj["console"] = console


# Import and register subcommand groups
from globaldetect.ip.cli import ip
from globaldetect.bgp.cli import bgp
from globaldetect.dns.cli import dns
from globaldetect.diag.cli import diag
from globaldetect.services.cli import services
from globaldetect.recon.cli import recon
from globaldetect.rbl.cli import rbl
from globaldetect.darkweb.cli import darkweb
from globaldetect.neighbors.cli import neighbors
from globaldetect.cap.cli import cap
from globaldetect.http.cli import http
from globaldetect.inventory.cli import catalog, system, switch, location, db

main.add_command(ip)
main.add_command(bgp)
main.add_command(dns)
main.add_command(diag)
main.add_command(services)
main.add_command(recon)
main.add_command(rbl)
main.add_command(darkweb)
main.add_command(neighbors)
main.add_command(cap)
main.add_command(http)

# Inventory commands
main.add_command(catalog)
main.add_command(system)
main.add_command(switch)
main.add_command(location)
main.add_command(db)

# Agent and server commands (added dynamically)
from globaldetect.inventory.agent import add_agent_commands
from globaldetect.inventory.server import add_server_commands
add_agent_commands(main)
add_server_commands(main)


if __name__ == "__main__":
    main()
