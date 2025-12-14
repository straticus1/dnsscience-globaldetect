"""
GlobalDetect Agent - Reports system inventory to central server.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import asyncio
import json
import os
import signal
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx

from globaldetect.inventory.discovery import AgentDiscovery
from globaldetect.inventory.models import System


@dataclass
class AgentConfig:
    """Agent configuration."""
    # Server connection
    server_url: str = ""
    api_key: str = ""
    verify_ssl: bool = True

    # Reporting
    report_interval: int = 300  # seconds (5 minutes)
    include_interfaces: bool = True
    include_resources: bool = True

    # Agent identity
    agent_id: str | None = None
    custom_tags: list[str] = field(default_factory=list)
    custom_fields: dict[str, Any] = field(default_factory=dict)

    # Location (manual override)
    datacenter: str | None = None
    rack: str | None = None
    rack_unit: int | None = None

    @classmethod
    def from_file(cls, path: str | Path) -> "AgentConfig":
        """Load configuration from file.

        Supports JSON and simple key=value format.
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")

        content = path.read_text()

        # Try JSON first
        try:
            data = json.loads(content)
            return cls.from_dict(data)
        except json.JSONDecodeError:
            pass

        # Parse key=value format
        data = {}
        for line in content.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")

                # Handle special types
                if value.lower() in ("true", "yes", "1"):
                    value = True
                elif value.lower() in ("false", "no", "0"):
                    value = False
                elif value.isdigit():
                    value = int(value)

                data[key] = value

        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AgentConfig":
        """Create config from dictionary."""
        return cls(
            server_url=data.get("server_url", data.get("GLOBALDETECT_SERVER", "")),
            api_key=data.get("api_key", data.get("GLOBALDETECT_API_KEY", "")),
            verify_ssl=data.get("verify_ssl", True),
            report_interval=data.get("report_interval", 300),
            include_interfaces=data.get("include_interfaces", True),
            include_resources=data.get("include_resources", True),
            agent_id=data.get("agent_id"),
            custom_tags=data.get("tags", data.get("custom_tags", [])),
            custom_fields=data.get("custom_fields", {}),
            datacenter=data.get("datacenter"),
            rack=data.get("rack"),
            rack_unit=data.get("rack_unit"),
        )

    @classmethod
    def from_env(cls) -> "AgentConfig":
        """Create config from environment variables."""
        return cls(
            server_url=os.environ.get("GLOBALDETECT_SERVER", ""),
            api_key=os.environ.get("GLOBALDETECT_API_KEY", ""),
            verify_ssl=os.environ.get("GLOBALDETECT_VERIFY_SSL", "true").lower() == "true",
            report_interval=int(os.environ.get("GLOBALDETECT_INTERVAL", "300")),
            datacenter=os.environ.get("GLOBALDETECT_DATACENTER"),
            rack=os.environ.get("GLOBALDETECT_RACK"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "server_url": self.server_url,
            "api_key": "***" if self.api_key else "",
            "verify_ssl": self.verify_ssl,
            "report_interval": self.report_interval,
            "include_interfaces": self.include_interfaces,
            "include_resources": self.include_resources,
            "agent_id": self.agent_id,
            "custom_tags": self.custom_tags,
            "custom_fields": self.custom_fields,
            "datacenter": self.datacenter,
            "rack": self.rack,
            "rack_unit": self.rack_unit,
        }


class Agent:
    """GlobalDetect inventory agent."""

    VERSION = "1.0.0"

    def __init__(self, config: AgentConfig):
        self.config = config
        self._running = False
        self._last_report: datetime | None = None
        self._report_count = 0
        self._error_count = 0

    async def report_once(self) -> bool:
        """Perform a single inventory report.

        Returns:
            True if report was successful
        """
        if not self.config.server_url:
            print("Error: No server URL configured")
            return False

        if not self.config.api_key:
            print("Error: No API key configured")
            return False

        # Discover self
        system = AgentDiscovery.discover_self()

        # Apply config overrides
        system.agent_version = self.VERSION
        system.agent_last_checkin = datetime.now()

        if self.config.custom_tags:
            system.tags.extend(self.config.custom_tags)

        if self.config.custom_fields:
            system.custom_fields.update(self.config.custom_fields)

        # Build payload
        payload = system.to_dict()
        payload["agent_id"] = self.config.agent_id or system.hostname

        # Add location info if configured
        if self.config.datacenter or self.config.rack:
            payload["location"] = {
                "datacenter": self.config.datacenter,
                "rack": self.config.rack,
                "rack_unit": self.config.rack_unit,
            }

        # Remove interfaces if not requested
        if not self.config.include_interfaces:
            payload.pop("interfaces", None)

        # Remove resource info if not requested
        if not self.config.include_resources:
            for key in ["cpu_cores", "ram_gb", "disk_gb"]:
                payload.pop(key, None)

        # Send report
        try:
            async with httpx.AsyncClient(verify=self.config.verify_ssl) as client:
                response = await client.post(
                    f"{self.config.server_url.rstrip('/')}/api/v1/agent/checkin",
                    json=payload,
                    headers={
                        "Authorization": f"Bearer {self.config.api_key}",
                        "Content-Type": "application/json",
                        "User-Agent": f"globaldetect-agent/{self.VERSION}",
                    },
                    timeout=30.0,
                )

                if response.status_code in (200, 201):
                    self._last_report = datetime.now()
                    self._report_count += 1
                    return True
                else:
                    self._error_count += 1
                    print(f"Server returned {response.status_code}: {response.text}")
                    return False

        except httpx.ConnectError as e:
            self._error_count += 1
            print(f"Connection error: {e}")
            return False
        except httpx.TimeoutException:
            self._error_count += 1
            print("Request timed out")
            return False
        except Exception as e:
            self._error_count += 1
            print(f"Error: {e}")
            return False

    async def run(self) -> None:
        """Run the agent in continuous mode."""
        self._running = True

        # Setup signal handlers
        def stop_handler(sig, frame):
            print("\nShutting down agent...")
            self._running = False

        signal.signal(signal.SIGINT, stop_handler)
        signal.signal(signal.SIGTERM, stop_handler)

        print(f"GlobalDetect Agent v{self.VERSION}")
        print(f"Server: {self.config.server_url}")
        print(f"Report interval: {self.config.report_interval}s")
        print("Starting...")

        while self._running:
            # Perform report
            success = await self.report_once()

            if success:
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] "
                      f"Report #{self._report_count} sent successfully")
            else:
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] "
                      f"Report failed (errors: {self._error_count})")

            # Wait for next interval
            for _ in range(self.config.report_interval):
                if not self._running:
                    break
                await asyncio.sleep(1)

        print(f"Agent stopped. Reports sent: {self._report_count}, Errors: {self._error_count}")

    def status(self) -> dict[str, Any]:
        """Get agent status."""
        return {
            "version": self.VERSION,
            "running": self._running,
            "server_url": self.config.server_url,
            "last_report": self._last_report.isoformat() if self._last_report else None,
            "report_count": self._report_count,
            "error_count": self._error_count,
        }


# CLI commands for agent mode
def add_agent_commands(cli_group):
    """Add agent commands to a Click group."""
    import click
    from rich.console import Console
    from rich.panel import Panel

    console = Console()

    @cli_group.group()
    def agent():
        """Agent mode for inventory reporting."""
        pass

    @agent.command("run")
    @click.option("--config", "-c", "config_file", type=click.Path(exists=True),
                  help="Path to config file")
    @click.option("--server", envvar="GLOBALDETECT_SERVER", help="Server URL")
    @click.option("--api-key", envvar="GLOBALDETECT_API_KEY", help="API key")
    @click.option("--interval", type=int, default=300, help="Report interval in seconds")
    @click.option("--once", is_flag=True, help="Report once and exit")
    def agent_run(config_file: str | None, server: str | None, api_key: str | None,
                  interval: int, once: bool):
        """Run the inventory agent.

        The agent discovers information about this system and reports it
        to a central GlobalDetect server at regular intervals.

        Configuration can be provided via:
        - Config file (--config)
        - Environment variables (GLOBALDETECT_SERVER, GLOBALDETECT_API_KEY)
        - Command line options
        """
        # Load configuration
        if config_file:
            config = AgentConfig.from_file(config_file)
        else:
            config = AgentConfig.from_env()

        # Override with command line options
        if server:
            config.server_url = server
        if api_key:
            config.api_key = api_key
        if interval:
            config.report_interval = interval

        # Validate
        if not config.server_url:
            console.print("[red]Error: No server URL configured[/red]")
            console.print("Set GLOBALDETECT_SERVER environment variable or use --server")
            sys.exit(1)

        if not config.api_key:
            console.print("[red]Error: No API key configured[/red]")
            console.print("Set GLOBALDETECT_API_KEY environment variable or use --api-key")
            sys.exit(1)

        agent_instance = Agent(config)

        if once:
            success = asyncio.run(agent_instance.report_once())
            if success:
                console.print("[green]Report sent successfully[/green]")
            else:
                console.print("[red]Report failed[/red]")
                sys.exit(1)
        else:
            asyncio.run(agent_instance.run())

    @agent.command("info")
    @click.option("--json", "json_output", is_flag=True, help="Output as JSON")
    def agent_info(json_output: bool):
        """Show information that would be reported by the agent."""
        system = AgentDiscovery.discover_self()

        if json_output:
            console.print_json(json.dumps(system.to_dict(), default=str))
            return

        # Display system info
        info_lines = [
            f"[bold]Hostname:[/bold] {system.hostname}",
            f"[bold]FQDN:[/bold] {system.fqdn}",
            f"[bold]OS:[/bold] {system.os_name} {system.os_version}",
            f"[bold]Kernel:[/bold] {system.kernel_version}",
        ]

        if system.cpu_cores:
            info_lines.append(f"[bold]CPU Cores:[/bold] {system.cpu_cores}")
        if system.ram_gb:
            info_lines.append(f"[bold]RAM:[/bold] {system.ram_gb} GB")
        if system.disk_gb:
            info_lines.append(f"[bold]Disk:[/bold] {system.disk_gb} GB")

        console.print(Panel("\n".join(info_lines), title="Agent Info"))

        if system.interfaces:
            console.print("\n[bold]Network Interfaces:[/bold]")
            for iface in system.interfaces:
                status = "[green]UP[/green]" if iface.is_up else "[red]DOWN[/red]"
                primary = " [bold](primary)[/bold]" if iface.is_primary else ""
                ips = ", ".join(iface.ip_addresses) if iface.ip_addresses else "no IP"
                console.print(f"  {iface.name}: {iface.mac_address or 'no MAC'} - {ips} {status}{primary}")

    @agent.command("config")
    @click.option("--output", "-o", type=click.Path(), help="Write example config to file")
    def agent_config(output: str | None):
        """Show or generate agent configuration."""
        example_config = """# GlobalDetect Agent Configuration
# This file configures the agent that reports inventory to a central server.

# Server connection (required)
server_url = "https://inventory.example.com"
api_key = "your-api-key-here"

# SSL verification (set to false for self-signed certs)
verify_ssl = true

# How often to report (in seconds)
report_interval = 300

# What to include in reports
include_interfaces = true
include_resources = true

# Optional: Override agent ID (defaults to hostname)
# agent_id = "custom-agent-id"

# Optional: Add custom tags
# tags = ["production", "web-tier"]

# Optional: Location info (if not auto-detected)
# datacenter = "DC1"
# rack = "A01"
# rack_unit = 42
"""
        if output:
            Path(output).write_text(example_config)
            console.print(f"[green]Example config written to {output}[/green]")
        else:
            console.print(example_config)

    return agent
