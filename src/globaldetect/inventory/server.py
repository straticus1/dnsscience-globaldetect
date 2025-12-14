"""
GlobalDetect Inventory Server - API for agent check-ins and inventory queries.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import json
import os
import secrets
from datetime import datetime
from functools import wraps
from typing import Any, Callable

from globaldetect.inventory.database import Database, get_database
from globaldetect.inventory.models import (
    Location,
    NetworkInterface,
    System,
    SystemStatus,
    SystemType,
)

# Try to import Flask - it's optional for server mode
try:
    from flask import Flask, request, jsonify, g
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False


def require_flask():
    """Raise error if Flask is not available."""
    if not FLASK_AVAILABLE:
        raise ImportError(
            "Flask is required for server mode. "
            "Install with: pip install flask"
        )


class InventoryServer:
    """REST API server for GlobalDetect inventory.

    Provides endpoints for:
    - Agent check-ins (POST /api/v1/agent/checkin)
    - System queries (GET /api/v1/systems)
    - Switch queries (GET /api/v1/switches)
    - Location queries (GET /api/v1/locations)
    """

    def __init__(
        self,
        db: Database | None = None,
        api_keys: list[str] | None = None,
        require_auth: bool = True,
    ):
        require_flask()

        self.db = db or get_database()
        self.db.initialize()

        # API keys for authentication
        self.api_keys = set(api_keys or [])
        self.require_auth = require_auth

        # Create Flask app
        self.app = Flask(__name__)
        self._setup_routes()

    def _setup_routes(self):
        """Setup Flask routes."""

        @self.app.before_request
        def before_request():
            g.db = self.db

        @self.app.after_request
        def after_request(response):
            response.headers["X-GlobalDetect-Version"] = "1.0.0"
            return response

        # Authentication decorator
        def require_api_key(f: Callable) -> Callable:
            @wraps(f)
            def decorated(*args, **kwargs):
                if not self.require_auth:
                    return f(*args, **kwargs)

                auth_header = request.headers.get("Authorization", "")
                if auth_header.startswith("Bearer "):
                    token = auth_header[7:]
                    if token in self.api_keys:
                        return f(*args, **kwargs)

                return jsonify({"error": "Unauthorized"}), 401

            return decorated

        # ================================================================
        # Health check
        # ================================================================

        @self.app.route("/health")
        def health():
            return jsonify({"status": "ok", "timestamp": datetime.now().isoformat()})

        # ================================================================
        # Agent endpoints
        # ================================================================

        @self.app.route("/api/v1/agent/checkin", methods=["POST"])
        @require_api_key
        def agent_checkin():
            """Handle agent check-in with system inventory."""
            data = request.get_json()
            if not data:
                return jsonify({"error": "No data provided"}), 400

            # Extract system info
            hostname = data.get("hostname")
            if not hostname:
                return jsonify({"error": "hostname is required"}), 400

            # Check if system exists
            existing = g.db.get_system_by_hostname(hostname)

            if existing:
                # Update existing system
                existing.fqdn = data.get("fqdn", existing.fqdn)
                existing.primary_ip = data.get("primary_ip", existing.primary_ip)
                existing.primary_mac = data.get("primary_mac", existing.primary_mac)
                existing.os_name = data.get("os_name", existing.os_name)
                existing.os_version = data.get("os_version", existing.os_version)
                existing.kernel_version = data.get("kernel_version", existing.kernel_version)
                existing.cpu_cores = data.get("cpu_cores", existing.cpu_cores)
                existing.ram_gb = data.get("ram_gb", existing.ram_gb)
                existing.disk_gb = data.get("disk_gb", existing.disk_gb)
                existing.agent_version = data.get("agent_version", existing.agent_version)
                existing.agent_last_checkin = datetime.now()
                existing.last_seen = datetime.now()

                # Update tags if provided
                if "tags" in data:
                    existing.tags = data["tags"]

                # Update custom fields if provided
                if "custom_fields" in data:
                    existing.custom_fields.update(data["custom_fields"])

                g.db.update_system(existing)

                # Update interfaces if provided
                if "interfaces" in data:
                    _update_interfaces(g.db, existing.id, data["interfaces"])

                return jsonify({
                    "status": "updated",
                    "system_id": existing.id,
                    "hostname": existing.hostname,
                })

            else:
                # Create new system
                system = System(
                    hostname=hostname,
                    fqdn=data.get("fqdn"),
                    primary_ip=data.get("primary_ip"),
                    primary_mac=data.get("primary_mac"),
                    system_type=SystemType(data.get("system_type", "server")),
                    status=SystemStatus.ACTIVE,
                    os_name=data.get("os_name"),
                    os_version=data.get("os_version"),
                    kernel_version=data.get("kernel_version"),
                    cpu_cores=data.get("cpu_cores"),
                    ram_gb=data.get("ram_gb"),
                    disk_gb=data.get("disk_gb"),
                    agent_version=data.get("agent_version"),
                    agent_last_checkin=datetime.now(),
                    tags=data.get("tags", []),
                    custom_fields=data.get("custom_fields", {}),
                    discovered_via="agent",
                    discovered_at=datetime.now(),
                    last_seen=datetime.now(),
                )

                # Handle location
                location_data = data.get("location")
                if location_data:
                    loc = Location(
                        datacenter=location_data.get("datacenter"),
                        rack=location_data.get("rack"),
                        rack_unit=location_data.get("rack_unit"),
                    )
                    loc = g.db.create_location(loc)
                    system.location_id = loc.id

                # Create interfaces
                if "interfaces" in data:
                    for iface_data in data["interfaces"]:
                        iface = NetworkInterface(
                            name=iface_data.get("name"),
                            mac_address=iface_data.get("mac_address"),
                            ip_addresses=iface_data.get("ip_addresses", []),
                            is_up=iface_data.get("is_up", True),
                            is_primary=iface_data.get("is_primary", False),
                            mtu=iface_data.get("mtu"),
                            discovered_via="agent",
                            last_seen=datetime.now(),
                        )
                        system.interfaces.append(iface)

                system = g.db.create_system(system)

                return jsonify({
                    "status": "created",
                    "system_id": system.id,
                    "hostname": system.hostname,
                }), 201

        # ================================================================
        # System endpoints
        # ================================================================

        @self.app.route("/api/v1/systems")
        @require_api_key
        def list_systems():
            """List all systems."""
            # Query parameters
            system_type = request.args.get("type")
            status = request.args.get("status")
            tag = request.args.get("tag")

            systems = g.db.list_systems(
                system_type=SystemType(system_type) if system_type else None,
                status=SystemStatus(status) if status else None,
                tag=tag,
            )

            return jsonify({
                "count": len(systems),
                "systems": [s.to_dict() for s in systems],
            })

        @self.app.route("/api/v1/systems/<identifier>")
        @require_api_key
        def get_system(identifier: str):
            """Get system by hostname or IP."""
            system = g.db.get_system_by_hostname(identifier)
            if system is None:
                system = g.db.get_system_by_ip(identifier)

            if system is None:
                return jsonify({"error": "System not found"}), 404

            return jsonify(system.to_dict())

        @self.app.route("/api/v1/systems/search")
        @require_api_key
        def search_systems():
            """Search systems."""
            query = request.args.get("q", "")
            if not query:
                return jsonify({"error": "Search query required"}), 400

            systems = g.db.search_systems(query)
            return jsonify({
                "query": query,
                "count": len(systems),
                "systems": [s.to_dict() for s in systems],
            })

        # ================================================================
        # Switch endpoints
        # ================================================================

        @self.app.route("/api/v1/switches")
        @require_api_key
        def list_switches():
            """List all switches."""
            vendor = request.args.get("vendor")
            switches = g.db.list_switches(vendor=vendor)

            return jsonify({
                "count": len(switches),
                "switches": [s.to_dict() for s in switches],
            })

        @self.app.route("/api/v1/switches/<identifier>")
        @require_api_key
        def get_switch(identifier: str):
            """Get switch by hostname or IP."""
            switch = g.db.get_switch_by_hostname(identifier)
            if switch is None:
                switch = g.db.get_switch_by_ip(identifier)

            if switch is None:
                return jsonify({"error": "Switch not found"}), 404

            return jsonify(switch.to_dict())

        @self.app.route("/api/v1/switches/<identifier>/systems")
        @require_api_key
        def get_switch_systems(identifier: str):
            """Get systems connected to a switch."""
            switch = g.db.get_switch_by_hostname(identifier)
            if switch is None:
                switch = g.db.get_switch_by_ip(identifier)

            if switch is None:
                return jsonify({"error": "Switch not found"}), 404

            systems = g.db.get_systems_on_switch(switch.id)
            return jsonify({
                "switch": switch.hostname,
                "count": len(systems),
                "systems": [s.to_dict() for s in systems],
            })

        # ================================================================
        # Location endpoints
        # ================================================================

        @self.app.route("/api/v1/locations")
        @require_api_key
        def list_locations():
            """List all locations."""
            datacenter = request.args.get("datacenter")
            locations = g.db.list_locations(datacenter=datacenter)

            return jsonify({
                "count": len(locations),
                "locations": [loc.to_dict() for loc in locations],
            })

        @self.app.route("/api/v1/locations/racks/<rack_id>/systems")
        @require_api_key
        def get_rack_systems(rack_id: str):
            """Get systems in a rack."""
            datacenter = request.args.get("datacenter")
            systems = g.db.get_systems_in_rack(rack_id, datacenter=datacenter)

            return jsonify({
                "rack": rack_id,
                "datacenter": datacenter,
                "count": len(systems),
                "systems": [s.to_dict() for s in systems],
            })

        # ================================================================
        # Stats endpoint
        # ================================================================

        @self.app.route("/api/v1/stats")
        @require_api_key
        def get_stats():
            """Get inventory statistics."""
            systems = g.db.list_systems()
            switches = g.db.list_switches()
            locations = g.db.list_locations()

            # Count by type
            type_counts = {}
            status_counts = {}
            for sys in systems:
                t = sys.system_type.value
                s = sys.status.value
                type_counts[t] = type_counts.get(t, 0) + 1
                status_counts[s] = status_counts.get(s, 0) + 1

            return jsonify({
                "totals": {
                    "systems": len(systems),
                    "switches": len(switches),
                    "locations": len(locations),
                },
                "systems_by_type": type_counts,
                "systems_by_status": status_counts,
            })

    def run(self, host: str = "0.0.0.0", port: int = 8080, debug: bool = False):
        """Run the server."""
        self.app.run(host=host, port=port, debug=debug)

    def add_api_key(self, key: str) -> None:
        """Add an API key."""
        self.api_keys.add(key)

    def generate_api_key(self) -> str:
        """Generate and register a new API key."""
        key = secrets.token_urlsafe(32)
        self.api_keys.add(key)
        return key


def _update_interfaces(db: Database, system_id: int, interfaces_data: list[dict]) -> None:
    """Update system interfaces from agent data."""
    existing = db.get_interfaces_for_system(system_id)
    existing_by_name = {i.name: i for i in existing}

    for iface_data in interfaces_data:
        name = iface_data.get("name")
        if not name:
            continue

        if name in existing_by_name:
            # Update existing
            iface = existing_by_name[name]
            iface.mac_address = iface_data.get("mac_address", iface.mac_address)
            iface.ip_addresses = iface_data.get("ip_addresses", iface.ip_addresses)
            iface.is_up = iface_data.get("is_up", iface.is_up)
            iface.mtu = iface_data.get("mtu", iface.mtu)
            iface.last_seen = datetime.now()
            db.update_interface(iface)
        else:
            # Create new
            iface = NetworkInterface(
                system_id=system_id,
                name=name,
                mac_address=iface_data.get("mac_address"),
                ip_addresses=iface_data.get("ip_addresses", []),
                is_up=iface_data.get("is_up", True),
                is_primary=iface_data.get("is_primary", False),
                mtu=iface_data.get("mtu"),
                discovered_via="agent",
                last_seen=datetime.now(),
            )
            db.create_interface(iface)


# CLI command for running server
def add_server_commands(cli_group):
    """Add server commands to a Click group."""
    import click
    from rich.console import Console

    console = Console()

    @cli_group.group()
    def server():
        """Inventory server management."""
        pass

    @server.command("run")
    @click.option("--host", default="0.0.0.0", help="Host to bind to")
    @click.option("--port", "-p", type=int, default=8080, help="Port to listen on")
    @click.option("--debug", is_flag=True, help="Enable debug mode")
    @click.option("--db", "db_url", envvar="GLOBALDETECT_DB", help="Database URL")
    @click.option("--api-key", multiple=True, help="API keys (can specify multiple)")
    @click.option("--no-auth", is_flag=True, help="Disable authentication")
    def server_run(host: str, port: int, debug: bool, db_url: str | None,
                   api_key: tuple, no_auth: bool):
        """Run the inventory API server.

        Examples:
            globaldetect server run
            globaldetect server run --port 9000 --db postgresql://localhost/inventory
            globaldetect server run --api-key secret123 --api-key secret456
        """
        try:
            require_flask()
        except ImportError as e:
            console.print(f"[red]{e}[/red]")
            return

        # Get database
        db = get_database(db_url)
        db.initialize()

        # Setup API keys
        keys = list(api_key)
        if not keys and not no_auth:
            # Generate a default key
            key = secrets.token_urlsafe(32)
            keys.append(key)
            console.print(f"[yellow]Generated API key: {key}[/yellow]")
            console.print("Use this key in the Authorization header: Bearer <key>")
            console.print()

        # Create and run server
        inventory_server = InventoryServer(
            db=db,
            api_keys=keys,
            require_auth=not no_auth,
        )

        console.print(f"[green]Starting inventory server on {host}:{port}[/green]")
        if no_auth:
            console.print("[yellow]Warning: Authentication disabled[/yellow]")

        inventory_server.run(host=host, port=port, debug=debug)

    @server.command("generate-key")
    def server_generate_key():
        """Generate a new API key."""
        key = secrets.token_urlsafe(32)
        console.print(f"API Key: {key}")
        console.print("\nUse this in the Authorization header:")
        console.print(f"  Authorization: Bearer {key}")

    return server
