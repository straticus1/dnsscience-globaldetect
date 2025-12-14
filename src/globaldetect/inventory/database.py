"""
Database abstraction layer supporting SQLite and PostgreSQL.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import json
import os
import sqlite3
from abc import ABC, abstractmethod
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Generator
from urllib.parse import urlparse

from globaldetect.inventory.models import (
    Location,
    NetworkInterface,
    Switch,
    System,
    SystemStatus,
    SystemType,
)


class Database(ABC):
    """Abstract database interface."""

    @abstractmethod
    def initialize(self) -> None:
        """Initialize database schema."""
        pass

    @abstractmethod
    def close(self) -> None:
        """Close database connection."""
        pass

    # Location operations
    @abstractmethod
    def create_location(self, location: Location) -> Location:
        pass

    @abstractmethod
    def get_location(self, location_id: int) -> Location | None:
        pass

    @abstractmethod
    def update_location(self, location: Location) -> Location:
        pass

    @abstractmethod
    def delete_location(self, location_id: int) -> bool:
        pass

    @abstractmethod
    def list_locations(
        self,
        datacenter: str | None = None,
        country: str | None = None,
    ) -> list[Location]:
        pass

    # Switch operations
    @abstractmethod
    def create_switch(self, switch: Switch) -> Switch:
        pass

    @abstractmethod
    def get_switch(self, switch_id: int) -> Switch | None:
        pass

    @abstractmethod
    def get_switch_by_hostname(self, hostname: str) -> Switch | None:
        pass

    @abstractmethod
    def get_switch_by_ip(self, ip: str) -> Switch | None:
        pass

    @abstractmethod
    def update_switch(self, switch: Switch) -> Switch:
        pass

    @abstractmethod
    def delete_switch(self, switch_id: int) -> bool:
        pass

    @abstractmethod
    def list_switches(
        self,
        location_id: int | None = None,
        vendor: str | None = None,
    ) -> list[Switch]:
        pass

    # System operations
    @abstractmethod
    def create_system(self, system: System) -> System:
        pass

    @abstractmethod
    def get_system(self, system_id: int) -> System | None:
        pass

    @abstractmethod
    def get_system_by_hostname(self, hostname: str) -> System | None:
        pass

    @abstractmethod
    def get_system_by_ip(self, ip: str) -> System | None:
        pass

    @abstractmethod
    def update_system(self, system: System) -> System:
        pass

    @abstractmethod
    def delete_system(self, system_id: int) -> bool:
        pass

    @abstractmethod
    def list_systems(
        self,
        system_type: SystemType | None = None,
        status: SystemStatus | None = None,
        location_id: int | None = None,
        switch_id: int | None = None,
        tag: str | None = None,
    ) -> list[System]:
        pass

    # Interface operations
    @abstractmethod
    def create_interface(self, interface: NetworkInterface) -> NetworkInterface:
        pass

    @abstractmethod
    def get_interfaces_for_system(self, system_id: int) -> list[NetworkInterface]:
        pass

    @abstractmethod
    def get_interfaces_on_switch(self, switch_id: int) -> list[NetworkInterface]:
        pass

    @abstractmethod
    def update_interface(self, interface: NetworkInterface) -> NetworkInterface:
        pass

    @abstractmethod
    def delete_interface(self, interface_id: int) -> bool:
        pass

    # Search and discovery
    @abstractmethod
    def search_systems(self, query: str) -> list[System]:
        pass

    @abstractmethod
    def get_systems_on_switch(self, switch_id: int) -> list[System]:
        pass

    @abstractmethod
    def get_systems_in_rack(self, rack: str, datacenter: str | None = None) -> list[System]:
        pass


class SQLiteDatabase(Database):
    """SQLite implementation for testing and small deployments."""

    def __init__(self, db_path: str = "globaldetect_inventory.db"):
        self.db_path = db_path
        self._conn: sqlite3.Connection | None = None

    @contextmanager
    def _get_conn(self) -> Generator[sqlite3.Connection, None, None]:
        """Get database connection with row factory."""
        if self._conn is None:
            self._conn = sqlite3.connect(self.db_path)
            self._conn.row_factory = sqlite3.Row
        yield self._conn

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def initialize(self) -> None:
        """Create database schema."""
        with self._get_conn() as conn:
            conn.executescript("""
                -- Locations table
                CREATE TABLE IF NOT EXISTS locations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    country TEXT,
                    state TEXT,
                    city TEXT,
                    address TEXT,
                    datacenter TEXT,
                    building TEXT,
                    floor TEXT,
                    room TEXT,
                    rack TEXT,
                    rack_unit INTEGER,
                    latitude REAL,
                    longitude REAL,
                    notes TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                );

                -- Switches table
                CREATE TABLE IF NOT EXISTS switches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hostname TEXT UNIQUE,
                    management_ip TEXT,
                    vendor TEXT,
                    model TEXT,
                    serial_number TEXT,
                    firmware_version TEXT,
                    platform TEXT,
                    capabilities TEXT,  -- JSON array
                    location_id INTEGER REFERENCES locations(id),
                    total_ports INTEGER,
                    notes TEXT,
                    tags TEXT,  -- JSON array
                    custom_fields TEXT,  -- JSON object
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    last_seen TEXT
                );

                -- Systems table
                CREATE TABLE IF NOT EXISTS systems (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hostname TEXT,
                    fqdn TEXT,
                    system_type TEXT DEFAULT 'unknown',
                    status TEXT DEFAULT 'unknown',
                    primary_ip TEXT,
                    primary_mac TEXT,
                    vendor TEXT,
                    model TEXT,
                    serial_number TEXT,
                    os_name TEXT,
                    os_version TEXT,
                    kernel_version TEXT,
                    cpu_cores INTEGER,
                    ram_gb REAL,
                    disk_gb REAL,
                    asn INTEGER,
                    as_name TEXT,
                    ip_country TEXT,
                    ip_city TEXT,
                    ip_org TEXT,
                    location_id INTEGER REFERENCES locations(id),
                    agent_version TEXT,
                    agent_last_checkin TEXT,
                    notes TEXT,
                    tags TEXT,  -- JSON array
                    custom_fields TEXT,  -- JSON object
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    last_seen TEXT,
                    discovered_at TEXT,
                    discovered_via TEXT
                );

                -- Network interfaces table
                CREATE TABLE IF NOT EXISTS interfaces (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    system_id INTEGER REFERENCES systems(id) ON DELETE CASCADE,
                    name TEXT,
                    mac_address TEXT,
                    ip_addresses TEXT,  -- JSON array
                    connected_switch_id INTEGER REFERENCES switches(id),
                    switch_port TEXT,
                    vlan_id INTEGER,
                    vlan_name TEXT,
                    speed_mbps INTEGER,
                    duplex TEXT,
                    mtu INTEGER,
                    is_up INTEGER DEFAULT 1,
                    is_primary INTEGER DEFAULT 0,
                    discovered_via TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    last_seen TEXT
                );

                -- Indexes
                CREATE INDEX IF NOT EXISTS idx_systems_hostname ON systems(hostname);
                CREATE INDEX IF NOT EXISTS idx_systems_primary_ip ON systems(primary_ip);
                CREATE INDEX IF NOT EXISTS idx_systems_type ON systems(system_type);
                CREATE INDEX IF NOT EXISTS idx_systems_status ON systems(status);
                CREATE INDEX IF NOT EXISTS idx_systems_location ON systems(location_id);
                CREATE INDEX IF NOT EXISTS idx_switches_hostname ON switches(hostname);
                CREATE INDEX IF NOT EXISTS idx_switches_ip ON switches(management_ip);
                CREATE INDEX IF NOT EXISTS idx_interfaces_system ON interfaces(system_id);
                CREATE INDEX IF NOT EXISTS idx_interfaces_switch ON interfaces(connected_switch_id);
                CREATE INDEX IF NOT EXISTS idx_interfaces_mac ON interfaces(mac_address);
                CREATE INDEX IF NOT EXISTS idx_locations_datacenter ON locations(datacenter);
                CREATE INDEX IF NOT EXISTS idx_locations_rack ON locations(rack);
            """)
            conn.commit()

    # Location operations
    def create_location(self, location: Location) -> Location:
        with self._get_conn() as conn:
            cursor = conn.execute("""
                INSERT INTO locations (
                    country, state, city, address, datacenter, building,
                    floor, room, rack, rack_unit, latitude, longitude, notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                location.country, location.state, location.city, location.address,
                location.datacenter, location.building, location.floor, location.room,
                location.rack, location.rack_unit, location.latitude, location.longitude,
                location.notes,
            ))
            conn.commit()
            location.id = cursor.lastrowid
            location.created_at = datetime.now()
            location.updated_at = datetime.now()
            return location

    def get_location(self, location_id: int) -> Location | None:
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM locations WHERE id = ?", (location_id,)
            ).fetchone()
            if row:
                return self._row_to_location(row)
            return None

    def update_location(self, location: Location) -> Location:
        with self._get_conn() as conn:
            conn.execute("""
                UPDATE locations SET
                    country = ?, state = ?, city = ?, address = ?,
                    datacenter = ?, building = ?, floor = ?, room = ?,
                    rack = ?, rack_unit = ?, latitude = ?, longitude = ?,
                    notes = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (
                location.country, location.state, location.city, location.address,
                location.datacenter, location.building, location.floor, location.room,
                location.rack, location.rack_unit, location.latitude, location.longitude,
                location.notes, location.id,
            ))
            conn.commit()
            location.updated_at = datetime.now()
            return location

    def delete_location(self, location_id: int) -> bool:
        with self._get_conn() as conn:
            cursor = conn.execute("DELETE FROM locations WHERE id = ?", (location_id,))
            conn.commit()
            return cursor.rowcount > 0

    def list_locations(
        self,
        datacenter: str | None = None,
        country: str | None = None,
    ) -> list[Location]:
        with self._get_conn() as conn:
            query = "SELECT * FROM locations WHERE 1=1"
            params: list[Any] = []

            if datacenter:
                query += " AND datacenter = ?"
                params.append(datacenter)
            if country:
                query += " AND country = ?"
                params.append(country)

            query += " ORDER BY datacenter, rack"
            rows = conn.execute(query, params).fetchall()
            return [self._row_to_location(row) for row in rows]

    def _row_to_location(self, row: sqlite3.Row) -> Location:
        return Location(
            id=row["id"],
            country=row["country"],
            state=row["state"],
            city=row["city"],
            address=row["address"],
            datacenter=row["datacenter"],
            building=row["building"],
            floor=row["floor"],
            room=row["room"],
            rack=row["rack"],
            rack_unit=row["rack_unit"],
            latitude=row["latitude"],
            longitude=row["longitude"],
            notes=row["notes"],
            created_at=datetime.fromisoformat(row["created_at"]) if row["created_at"] else None,
            updated_at=datetime.fromisoformat(row["updated_at"]) if row["updated_at"] else None,
        )

    # Switch operations
    def create_switch(self, switch: Switch) -> Switch:
        with self._get_conn() as conn:
            cursor = conn.execute("""
                INSERT INTO switches (
                    hostname, management_ip, vendor, model, serial_number,
                    firmware_version, platform, capabilities, location_id,
                    total_ports, notes, tags, custom_fields, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                switch.hostname, switch.management_ip, switch.vendor, switch.model,
                switch.serial_number, switch.firmware_version, switch.platform,
                json.dumps(switch.capabilities), switch.location_id,
                switch.total_ports, switch.notes, json.dumps(switch.tags),
                json.dumps(switch.custom_fields),
                switch.last_seen.isoformat() if switch.last_seen else None,
            ))
            conn.commit()
            switch.id = cursor.lastrowid
            switch.created_at = datetime.now()
            switch.updated_at = datetime.now()
            return switch

    def get_switch(self, switch_id: int) -> Switch | None:
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM switches WHERE id = ?", (switch_id,)
            ).fetchone()
            if row:
                return self._row_to_switch(row)
            return None

    def get_switch_by_hostname(self, hostname: str) -> Switch | None:
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM switches WHERE hostname = ?", (hostname,)
            ).fetchone()
            if row:
                return self._row_to_switch(row)
            return None

    def get_switch_by_ip(self, ip: str) -> Switch | None:
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM switches WHERE management_ip = ?", (ip,)
            ).fetchone()
            if row:
                return self._row_to_switch(row)
            return None

    def update_switch(self, switch: Switch) -> Switch:
        with self._get_conn() as conn:
            conn.execute("""
                UPDATE switches SET
                    hostname = ?, management_ip = ?, vendor = ?, model = ?,
                    serial_number = ?, firmware_version = ?, platform = ?,
                    capabilities = ?, location_id = ?, total_ports = ?,
                    notes = ?, tags = ?, custom_fields = ?, last_seen = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (
                switch.hostname, switch.management_ip, switch.vendor, switch.model,
                switch.serial_number, switch.firmware_version, switch.platform,
                json.dumps(switch.capabilities), switch.location_id,
                switch.total_ports, switch.notes, json.dumps(switch.tags),
                json.dumps(switch.custom_fields),
                switch.last_seen.isoformat() if switch.last_seen else None,
                switch.id,
            ))
            conn.commit()
            switch.updated_at = datetime.now()
            return switch

    def delete_switch(self, switch_id: int) -> bool:
        with self._get_conn() as conn:
            cursor = conn.execute("DELETE FROM switches WHERE id = ?", (switch_id,))
            conn.commit()
            return cursor.rowcount > 0

    def list_switches(
        self,
        location_id: int | None = None,
        vendor: str | None = None,
    ) -> list[Switch]:
        with self._get_conn() as conn:
            query = "SELECT * FROM switches WHERE 1=1"
            params: list[Any] = []

            if location_id:
                query += " AND location_id = ?"
                params.append(location_id)
            if vendor:
                query += " AND vendor = ?"
                params.append(vendor)

            query += " ORDER BY hostname"
            rows = conn.execute(query, params).fetchall()
            return [self._row_to_switch(row) for row in rows]

    def _row_to_switch(self, row: sqlite3.Row) -> Switch:
        return Switch(
            id=row["id"],
            hostname=row["hostname"],
            management_ip=row["management_ip"],
            vendor=row["vendor"],
            model=row["model"],
            serial_number=row["serial_number"],
            firmware_version=row["firmware_version"],
            platform=row["platform"],
            capabilities=json.loads(row["capabilities"]) if row["capabilities"] else [],
            location_id=row["location_id"],
            total_ports=row["total_ports"],
            notes=row["notes"],
            tags=json.loads(row["tags"]) if row["tags"] else [],
            custom_fields=json.loads(row["custom_fields"]) if row["custom_fields"] else {},
            created_at=datetime.fromisoformat(row["created_at"]) if row["created_at"] else None,
            updated_at=datetime.fromisoformat(row["updated_at"]) if row["updated_at"] else None,
            last_seen=datetime.fromisoformat(row["last_seen"]) if row["last_seen"] else None,
        )

    # System operations
    def create_system(self, system: System) -> System:
        with self._get_conn() as conn:
            cursor = conn.execute("""
                INSERT INTO systems (
                    hostname, fqdn, system_type, status, primary_ip, primary_mac,
                    vendor, model, serial_number, os_name, os_version, kernel_version,
                    cpu_cores, ram_gb, disk_gb, asn, as_name, ip_country, ip_city,
                    ip_org, location_id, agent_version, agent_last_checkin,
                    notes, tags, custom_fields, last_seen, discovered_at, discovered_via
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                system.hostname, system.fqdn, system.system_type.value, system.status.value,
                system.primary_ip, system.primary_mac, system.vendor, system.model,
                system.serial_number, system.os_name, system.os_version, system.kernel_version,
                system.cpu_cores, system.ram_gb, system.disk_gb, system.asn, system.as_name,
                system.ip_country, system.ip_city, system.ip_org, system.location_id,
                system.agent_version,
                system.agent_last_checkin.isoformat() if system.agent_last_checkin else None,
                system.notes, json.dumps(system.tags), json.dumps(system.custom_fields),
                system.last_seen.isoformat() if system.last_seen else None,
                system.discovered_at.isoformat() if system.discovered_at else None,
                system.discovered_via,
            ))
            conn.commit()
            system.id = cursor.lastrowid
            system.created_at = datetime.now()
            system.updated_at = datetime.now()

            # Create interfaces
            for iface in system.interfaces:
                iface.system_id = system.id
                self.create_interface(iface)

            return system

    def get_system(self, system_id: int) -> System | None:
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM systems WHERE id = ?", (system_id,)
            ).fetchone()
            if row:
                system = self._row_to_system(row)
                system.interfaces = self.get_interfaces_for_system(system_id)
                return system
            return None

    def get_system_by_hostname(self, hostname: str) -> System | None:
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM systems WHERE hostname = ? OR fqdn = ?",
                (hostname, hostname)
            ).fetchone()
            if row:
                system = self._row_to_system(row)
                system.interfaces = self.get_interfaces_for_system(system.id)
                return system
            return None

    def get_system_by_ip(self, ip: str) -> System | None:
        with self._get_conn() as conn:
            # Check primary IP
            row = conn.execute(
                "SELECT * FROM systems WHERE primary_ip = ?", (ip,)
            ).fetchone()
            if row:
                system = self._row_to_system(row)
                system.interfaces = self.get_interfaces_for_system(system.id)
                return system

            # Check interfaces
            iface_row = conn.execute(
                "SELECT system_id FROM interfaces WHERE ip_addresses LIKE ?",
                (f'%"{ip}"%',)
            ).fetchone()
            if iface_row:
                return self.get_system(iface_row["system_id"])

            return None

    def update_system(self, system: System) -> System:
        with self._get_conn() as conn:
            conn.execute("""
                UPDATE systems SET
                    hostname = ?, fqdn = ?, system_type = ?, status = ?,
                    primary_ip = ?, primary_mac = ?, vendor = ?, model = ?,
                    serial_number = ?, os_name = ?, os_version = ?, kernel_version = ?,
                    cpu_cores = ?, ram_gb = ?, disk_gb = ?, asn = ?, as_name = ?,
                    ip_country = ?, ip_city = ?, ip_org = ?, location_id = ?,
                    agent_version = ?, agent_last_checkin = ?, notes = ?, tags = ?,
                    custom_fields = ?, last_seen = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (
                system.hostname, system.fqdn, system.system_type.value, system.status.value,
                system.primary_ip, system.primary_mac, system.vendor, system.model,
                system.serial_number, system.os_name, system.os_version, system.kernel_version,
                system.cpu_cores, system.ram_gb, system.disk_gb, system.asn, system.as_name,
                system.ip_country, system.ip_city, system.ip_org, system.location_id,
                system.agent_version,
                system.agent_last_checkin.isoformat() if system.agent_last_checkin else None,
                system.notes, json.dumps(system.tags), json.dumps(system.custom_fields),
                system.last_seen.isoformat() if system.last_seen else None,
                system.id,
            ))
            conn.commit()
            system.updated_at = datetime.now()
            return system

    def delete_system(self, system_id: int) -> bool:
        with self._get_conn() as conn:
            cursor = conn.execute("DELETE FROM systems WHERE id = ?", (system_id,))
            conn.commit()
            return cursor.rowcount > 0

    def list_systems(
        self,
        system_type: SystemType | None = None,
        status: SystemStatus | None = None,
        location_id: int | None = None,
        switch_id: int | None = None,
        tag: str | None = None,
    ) -> list[System]:
        with self._get_conn() as conn:
            if switch_id:
                # Get systems connected to this switch
                query = """
                    SELECT DISTINCT s.* FROM systems s
                    JOIN interfaces i ON i.system_id = s.id
                    WHERE i.connected_switch_id = ?
                """
                params: list[Any] = [switch_id]
            else:
                query = "SELECT * FROM systems WHERE 1=1"
                params = []

            if system_type:
                query += " AND system_type = ?"
                params.append(system_type.value)
            if status:
                query += " AND status = ?"
                params.append(status.value)
            if location_id:
                query += " AND location_id = ?"
                params.append(location_id)
            if tag:
                query += " AND tags LIKE ?"
                params.append(f'%"{tag}"%')

            query += " ORDER BY hostname"
            rows = conn.execute(query, params).fetchall()

            systems = []
            for row in rows:
                system = self._row_to_system(row)
                system.interfaces = self.get_interfaces_for_system(system.id)
                systems.append(system)
            return systems

    def _row_to_system(self, row: sqlite3.Row) -> System:
        return System(
            id=row["id"],
            hostname=row["hostname"],
            fqdn=row["fqdn"],
            system_type=SystemType(row["system_type"]) if row["system_type"] else SystemType.UNKNOWN,
            status=SystemStatus(row["status"]) if row["status"] else SystemStatus.UNKNOWN,
            primary_ip=row["primary_ip"],
            primary_mac=row["primary_mac"],
            vendor=row["vendor"],
            model=row["model"],
            serial_number=row["serial_number"],
            os_name=row["os_name"],
            os_version=row["os_version"],
            kernel_version=row["kernel_version"],
            cpu_cores=row["cpu_cores"],
            ram_gb=row["ram_gb"],
            disk_gb=row["disk_gb"],
            asn=row["asn"],
            as_name=row["as_name"],
            ip_country=row["ip_country"],
            ip_city=row["ip_city"],
            ip_org=row["ip_org"],
            location_id=row["location_id"],
            agent_version=row["agent_version"],
            agent_last_checkin=datetime.fromisoformat(row["agent_last_checkin"]) if row["agent_last_checkin"] else None,
            notes=row["notes"],
            tags=json.loads(row["tags"]) if row["tags"] else [],
            custom_fields=json.loads(row["custom_fields"]) if row["custom_fields"] else {},
            created_at=datetime.fromisoformat(row["created_at"]) if row["created_at"] else None,
            updated_at=datetime.fromisoformat(row["updated_at"]) if row["updated_at"] else None,
            last_seen=datetime.fromisoformat(row["last_seen"]) if row["last_seen"] else None,
            discovered_at=datetime.fromisoformat(row["discovered_at"]) if row["discovered_at"] else None,
            discovered_via=row["discovered_via"],
        )

    # Interface operations
    def create_interface(self, interface: NetworkInterface) -> NetworkInterface:
        with self._get_conn() as conn:
            cursor = conn.execute("""
                INSERT INTO interfaces (
                    system_id, name, mac_address, ip_addresses, connected_switch_id,
                    switch_port, vlan_id, vlan_name, speed_mbps, duplex, mtu,
                    is_up, is_primary, discovered_via, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                interface.system_id, interface.name, interface.mac_address,
                json.dumps(interface.ip_addresses), interface.connected_switch_id,
                interface.switch_port, interface.vlan_id, interface.vlan_name,
                interface.speed_mbps, interface.duplex, interface.mtu,
                1 if interface.is_up else 0, 1 if interface.is_primary else 0,
                interface.discovered_via,
                interface.last_seen.isoformat() if interface.last_seen else None,
            ))
            conn.commit()
            interface.id = cursor.lastrowid
            interface.created_at = datetime.now()
            interface.updated_at = datetime.now()
            return interface

    def get_interfaces_for_system(self, system_id: int) -> list[NetworkInterface]:
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM interfaces WHERE system_id = ? ORDER BY name",
                (system_id,)
            ).fetchall()
            return [self._row_to_interface(row) for row in rows]

    def get_interfaces_on_switch(self, switch_id: int) -> list[NetworkInterface]:
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM interfaces WHERE connected_switch_id = ? ORDER BY switch_port",
                (switch_id,)
            ).fetchall()
            return [self._row_to_interface(row) for row in rows]

    def update_interface(self, interface: NetworkInterface) -> NetworkInterface:
        with self._get_conn() as conn:
            conn.execute("""
                UPDATE interfaces SET
                    name = ?, mac_address = ?, ip_addresses = ?, connected_switch_id = ?,
                    switch_port = ?, vlan_id = ?, vlan_name = ?, speed_mbps = ?,
                    duplex = ?, mtu = ?, is_up = ?, is_primary = ?, discovered_via = ?,
                    last_seen = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (
                interface.name, interface.mac_address, json.dumps(interface.ip_addresses),
                interface.connected_switch_id, interface.switch_port, interface.vlan_id,
                interface.vlan_name, interface.speed_mbps, interface.duplex, interface.mtu,
                1 if interface.is_up else 0, 1 if interface.is_primary else 0,
                interface.discovered_via,
                interface.last_seen.isoformat() if interface.last_seen else None,
                interface.id,
            ))
            conn.commit()
            interface.updated_at = datetime.now()
            return interface

    def delete_interface(self, interface_id: int) -> bool:
        with self._get_conn() as conn:
            cursor = conn.execute("DELETE FROM interfaces WHERE id = ?", (interface_id,))
            conn.commit()
            return cursor.rowcount > 0

    def _row_to_interface(self, row: sqlite3.Row) -> NetworkInterface:
        return NetworkInterface(
            id=row["id"],
            system_id=row["system_id"],
            name=row["name"],
            mac_address=row["mac_address"],
            ip_addresses=json.loads(row["ip_addresses"]) if row["ip_addresses"] else [],
            connected_switch_id=row["connected_switch_id"],
            switch_port=row["switch_port"],
            vlan_id=row["vlan_id"],
            vlan_name=row["vlan_name"],
            speed_mbps=row["speed_mbps"],
            duplex=row["duplex"],
            mtu=row["mtu"],
            is_up=bool(row["is_up"]),
            is_primary=bool(row["is_primary"]),
            discovered_via=row["discovered_via"],
            created_at=datetime.fromisoformat(row["created_at"]) if row["created_at"] else None,
            updated_at=datetime.fromisoformat(row["updated_at"]) if row["updated_at"] else None,
            last_seen=datetime.fromisoformat(row["last_seen"]) if row["last_seen"] else None,
        )

    # Search operations
    def search_systems(self, query: str) -> list[System]:
        with self._get_conn() as conn:
            search = f"%{query}%"
            rows = conn.execute("""
                SELECT * FROM systems
                WHERE hostname LIKE ?
                   OR fqdn LIKE ?
                   OR primary_ip LIKE ?
                   OR notes LIKE ?
                   OR tags LIKE ?
                ORDER BY hostname
            """, (search, search, search, search, search)).fetchall()

            systems = []
            for row in rows:
                system = self._row_to_system(row)
                system.interfaces = self.get_interfaces_for_system(system.id)
                systems.append(system)
            return systems

    def get_systems_on_switch(self, switch_id: int) -> list[System]:
        return self.list_systems(switch_id=switch_id)

    def get_systems_in_rack(self, rack: str, datacenter: str | None = None) -> list[System]:
        with self._get_conn() as conn:
            query = """
                SELECT s.* FROM systems s
                JOIN locations l ON l.id = s.location_id
                WHERE l.rack = ?
            """
            params: list[Any] = [rack]

            if datacenter:
                query += " AND l.datacenter = ?"
                params.append(datacenter)

            query += " ORDER BY l.rack_unit, s.hostname"
            rows = conn.execute(query, params).fetchall()

            systems = []
            for row in rows:
                system = self._row_to_system(row)
                system.interfaces = self.get_interfaces_for_system(system.id)
                systems.append(system)
            return systems


class PostgreSQLDatabase(Database):
    """PostgreSQL implementation for enterprise deployments.

    Supports AWS RDS PostgreSQL and Aurora PostgreSQL.
    """

    def __init__(self, connection_string: str):
        """Initialize with connection string.

        Args:
            connection_string: PostgreSQL connection string
                Format: postgresql://user:password@host:port/database
                Or: postgresql://user:password@host/database?sslmode=require
        """
        self.connection_string = connection_string
        self._conn = None

        # Parse connection string
        parsed = urlparse(connection_string)
        self.host = parsed.hostname
        self.port = parsed.port or 5432
        self.database = parsed.path.lstrip("/")
        self.user = parsed.username
        self.password = parsed.password

        # Check for psycopg2
        try:
            import psycopg2
            self._psycopg2 = psycopg2
        except ImportError:
            raise ImportError(
                "psycopg2 is required for PostgreSQL support. "
                "Install with: pip install psycopg2-binary"
            )

    def _get_conn(self):
        """Get database connection."""
        if self._conn is None or self._conn.closed:
            self._conn = self._psycopg2.connect(self.connection_string)
        return self._conn

    def close(self) -> None:
        if self._conn and not self._conn.closed:
            self._conn.close()
            self._conn = None

    def initialize(self) -> None:
        """Create database schema."""
        conn = self._get_conn()
        with conn.cursor() as cur:
            cur.execute("""
                -- Locations table
                CREATE TABLE IF NOT EXISTS locations (
                    id SERIAL PRIMARY KEY,
                    country TEXT,
                    state TEXT,
                    city TEXT,
                    address TEXT,
                    datacenter TEXT,
                    building TEXT,
                    floor TEXT,
                    room TEXT,
                    rack TEXT,
                    rack_unit INTEGER,
                    latitude DOUBLE PRECISION,
                    longitude DOUBLE PRECISION,
                    notes TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                -- Switches table
                CREATE TABLE IF NOT EXISTS switches (
                    id SERIAL PRIMARY KEY,
                    hostname TEXT UNIQUE,
                    management_ip TEXT,
                    vendor TEXT,
                    model TEXT,
                    serial_number TEXT,
                    firmware_version TEXT,
                    platform TEXT,
                    capabilities JSONB DEFAULT '[]',
                    location_id INTEGER REFERENCES locations(id),
                    total_ports INTEGER,
                    notes TEXT,
                    tags JSONB DEFAULT '[]',
                    custom_fields JSONB DEFAULT '{}',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP
                );

                -- Systems table
                CREATE TABLE IF NOT EXISTS systems (
                    id SERIAL PRIMARY KEY,
                    hostname TEXT,
                    fqdn TEXT,
                    system_type TEXT DEFAULT 'unknown',
                    status TEXT DEFAULT 'unknown',
                    primary_ip TEXT,
                    primary_mac TEXT,
                    vendor TEXT,
                    model TEXT,
                    serial_number TEXT,
                    os_name TEXT,
                    os_version TEXT,
                    kernel_version TEXT,
                    cpu_cores INTEGER,
                    ram_gb DOUBLE PRECISION,
                    disk_gb DOUBLE PRECISION,
                    asn INTEGER,
                    as_name TEXT,
                    ip_country TEXT,
                    ip_city TEXT,
                    ip_org TEXT,
                    location_id INTEGER REFERENCES locations(id),
                    agent_version TEXT,
                    agent_last_checkin TIMESTAMP,
                    notes TEXT,
                    tags JSONB DEFAULT '[]',
                    custom_fields JSONB DEFAULT '{}',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP,
                    discovered_at TIMESTAMP,
                    discovered_via TEXT
                );

                -- Network interfaces table
                CREATE TABLE IF NOT EXISTS interfaces (
                    id SERIAL PRIMARY KEY,
                    system_id INTEGER REFERENCES systems(id) ON DELETE CASCADE,
                    name TEXT,
                    mac_address TEXT,
                    ip_addresses JSONB DEFAULT '[]',
                    connected_switch_id INTEGER REFERENCES switches(id),
                    switch_port TEXT,
                    vlan_id INTEGER,
                    vlan_name TEXT,
                    speed_mbps INTEGER,
                    duplex TEXT,
                    mtu INTEGER,
                    is_up BOOLEAN DEFAULT TRUE,
                    is_primary BOOLEAN DEFAULT FALSE,
                    discovered_via TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP
                );

                -- Indexes
                CREATE INDEX IF NOT EXISTS idx_systems_hostname ON systems(hostname);
                CREATE INDEX IF NOT EXISTS idx_systems_primary_ip ON systems(primary_ip);
                CREATE INDEX IF NOT EXISTS idx_systems_type ON systems(system_type);
                CREATE INDEX IF NOT EXISTS idx_systems_status ON systems(status);
                CREATE INDEX IF NOT EXISTS idx_systems_location ON systems(location_id);
                CREATE INDEX IF NOT EXISTS idx_switches_hostname ON switches(hostname);
                CREATE INDEX IF NOT EXISTS idx_switches_ip ON switches(management_ip);
                CREATE INDEX IF NOT EXISTS idx_interfaces_system ON interfaces(system_id);
                CREATE INDEX IF NOT EXISTS idx_interfaces_switch ON interfaces(connected_switch_id);
                CREATE INDEX IF NOT EXISTS idx_interfaces_mac ON interfaces(mac_address);
                CREATE INDEX IF NOT EXISTS idx_locations_datacenter ON locations(datacenter);
                CREATE INDEX IF NOT EXISTS idx_locations_rack ON locations(rack);

                -- Full text search indexes (PostgreSQL specific)
                CREATE INDEX IF NOT EXISTS idx_systems_fts ON systems
                    USING gin(to_tsvector('english', coalesce(hostname, '') || ' ' || coalesce(fqdn, '') || ' ' || coalesce(notes, '')));
            """)
            conn.commit()

    # The PostgreSQL implementation methods follow the same pattern as SQLite
    # but use psycopg2 syntax and native JSONB support.
    # For brevity, implementing the key methods - others follow the same pattern.

    def create_location(self, location: Location) -> Location:
        conn = self._get_conn()
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO locations (
                    country, state, city, address, datacenter, building,
                    floor, room, rack, rack_unit, latitude, longitude, notes
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id, created_at, updated_at
            """, (
                location.country, location.state, location.city, location.address,
                location.datacenter, location.building, location.floor, location.room,
                location.rack, location.rack_unit, location.latitude, location.longitude,
                location.notes,
            ))
            row = cur.fetchone()
            location.id = row[0]
            location.created_at = row[1]
            location.updated_at = row[2]
            conn.commit()
            return location

    def get_location(self, location_id: int) -> Location | None:
        conn = self._get_conn()
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM locations WHERE id = %s", (location_id,))
            row = cur.fetchone()
            if row:
                return self._row_to_location_pg(row, cur.description)
            return None

    def update_location(self, location: Location) -> Location:
        conn = self._get_conn()
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE locations SET
                    country = %s, state = %s, city = %s, address = %s,
                    datacenter = %s, building = %s, floor = %s, room = %s,
                    rack = %s, rack_unit = %s, latitude = %s, longitude = %s,
                    notes = %s, updated_at = CURRENT_TIMESTAMP
                WHERE id = %s
                RETURNING updated_at
            """, (
                location.country, location.state, location.city, location.address,
                location.datacenter, location.building, location.floor, location.room,
                location.rack, location.rack_unit, location.latitude, location.longitude,
                location.notes, location.id,
            ))
            row = cur.fetchone()
            location.updated_at = row[0]
            conn.commit()
            return location

    def delete_location(self, location_id: int) -> bool:
        conn = self._get_conn()
        with conn.cursor() as cur:
            cur.execute("DELETE FROM locations WHERE id = %s", (location_id,))
            deleted = cur.rowcount > 0
            conn.commit()
            return deleted

    def list_locations(
        self,
        datacenter: str | None = None,
        country: str | None = None,
    ) -> list[Location]:
        conn = self._get_conn()
        with conn.cursor() as cur:
            query = "SELECT * FROM locations WHERE 1=1"
            params: list[Any] = []

            if datacenter:
                query += " AND datacenter = %s"
                params.append(datacenter)
            if country:
                query += " AND country = %s"
                params.append(country)

            query += " ORDER BY datacenter, rack"
            cur.execute(query, params)
            rows = cur.fetchall()
            return [self._row_to_location_pg(row, cur.description) for row in rows]

    def _row_to_location_pg(self, row: tuple, description) -> Location:
        cols = [d[0] for d in description]
        data = dict(zip(cols, row))
        return Location(
            id=data["id"],
            country=data["country"],
            state=data["state"],
            city=data["city"],
            address=data["address"],
            datacenter=data["datacenter"],
            building=data["building"],
            floor=data["floor"],
            room=data["room"],
            rack=data["rack"],
            rack_unit=data["rack_unit"],
            latitude=data["latitude"],
            longitude=data["longitude"],
            notes=data["notes"],
            created_at=data["created_at"],
            updated_at=data["updated_at"],
        )

    # Switch operations (PostgreSQL)
    def create_switch(self, switch: Switch) -> Switch:
        conn = self._get_conn()
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO switches (
                    hostname, management_ip, vendor, model, serial_number,
                    firmware_version, platform, capabilities, location_id,
                    total_ports, notes, tags, custom_fields, last_seen
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id, created_at, updated_at
            """, (
                switch.hostname, switch.management_ip, switch.vendor, switch.model,
                switch.serial_number, switch.firmware_version, switch.platform,
                json.dumps(switch.capabilities), switch.location_id,
                switch.total_ports, switch.notes, json.dumps(switch.tags),
                json.dumps(switch.custom_fields), switch.last_seen,
            ))
            row = cur.fetchone()
            switch.id = row[0]
            switch.created_at = row[1]
            switch.updated_at = row[2]
            conn.commit()
            return switch

    def get_switch(self, switch_id: int) -> Switch | None:
        conn = self._get_conn()
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM switches WHERE id = %s", (switch_id,))
            row = cur.fetchone()
            if row:
                return self._row_to_switch_pg(row, cur.description)
            return None

    def get_switch_by_hostname(self, hostname: str) -> Switch | None:
        conn = self._get_conn()
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM switches WHERE hostname = %s", (hostname,))
            row = cur.fetchone()
            if row:
                return self._row_to_switch_pg(row, cur.description)
            return None

    def get_switch_by_ip(self, ip: str) -> Switch | None:
        conn = self._get_conn()
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM switches WHERE management_ip = %s", (ip,))
            row = cur.fetchone()
            if row:
                return self._row_to_switch_pg(row, cur.description)
            return None

    def update_switch(self, switch: Switch) -> Switch:
        conn = self._get_conn()
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE switches SET
                    hostname = %s, management_ip = %s, vendor = %s, model = %s,
                    serial_number = %s, firmware_version = %s, platform = %s,
                    capabilities = %s, location_id = %s, total_ports = %s,
                    notes = %s, tags = %s, custom_fields = %s, last_seen = %s,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = %s
                RETURNING updated_at
            """, (
                switch.hostname, switch.management_ip, switch.vendor, switch.model,
                switch.serial_number, switch.firmware_version, switch.platform,
                json.dumps(switch.capabilities), switch.location_id,
                switch.total_ports, switch.notes, json.dumps(switch.tags),
                json.dumps(switch.custom_fields), switch.last_seen, switch.id,
            ))
            row = cur.fetchone()
            switch.updated_at = row[0]
            conn.commit()
            return switch

    def delete_switch(self, switch_id: int) -> bool:
        conn = self._get_conn()
        with conn.cursor() as cur:
            cur.execute("DELETE FROM switches WHERE id = %s", (switch_id,))
            deleted = cur.rowcount > 0
            conn.commit()
            return deleted

    def list_switches(
        self,
        location_id: int | None = None,
        vendor: str | None = None,
    ) -> list[Switch]:
        conn = self._get_conn()
        with conn.cursor() as cur:
            query = "SELECT * FROM switches WHERE 1=1"
            params: list[Any] = []

            if location_id:
                query += " AND location_id = %s"
                params.append(location_id)
            if vendor:
                query += " AND vendor = %s"
                params.append(vendor)

            query += " ORDER BY hostname"
            cur.execute(query, params)
            rows = cur.fetchall()
            return [self._row_to_switch_pg(row, cur.description) for row in rows]

    def _row_to_switch_pg(self, row: tuple, description) -> Switch:
        cols = [d[0] for d in description]
        data = dict(zip(cols, row))
        return Switch(
            id=data["id"],
            hostname=data["hostname"],
            management_ip=data["management_ip"],
            vendor=data["vendor"],
            model=data["model"],
            serial_number=data["serial_number"],
            firmware_version=data["firmware_version"],
            platform=data["platform"],
            capabilities=data["capabilities"] if data["capabilities"] else [],
            location_id=data["location_id"],
            total_ports=data["total_ports"],
            notes=data["notes"],
            tags=data["tags"] if data["tags"] else [],
            custom_fields=data["custom_fields"] if data["custom_fields"] else {},
            created_at=data["created_at"],
            updated_at=data["updated_at"],
            last_seen=data["last_seen"],
        )

    # System operations (PostgreSQL)
    def create_system(self, system: System) -> System:
        conn = self._get_conn()
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO systems (
                    hostname, fqdn, system_type, status, primary_ip, primary_mac,
                    vendor, model, serial_number, os_name, os_version, kernel_version,
                    cpu_cores, ram_gb, disk_gb, asn, as_name, ip_country, ip_city,
                    ip_org, location_id, agent_version, agent_last_checkin,
                    notes, tags, custom_fields, last_seen, discovered_at, discovered_via
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id, created_at, updated_at
            """, (
                system.hostname, system.fqdn, system.system_type.value, system.status.value,
                system.primary_ip, system.primary_mac, system.vendor, system.model,
                system.serial_number, system.os_name, system.os_version, system.kernel_version,
                system.cpu_cores, system.ram_gb, system.disk_gb, system.asn, system.as_name,
                system.ip_country, system.ip_city, system.ip_org, system.location_id,
                system.agent_version, system.agent_last_checkin, system.notes,
                json.dumps(system.tags), json.dumps(system.custom_fields),
                system.last_seen, system.discovered_at, system.discovered_via,
            ))
            row = cur.fetchone()
            system.id = row[0]
            system.created_at = row[1]
            system.updated_at = row[2]
            conn.commit()

            # Create interfaces
            for iface in system.interfaces:
                iface.system_id = system.id
                self.create_interface(iface)

            return system

    def get_system(self, system_id: int) -> System | None:
        conn = self._get_conn()
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM systems WHERE id = %s", (system_id,))
            row = cur.fetchone()
            if row:
                system = self._row_to_system_pg(row, cur.description)
                system.interfaces = self.get_interfaces_for_system(system_id)
                return system
            return None

    def get_system_by_hostname(self, hostname: str) -> System | None:
        conn = self._get_conn()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM systems WHERE hostname = %s OR fqdn = %s",
                (hostname, hostname)
            )
            row = cur.fetchone()
            if row:
                system = self._row_to_system_pg(row, cur.description)
                system.interfaces = self.get_interfaces_for_system(system.id)
                return system
            return None

    def get_system_by_ip(self, ip: str) -> System | None:
        conn = self._get_conn()
        with conn.cursor() as cur:
            # Check primary IP
            cur.execute("SELECT * FROM systems WHERE primary_ip = %s", (ip,))
            row = cur.fetchone()
            if row:
                system = self._row_to_system_pg(row, cur.description)
                system.interfaces = self.get_interfaces_for_system(system.id)
                return system

            # Check interfaces using JSONB containment
            cur.execute(
                "SELECT system_id FROM interfaces WHERE ip_addresses @> %s::jsonb",
                (json.dumps([ip]),)
            )
            iface_row = cur.fetchone()
            if iface_row:
                return self.get_system(iface_row[0])

            return None

    def update_system(self, system: System) -> System:
        conn = self._get_conn()
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE systems SET
                    hostname = %s, fqdn = %s, system_type = %s, status = %s,
                    primary_ip = %s, primary_mac = %s, vendor = %s, model = %s,
                    serial_number = %s, os_name = %s, os_version = %s, kernel_version = %s,
                    cpu_cores = %s, ram_gb = %s, disk_gb = %s, asn = %s, as_name = %s,
                    ip_country = %s, ip_city = %s, ip_org = %s, location_id = %s,
                    agent_version = %s, agent_last_checkin = %s, notes = %s, tags = %s,
                    custom_fields = %s, last_seen = %s, updated_at = CURRENT_TIMESTAMP
                WHERE id = %s
                RETURNING updated_at
            """, (
                system.hostname, system.fqdn, system.system_type.value, system.status.value,
                system.primary_ip, system.primary_mac, system.vendor, system.model,
                system.serial_number, system.os_name, system.os_version, system.kernel_version,
                system.cpu_cores, system.ram_gb, system.disk_gb, system.asn, system.as_name,
                system.ip_country, system.ip_city, system.ip_org, system.location_id,
                system.agent_version, system.agent_last_checkin, system.notes,
                json.dumps(system.tags), json.dumps(system.custom_fields),
                system.last_seen, system.id,
            ))
            row = cur.fetchone()
            system.updated_at = row[0]
            conn.commit()
            return system

    def delete_system(self, system_id: int) -> bool:
        conn = self._get_conn()
        with conn.cursor() as cur:
            cur.execute("DELETE FROM systems WHERE id = %s", (system_id,))
            deleted = cur.rowcount > 0
            conn.commit()
            return deleted

    def list_systems(
        self,
        system_type: SystemType | None = None,
        status: SystemStatus | None = None,
        location_id: int | None = None,
        switch_id: int | None = None,
        tag: str | None = None,
    ) -> list[System]:
        conn = self._get_conn()
        with conn.cursor() as cur:
            if switch_id:
                query = """
                    SELECT DISTINCT s.* FROM systems s
                    JOIN interfaces i ON i.system_id = s.id
                    WHERE i.connected_switch_id = %s
                """
                params: list[Any] = [switch_id]
            else:
                query = "SELECT * FROM systems WHERE 1=1"
                params = []

            if system_type:
                query += " AND system_type = %s"
                params.append(system_type.value)
            if status:
                query += " AND status = %s"
                params.append(status.value)
            if location_id:
                query += " AND location_id = %s"
                params.append(location_id)
            if tag:
                query += " AND tags @> %s::jsonb"
                params.append(json.dumps([tag]))

            query += " ORDER BY hostname"
            cur.execute(query, params)
            rows = cur.fetchall()

            systems = []
            for row in rows:
                system = self._row_to_system_pg(row, cur.description)
                system.interfaces = self.get_interfaces_for_system(system.id)
                systems.append(system)
            return systems

    def _row_to_system_pg(self, row: tuple, description) -> System:
        cols = [d[0] for d in description]
        data = dict(zip(cols, row))
        return System(
            id=data["id"],
            hostname=data["hostname"],
            fqdn=data["fqdn"],
            system_type=SystemType(data["system_type"]) if data["system_type"] else SystemType.UNKNOWN,
            status=SystemStatus(data["status"]) if data["status"] else SystemStatus.UNKNOWN,
            primary_ip=data["primary_ip"],
            primary_mac=data["primary_mac"],
            vendor=data["vendor"],
            model=data["model"],
            serial_number=data["serial_number"],
            os_name=data["os_name"],
            os_version=data["os_version"],
            kernel_version=data["kernel_version"],
            cpu_cores=data["cpu_cores"],
            ram_gb=data["ram_gb"],
            disk_gb=data["disk_gb"],
            asn=data["asn"],
            as_name=data["as_name"],
            ip_country=data["ip_country"],
            ip_city=data["ip_city"],
            ip_org=data["ip_org"],
            location_id=data["location_id"],
            agent_version=data["agent_version"],
            agent_last_checkin=data["agent_last_checkin"],
            notes=data["notes"],
            tags=data["tags"] if data["tags"] else [],
            custom_fields=data["custom_fields"] if data["custom_fields"] else {},
            created_at=data["created_at"],
            updated_at=data["updated_at"],
            last_seen=data["last_seen"],
            discovered_at=data["discovered_at"],
            discovered_via=data["discovered_via"],
        )

    # Interface operations (PostgreSQL)
    def create_interface(self, interface: NetworkInterface) -> NetworkInterface:
        conn = self._get_conn()
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO interfaces (
                    system_id, name, mac_address, ip_addresses, connected_switch_id,
                    switch_port, vlan_id, vlan_name, speed_mbps, duplex, mtu,
                    is_up, is_primary, discovered_via, last_seen
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id, created_at, updated_at
            """, (
                interface.system_id, interface.name, interface.mac_address,
                json.dumps(interface.ip_addresses), interface.connected_switch_id,
                interface.switch_port, interface.vlan_id, interface.vlan_name,
                interface.speed_mbps, interface.duplex, interface.mtu,
                interface.is_up, interface.is_primary, interface.discovered_via,
                interface.last_seen,
            ))
            row = cur.fetchone()
            interface.id = row[0]
            interface.created_at = row[1]
            interface.updated_at = row[2]
            conn.commit()
            return interface

    def get_interfaces_for_system(self, system_id: int) -> list[NetworkInterface]:
        conn = self._get_conn()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM interfaces WHERE system_id = %s ORDER BY name",
                (system_id,)
            )
            rows = cur.fetchall()
            return [self._row_to_interface_pg(row, cur.description) for row in rows]

    def get_interfaces_on_switch(self, switch_id: int) -> list[NetworkInterface]:
        conn = self._get_conn()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM interfaces WHERE connected_switch_id = %s ORDER BY switch_port",
                (switch_id,)
            )
            rows = cur.fetchall()
            return [self._row_to_interface_pg(row, cur.description) for row in rows]

    def update_interface(self, interface: NetworkInterface) -> NetworkInterface:
        conn = self._get_conn()
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE interfaces SET
                    name = %s, mac_address = %s, ip_addresses = %s, connected_switch_id = %s,
                    switch_port = %s, vlan_id = %s, vlan_name = %s, speed_mbps = %s,
                    duplex = %s, mtu = %s, is_up = %s, is_primary = %s, discovered_via = %s,
                    last_seen = %s, updated_at = CURRENT_TIMESTAMP
                WHERE id = %s
                RETURNING updated_at
            """, (
                interface.name, interface.mac_address, json.dumps(interface.ip_addresses),
                interface.connected_switch_id, interface.switch_port, interface.vlan_id,
                interface.vlan_name, interface.speed_mbps, interface.duplex, interface.mtu,
                interface.is_up, interface.is_primary, interface.discovered_via,
                interface.last_seen, interface.id,
            ))
            row = cur.fetchone()
            interface.updated_at = row[0]
            conn.commit()
            return interface

    def delete_interface(self, interface_id: int) -> bool:
        conn = self._get_conn()
        with conn.cursor() as cur:
            cur.execute("DELETE FROM interfaces WHERE id = %s", (interface_id,))
            deleted = cur.rowcount > 0
            conn.commit()
            return deleted

    def _row_to_interface_pg(self, row: tuple, description) -> NetworkInterface:
        cols = [d[0] for d in description]
        data = dict(zip(cols, row))
        return NetworkInterface(
            id=data["id"],
            system_id=data["system_id"],
            name=data["name"],
            mac_address=data["mac_address"],
            ip_addresses=data["ip_addresses"] if data["ip_addresses"] else [],
            connected_switch_id=data["connected_switch_id"],
            switch_port=data["switch_port"],
            vlan_id=data["vlan_id"],
            vlan_name=data["vlan_name"],
            speed_mbps=data["speed_mbps"],
            duplex=data["duplex"],
            mtu=data["mtu"],
            is_up=data["is_up"],
            is_primary=data["is_primary"],
            discovered_via=data["discovered_via"],
            created_at=data["created_at"],
            updated_at=data["updated_at"],
            last_seen=data["last_seen"],
        )

    # Search operations (PostgreSQL)
    def search_systems(self, query: str) -> list[System]:
        conn = self._get_conn()
        with conn.cursor() as cur:
            # Use PostgreSQL full-text search
            cur.execute("""
                SELECT * FROM systems
                WHERE to_tsvector('english', coalesce(hostname, '') || ' ' || coalesce(fqdn, '') || ' ' || coalesce(notes, ''))
                    @@ plainto_tsquery('english', %s)
                   OR hostname ILIKE %s
                   OR fqdn ILIKE %s
                   OR primary_ip ILIKE %s
                ORDER BY hostname
            """, (query, f"%{query}%", f"%{query}%", f"%{query}%"))
            rows = cur.fetchall()

            systems = []
            for row in rows:
                system = self._row_to_system_pg(row, cur.description)
                system.interfaces = self.get_interfaces_for_system(system.id)
                systems.append(system)
            return systems

    def get_systems_on_switch(self, switch_id: int) -> list[System]:
        return self.list_systems(switch_id=switch_id)

    def get_systems_in_rack(self, rack: str, datacenter: str | None = None) -> list[System]:
        conn = self._get_conn()
        with conn.cursor() as cur:
            query = """
                SELECT s.* FROM systems s
                JOIN locations l ON l.id = s.location_id
                WHERE l.rack = %s
            """
            params: list[Any] = [rack]

            if datacenter:
                query += " AND l.datacenter = %s"
                params.append(datacenter)

            query += " ORDER BY l.rack_unit, s.hostname"
            cur.execute(query, params)
            rows = cur.fetchall()

            systems = []
            for row in rows:
                system = self._row_to_system_pg(row, cur.description)
                system.interfaces = self.get_interfaces_for_system(system.id)
                systems.append(system)
            return systems


def get_database(connection_string: str | None = None) -> Database:
    """Get database instance based on connection string.

    Args:
        connection_string: Database connection string.
            - None or "sqlite" or "sqlite:///path.db" -> SQLite
            - "postgresql://..." -> PostgreSQL

    Returns:
        Database instance
    """
    if connection_string is None:
        # Default to SQLite in user's config directory
        config_dir = Path.home() / ".config" / "globaldetect"
        config_dir.mkdir(parents=True, exist_ok=True)
        db_path = config_dir / "inventory.db"
        return SQLiteDatabase(str(db_path))

    if connection_string.startswith("sqlite"):
        if ":///" in connection_string:
            db_path = connection_string.split("///", 1)[1]
        else:
            config_dir = Path.home() / ".config" / "globaldetect"
            config_dir.mkdir(parents=True, exist_ok=True)
            db_path = str(config_dir / "inventory.db")
        return SQLiteDatabase(db_path)

    if connection_string.startswith("postgresql"):
        return PostgreSQLDatabase(connection_string)

    raise ValueError(f"Unsupported database type: {connection_string}")
