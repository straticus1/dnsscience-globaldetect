"""
Database models for network inventory.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class SystemType(str, Enum):
    """Type of system in inventory."""
    SERVER = "server"
    WORKSTATION = "workstation"
    ROUTER = "router"
    SWITCH = "switch"
    FIREWALL = "firewall"
    LOAD_BALANCER = "load_balancer"
    STORAGE = "storage"
    APPLIANCE = "appliance"
    VM = "vm"
    CONTAINER_HOST = "container_host"
    UNKNOWN = "unknown"


class SystemStatus(str, Enum):
    """Operational status of a system."""
    # Lifecycle stages
    ORDERED = "ordered"  # Hardware has been ordered
    PURCHASED = "purchased"  # PO issued
    ASSEMBLED = "assembled"  # Being built/configured
    SHIPPED = "shipped"  # In transit
    DELIVERED = "delivered"  # Received at location
    INSTALLING = "installing"  # Being installed/racked
    PROVISIONING = "provisioning"  # OS/software being installed

    # Operational states
    ACTIVE = "active"  # In production
    INACTIVE = "inactive"  # Powered off or disconnected
    MAINTENANCE = "maintenance"  # Planned maintenance
    DEGRADED = "degraded"  # Partially functional

    # End of life
    DECOMMISSIONING = "decommissioning"  # Being removed from service
    DECOMMISSIONED = "decommissioned"  # No longer in service
    DISPOSED = "disposed"  # Physically removed/recycled

    UNKNOWN = "unknown"


class InterfaceRole(str, Enum):
    """Role/purpose of a network interface."""
    PRIMARY = "primary"  # Main production interface
    MANAGEMENT = "management"  # Out-of-band management (IPMI, iLO, iDRAC)
    BACKUP = "backup"  # Backup/failover interface
    STORAGE = "storage"  # SAN/NAS traffic
    CLUSTER = "cluster"  # Cluster heartbeat
    REPLICATION = "replication"  # Database/storage replication
    MONITORING = "monitoring"  # Monitoring network
    DMZ = "dmz"  # DMZ-facing interface
    INTERNAL = "internal"  # Internal network
    EXTERNAL = "external"  # Internet-facing
    BOND_MEMBER = "bond_member"  # Part of a bond/team
    VLAN_TRUNK = "vlan_trunk"  # Carries multiple VLANs
    OTHER = "other"


@dataclass
class Location:
    """Physical location information."""
    id: int | None = None

    # Geographic
    country: str | None = None
    state: str | None = None
    city: str | None = None
    address: str | None = None

    # Data center specifics
    datacenter: str | None = None
    building: str | None = None
    floor: str | None = None
    room: str | None = None
    rack: str | None = None
    rack_unit: int | None = None  # U position in rack

    # Coordinates (for mapping)
    latitude: float | None = None
    longitude: float | None = None

    # Metadata
    notes: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "country": self.country,
            "state": self.state,
            "city": self.city,
            "address": self.address,
            "datacenter": self.datacenter,
            "building": self.building,
            "floor": self.floor,
            "room": self.room,
            "rack": self.rack,
            "rack_unit": self.rack_unit,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "notes": self.notes,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Location":
        return cls(
            id=data.get("id"),
            country=data.get("country"),
            state=data.get("state"),
            city=data.get("city"),
            address=data.get("address"),
            datacenter=data.get("datacenter"),
            building=data.get("building"),
            floor=data.get("floor"),
            room=data.get("room"),
            rack=data.get("rack"),
            rack_unit=data.get("rack_unit"),
            latitude=data.get("latitude"),
            longitude=data.get("longitude"),
            notes=data.get("notes"),
            created_at=datetime.fromisoformat(data["created_at"]) if data.get("created_at") else None,
            updated_at=datetime.fromisoformat(data["updated_at"]) if data.get("updated_at") else None,
        )


@dataclass
class Switch:
    """Network switch information."""
    id: int | None = None

    # Identity
    hostname: str | None = None
    management_ip: str | None = None

    # Hardware
    vendor: str | None = None
    model: str | None = None
    serial_number: str | None = None
    firmware_version: str | None = None

    # Discovery info (from CDP/LLDP)
    platform: str | None = None
    capabilities: list[str] = field(default_factory=list)

    # Location
    location_id: int | None = None
    location: Location | None = None

    # Port count
    total_ports: int | None = None

    # Metadata
    notes: str | None = None
    tags: list[str] = field(default_factory=list)
    custom_fields: dict[str, Any] = field(default_factory=dict)

    # Timestamps
    created_at: datetime | None = None
    updated_at: datetime | None = None
    last_seen: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "hostname": self.hostname,
            "management_ip": self.management_ip,
            "vendor": self.vendor,
            "model": self.model,
            "serial_number": self.serial_number,
            "firmware_version": self.firmware_version,
            "platform": self.platform,
            "capabilities": self.capabilities,
            "location_id": self.location_id,
            "total_ports": self.total_ports,
            "notes": self.notes,
            "tags": self.tags,
            "custom_fields": self.custom_fields,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Switch":
        return cls(
            id=data.get("id"),
            hostname=data.get("hostname"),
            management_ip=data.get("management_ip"),
            vendor=data.get("vendor"),
            model=data.get("model"),
            serial_number=data.get("serial_number"),
            firmware_version=data.get("firmware_version"),
            platform=data.get("platform"),
            capabilities=data.get("capabilities", []),
            location_id=data.get("location_id"),
            total_ports=data.get("total_ports"),
            notes=data.get("notes"),
            tags=data.get("tags", []),
            custom_fields=data.get("custom_fields", {}),
            created_at=datetime.fromisoformat(data["created_at"]) if data.get("created_at") else None,
            updated_at=datetime.fromisoformat(data["updated_at"]) if data.get("updated_at") else None,
            last_seen=datetime.fromisoformat(data["last_seen"]) if data.get("last_seen") else None,
        )


@dataclass
class NetworkInterface:
    """Network interface on a system."""
    id: int | None = None
    system_id: int | None = None

    # Interface info
    name: str | None = None  # OS interface name (eth0, eno1, enp3s0, etc.)
    mac_address: str | None = None
    ip_addresses: list[str] = field(default_factory=list)

    # DNS names for this interface (e.g., eth0.example.com, mgmt.example.com)
    dns_names: list[str] = field(default_factory=list)

    # Interface role/purpose
    role: InterfaceRole = InterfaceRole.OTHER
    description: str | None = None  # Human-readable description

    # Connection info (where is it plugged in)
    connected_switch_id: int | None = None
    connected_switch: Switch | None = None
    switch_port: str | None = None

    # VLAN
    vlan_id: int | None = None
    vlan_name: str | None = None
    vlans: list[int] = field(default_factory=list)  # For trunk ports with multiple VLANs

    # Link info
    speed_mbps: int | None = None
    duplex: str | None = None  # full, half, auto
    mtu: int | None = None
    media_type: str | None = None  # copper, fiber, etc.

    # Bonding/Teaming
    bond_master: str | None = None  # If part of a bond, name of master interface
    bond_slaves: list[str] = field(default_factory=list)  # If bond master, list of slave interfaces
    bond_mode: str | None = None  # 802.3ad, active-backup, etc.

    # State
    is_up: bool = True
    is_primary: bool = False
    is_management: bool = False  # Shortcut for management interfaces

    # Discovery source
    discovered_via: str | None = None  # cdp, lldp, arp, agent

    # Timestamps
    created_at: datetime | None = None
    updated_at: datetime | None = None
    last_seen: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "system_id": self.system_id,
            "name": self.name,
            "mac_address": self.mac_address,
            "ip_addresses": self.ip_addresses,
            "dns_names": self.dns_names,
            "role": self.role.value,
            "description": self.description,
            "connected_switch_id": self.connected_switch_id,
            "switch_port": self.switch_port,
            "vlan_id": self.vlan_id,
            "vlan_name": self.vlan_name,
            "vlans": self.vlans,
            "speed_mbps": self.speed_mbps,
            "duplex": self.duplex,
            "mtu": self.mtu,
            "media_type": self.media_type,
            "bond_master": self.bond_master,
            "bond_slaves": self.bond_slaves,
            "bond_mode": self.bond_mode,
            "is_up": self.is_up,
            "is_primary": self.is_primary,
            "is_management": self.is_management,
            "discovered_via": self.discovered_via,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "NetworkInterface":
        return cls(
            id=data.get("id"),
            system_id=data.get("system_id"),
            name=data.get("name"),
            mac_address=data.get("mac_address"),
            ip_addresses=data.get("ip_addresses", []),
            dns_names=data.get("dns_names", []),
            role=InterfaceRole(data.get("role", "other")),
            description=data.get("description"),
            connected_switch_id=data.get("connected_switch_id"),
            switch_port=data.get("switch_port"),
            vlan_id=data.get("vlan_id"),
            vlan_name=data.get("vlan_name"),
            vlans=data.get("vlans", []),
            speed_mbps=data.get("speed_mbps"),
            duplex=data.get("duplex"),
            mtu=data.get("mtu"),
            media_type=data.get("media_type"),
            bond_master=data.get("bond_master"),
            bond_slaves=data.get("bond_slaves", []),
            bond_mode=data.get("bond_mode"),
            is_up=data.get("is_up", True),
            is_primary=data.get("is_primary", False),
            is_management=data.get("is_management", False),
            discovered_via=data.get("discovered_via"),
            created_at=datetime.fromisoformat(data["created_at"]) if data.get("created_at") else None,
            updated_at=datetime.fromisoformat(data["updated_at"]) if data.get("updated_at") else None,
            last_seen=datetime.fromisoformat(data["last_seen"]) if data.get("last_seen") else None,
        )


@dataclass
class System:
    """A system (server, workstation, network device, etc.) in the inventory."""
    id: int | None = None

    # Identity
    hostname: str | None = None
    fqdn: str | None = None
    aliases: list[str] = field(default_factory=list)  # Additional DNS names for this system

    # Type and status
    system_type: SystemType = SystemType.UNKNOWN
    status: SystemStatus = SystemStatus.UNKNOWN

    # Network (primary)
    primary_ip: str | None = None
    primary_mac: str | None = None

    # Management interface (separate from primary)
    management_ip: str | None = None
    management_dns: str | None = None  # e.g., mgmt.example.com

    # All interfaces
    interfaces: list[NetworkInterface] = field(default_factory=list)

    # Hardware
    vendor: str | None = None
    model: str | None = None
    serial_number: str | None = None
    asset_tag: str | None = None
    service_tag: str | None = None  # Dell service tag, HP serial, etc.

    # OS info
    os_name: str | None = None
    os_version: str | None = None
    kernel_version: str | None = None

    # Resources
    cpu_cores: int | None = None
    cpu_model: str | None = None
    ram_gb: float | None = None
    disk_gb: float | None = None

    # BGP/IP derived location
    asn: int | None = None
    as_name: str | None = None
    ip_country: str | None = None
    ip_city: str | None = None
    ip_org: str | None = None

    # Physical location
    location_id: int | None = None
    location: Location | None = None

    # Procurement/shipping
    purchase_order: str | None = None
    purchase_date: datetime | None = None
    shipping_carrier: str | None = None  # FedEx, UPS, etc.
    tracking_number: str | None = None
    ship_date: datetime | None = None
    delivery_date: datetime | None = None

    # Lifecycle/ticketing
    install_ticket: str | None = None  # Ticket/request that provisioned this system
    install_date: datetime | None = None
    last_service_ticket: str | None = None  # Most recent service ticket
    last_service_date: datetime | None = None
    warranty_expires: datetime | None = None
    decommission_ticket: str | None = None
    decommission_date: datetime | None = None

    # Agent info (if running globaldetect agent)
    agent_version: str | None = None
    agent_last_checkin: datetime | None = None

    # Metadata
    notes: str | None = None
    tags: list[str] = field(default_factory=list)
    custom_fields: dict[str, Any] = field(default_factory=dict)

    # Owner/contact
    owner: str | None = None  # Team or person responsible
    contact_email: str | None = None
    cost_center: str | None = None

    # Timestamps
    created_at: datetime | None = None
    updated_at: datetime | None = None
    last_seen: datetime | None = None
    discovered_at: datetime | None = None

    # Discovery info
    discovered_via: str | None = None  # scan, agent, manual, cdp, lldp

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "hostname": self.hostname,
            "fqdn": self.fqdn,
            "aliases": self.aliases,
            "system_type": self.system_type.value,
            "status": self.status.value,
            "primary_ip": self.primary_ip,
            "primary_mac": self.primary_mac,
            "management_ip": self.management_ip,
            "management_dns": self.management_dns,
            "vendor": self.vendor,
            "model": self.model,
            "serial_number": self.serial_number,
            "asset_tag": self.asset_tag,
            "service_tag": self.service_tag,
            "os_name": self.os_name,
            "os_version": self.os_version,
            "kernel_version": self.kernel_version,
            "cpu_cores": self.cpu_cores,
            "cpu_model": self.cpu_model,
            "ram_gb": self.ram_gb,
            "disk_gb": self.disk_gb,
            "asn": self.asn,
            "as_name": self.as_name,
            "ip_country": self.ip_country,
            "ip_city": self.ip_city,
            "ip_org": self.ip_org,
            "location_id": self.location_id,
            # Procurement/shipping
            "purchase_order": self.purchase_order,
            "purchase_date": self.purchase_date.isoformat() if self.purchase_date else None,
            "shipping_carrier": self.shipping_carrier,
            "tracking_number": self.tracking_number,
            "ship_date": self.ship_date.isoformat() if self.ship_date else None,
            "delivery_date": self.delivery_date.isoformat() if self.delivery_date else None,
            # Lifecycle/ticketing
            "install_ticket": self.install_ticket,
            "install_date": self.install_date.isoformat() if self.install_date else None,
            "last_service_ticket": self.last_service_ticket,
            "last_service_date": self.last_service_date.isoformat() if self.last_service_date else None,
            "warranty_expires": self.warranty_expires.isoformat() if self.warranty_expires else None,
            "decommission_ticket": self.decommission_ticket,
            "decommission_date": self.decommission_date.isoformat() if self.decommission_date else None,
            # Agent
            "agent_version": self.agent_version,
            "agent_last_checkin": self.agent_last_checkin.isoformat() if self.agent_last_checkin else None,
            # Metadata
            "notes": self.notes,
            "tags": self.tags,
            "custom_fields": self.custom_fields,
            # Owner/contact
            "owner": self.owner,
            "contact_email": self.contact_email,
            "cost_center": self.cost_center,
            # Timestamps
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "discovered_at": self.discovered_at.isoformat() if self.discovered_at else None,
            "discovered_via": self.discovered_via,
            "interfaces": [iface.to_dict() for iface in self.interfaces],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "System":
        interfaces = [
            NetworkInterface.from_dict(iface)
            for iface in data.get("interfaces", [])
        ]
        return cls(
            id=data.get("id"),
            hostname=data.get("hostname"),
            fqdn=data.get("fqdn"),
            aliases=data.get("aliases", []),
            system_type=SystemType(data.get("system_type", "unknown")),
            status=SystemStatus(data.get("status", "unknown")),
            primary_ip=data.get("primary_ip"),
            primary_mac=data.get("primary_mac"),
            management_ip=data.get("management_ip"),
            management_dns=data.get("management_dns"),
            interfaces=interfaces,
            vendor=data.get("vendor"),
            model=data.get("model"),
            serial_number=data.get("serial_number"),
            asset_tag=data.get("asset_tag"),
            service_tag=data.get("service_tag"),
            os_name=data.get("os_name"),
            os_version=data.get("os_version"),
            kernel_version=data.get("kernel_version"),
            cpu_cores=data.get("cpu_cores"),
            cpu_model=data.get("cpu_model"),
            ram_gb=data.get("ram_gb"),
            disk_gb=data.get("disk_gb"),
            asn=data.get("asn"),
            as_name=data.get("as_name"),
            ip_country=data.get("ip_country"),
            ip_city=data.get("ip_city"),
            ip_org=data.get("ip_org"),
            location_id=data.get("location_id"),
            # Procurement/shipping
            purchase_order=data.get("purchase_order"),
            purchase_date=datetime.fromisoformat(data["purchase_date"]) if data.get("purchase_date") else None,
            shipping_carrier=data.get("shipping_carrier"),
            tracking_number=data.get("tracking_number"),
            ship_date=datetime.fromisoformat(data["ship_date"]) if data.get("ship_date") else None,
            delivery_date=datetime.fromisoformat(data["delivery_date"]) if data.get("delivery_date") else None,
            # Lifecycle/ticketing
            install_ticket=data.get("install_ticket"),
            install_date=datetime.fromisoformat(data["install_date"]) if data.get("install_date") else None,
            last_service_ticket=data.get("last_service_ticket"),
            last_service_date=datetime.fromisoformat(data["last_service_date"]) if data.get("last_service_date") else None,
            warranty_expires=datetime.fromisoformat(data["warranty_expires"]) if data.get("warranty_expires") else None,
            decommission_ticket=data.get("decommission_ticket"),
            decommission_date=datetime.fromisoformat(data["decommission_date"]) if data.get("decommission_date") else None,
            # Agent
            agent_version=data.get("agent_version"),
            agent_last_checkin=datetime.fromisoformat(data["agent_last_checkin"]) if data.get("agent_last_checkin") else None,
            # Metadata
            notes=data.get("notes"),
            tags=data.get("tags", []),
            custom_fields=data.get("custom_fields", {}),
            # Owner/contact
            owner=data.get("owner"),
            contact_email=data.get("contact_email"),
            cost_center=data.get("cost_center"),
            # Timestamps
            created_at=datetime.fromisoformat(data["created_at"]) if data.get("created_at") else None,
            updated_at=datetime.fromisoformat(data["updated_at"]) if data.get("updated_at") else None,
            last_seen=datetime.fromisoformat(data["last_seen"]) if data.get("last_seen") else None,
            discovered_at=datetime.fromisoformat(data["discovered_at"]) if data.get("discovered_at") else None,
            discovered_via=data.get("discovered_via"),
        )
