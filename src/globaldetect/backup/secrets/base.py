"""
Abstract base classes and models for secrets management.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Iterator


class BackendType(str, Enum):
    """Secrets storage backend type."""
    SQLITE = "sqlite"
    POSTGRESQL = "postgresql"
    AURORA_POSTGRESQL = "aurora_postgresql"
    RDS_POSTGRESQL = "rds_postgresql"
    CONFIDANT = "confidant"


class SecretType(str, Enum):
    """Type of secret stored."""
    PASSWORD = "password"
    SSH_KEY = "ssh_key"
    API_KEY = "api_key"
    API_TOKEN = "api_token"
    CERTIFICATE = "certificate"
    PRIVATE_KEY = "private_key"
    SNMP_COMMUNITY = "snmp_community"
    ENABLE_SECRET = "enable_secret"
    GENERIC = "generic"


class ResourceType(str, Enum):
    """Type of resource that can be linked."""
    # AWS Resources
    EC2_INSTANCE = "ec2_instance"
    RDS_INSTANCE = "rds_instance"
    LAMBDA_FUNCTION = "lambda_function"
    ECS_SERVICE = "ecs_service"
    EKS_CLUSTER = "eks_cluster"
    S3_BUCKET = "s3_bucket"
    IAM_ROLE = "iam_role"
    IAM_USER = "iam_user"
    SECRETS_MANAGER = "secrets_manager"

    # Network devices
    ROUTER = "router"
    SWITCH = "switch"
    FIREWALL = "firewall"
    LOAD_BALANCER = "load_balancer"
    DNS_APPLIANCE = "dns_appliance"

    # Servers
    SERVER = "server"
    VM = "vm"
    CONTAINER = "container"

    # Generic
    SERVICE = "service"
    APPLICATION = "application"
    DATABASE = "database"
    OTHER = "other"


@dataclass
class SecretEntry:
    """A secret stored in the backend."""
    id: str | None = None
    name: str | None = None
    description: str | None = None

    # Secret data
    secret_type: SecretType = SecretType.GENERIC
    secret_value: str | None = None  # Encrypted at rest

    # Metadata
    version: int = 1
    enabled: bool = True

    # Rotation
    rotation_enabled: bool = False
    rotation_days: int | None = None
    last_rotated: datetime | None = None
    expires_at: datetime | None = None

    # Ownership
    owner_user_id: str | None = None
    owner_group: str | None = None

    # Access control
    allowed_users: list[str] = field(default_factory=list)
    allowed_groups: list[str] = field(default_factory=list)
    allowed_arns: list[str] = field(default_factory=list)

    # Linked resources
    linked_resources: list[str] = field(default_factory=list)  # Resource IDs

    # Tags and custom fields
    tags: list[str] = field(default_factory=list)
    custom_fields: dict[str, Any] = field(default_factory=dict)

    # Confidant metadata (when synced from Confidant)
    confidant_id: str | None = None
    confidant_revision: int | None = None

    # Timestamps
    created_at: datetime | None = None
    updated_at: datetime | None = None
    accessed_at: datetime | None = None

    def to_dict(self, include_secret: bool = False) -> dict[str, Any]:
        """Convert to dictionary."""
        data = {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "secret_type": self.secret_type.value,
            "version": self.version,
            "enabled": self.enabled,
            "rotation_enabled": self.rotation_enabled,
            "rotation_days": self.rotation_days,
            "last_rotated": self.last_rotated.isoformat() if self.last_rotated else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "owner_user_id": self.owner_user_id,
            "owner_group": self.owner_group,
            "allowed_users": self.allowed_users,
            "allowed_groups": self.allowed_groups,
            "allowed_arns": self.allowed_arns,
            "linked_resources": self.linked_resources,
            "tags": self.tags,
            "custom_fields": self.custom_fields,
            "confidant_id": self.confidant_id,
            "confidant_revision": self.confidant_revision,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "accessed_at": self.accessed_at.isoformat() if self.accessed_at else None,
        }
        if include_secret:
            data["secret_value"] = self.secret_value
        return data


@dataclass
class UserEntry:
    """A user in the secrets system."""
    id: str | None = None
    username: str | None = None
    email: str | None = None
    full_name: str | None = None

    # Authentication
    password_hash: str | None = None  # For local auth
    ssh_public_keys: list[str] = field(default_factory=list)

    # Unix user fields (for passwd file generation)
    uid: int | None = None
    gid: int | None = None
    home_directory: str | None = None
    shell: str = "/bin/bash"
    gecos: str | None = None  # Comment field

    # Groups
    groups: list[str] = field(default_factory=list)
    primary_group: str | None = None

    # AWS/Cloud identity
    aws_arns: list[str] = field(default_factory=list)  # Linked ARNs
    aws_account_id: str | None = None

    # Status
    enabled: bool = True
    locked: bool = False
    password_expires: datetime | None = None
    last_login: datetime | None = None

    # Access control
    is_admin: bool = False
    can_create_secrets: bool = True
    can_delete_secrets: bool = False

    # Linked resources
    linked_resources: list[str] = field(default_factory=list)

    # Metadata
    tags: list[str] = field(default_factory=list)
    custom_fields: dict[str, Any] = field(default_factory=dict)

    # Timestamps
    created_at: datetime | None = None
    updated_at: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary (excludes password hash)."""
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "full_name": self.full_name,
            "uid": self.uid,
            "gid": self.gid,
            "home_directory": self.home_directory,
            "shell": self.shell,
            "gecos": self.gecos,
            "groups": self.groups,
            "primary_group": self.primary_group,
            "aws_arns": self.aws_arns,
            "aws_account_id": self.aws_account_id,
            "enabled": self.enabled,
            "locked": self.locked,
            "password_expires": self.password_expires.isoformat() if self.password_expires else None,
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "is_admin": self.is_admin,
            "can_create_secrets": self.can_create_secrets,
            "can_delete_secrets": self.can_delete_secrets,
            "linked_resources": self.linked_resources,
            "tags": self.tags,
            "custom_fields": self.custom_fields,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def to_passwd_line(self) -> str:
        """Generate passwd file entry."""
        # Format: username:x:uid:gid:gecos:home:shell
        uid = self.uid or 65534
        gid = self.gid or 65534
        gecos = self.gecos or self.full_name or ""
        home = self.home_directory or f"/home/{self.username}"
        return f"{self.username}:x:{uid}:{gid}:{gecos}:{home}:{self.shell}"

    def to_shadow_line(self, encrypted_password: str = "!") -> str:
        """Generate shadow file entry."""
        # Format: username:password:lastchg:min:max:warn:inactive:expire:reserved
        # lastchg = days since epoch of last password change
        if self.updated_at:
            lastchg = (self.updated_at - datetime(1970, 1, 1)).days
        else:
            lastchg = 0
        return f"{self.username}:{encrypted_password}:{lastchg}:0:99999:7:::"


@dataclass
class ARNLink:
    """Link between an ARN and local resources."""
    id: str | None = None

    # ARN information
    arn: str | None = None
    aws_account_id: str | None = None
    aws_region: str | None = None
    service: str | None = None  # ec2, rds, lambda, etc.
    resource_type: str | None = None
    resource_id: str | None = None

    # Linked local entities
    linked_user_ids: list[str] = field(default_factory=list)
    linked_secret_ids: list[str] = field(default_factory=list)
    linked_system_ids: list[str] = field(default_factory=list)  # Inventory system IDs

    # Metadata
    name: str | None = None
    description: str | None = None
    tags: list[str] = field(default_factory=list)

    # Timestamps
    created_at: datetime | None = None
    updated_at: datetime | None = None
    last_verified: datetime | None = None

    def parse_arn(self) -> dict[str, str]:
        """Parse ARN into components."""
        if not self.arn:
            return {}

        # ARN format: arn:partition:service:region:account:resource
        parts = self.arn.split(":")
        if len(parts) < 6:
            return {}

        return {
            "partition": parts[1],
            "service": parts[2],
            "region": parts[3],
            "account": parts[4],
            "resource": ":".join(parts[5:]),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "arn": self.arn,
            "aws_account_id": self.aws_account_id,
            "aws_region": self.aws_region,
            "service": self.service,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "linked_user_ids": self.linked_user_ids,
            "linked_secret_ids": self.linked_secret_ids,
            "linked_system_ids": self.linked_system_ids,
            "name": self.name,
            "description": self.description,
            "tags": self.tags,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "last_verified": self.last_verified.isoformat() if self.last_verified else None,
        }


@dataclass
class ResourceLink:
    """Link between a resource and secrets/users."""
    id: str | None = None

    # Resource identification
    resource_type: ResourceType = ResourceType.OTHER
    resource_id: str | None = None  # External ID (instance-id, etc.)
    resource_name: str | None = None

    # Linked entities
    linked_secret_ids: list[str] = field(default_factory=list)
    linked_user_ids: list[str] = field(default_factory=list)
    linked_arn_ids: list[str] = field(default_factory=list)

    # Inventory system link
    inventory_system_id: int | None = None

    # Metadata
    description: str | None = None
    tags: list[str] = field(default_factory=list)
    custom_fields: dict[str, Any] = field(default_factory=dict)

    # Timestamps
    created_at: datetime | None = None
    updated_at: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "resource_type": self.resource_type.value,
            "resource_id": self.resource_id,
            "resource_name": self.resource_name,
            "linked_secret_ids": self.linked_secret_ids,
            "linked_user_ids": self.linked_user_ids,
            "linked_arn_ids": self.linked_arn_ids,
            "inventory_system_id": self.inventory_system_id,
            "description": self.description,
            "tags": self.tags,
            "custom_fields": self.custom_fields,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class SecretsBackend(ABC):
    """Abstract base class for secrets storage backends."""

    BACKEND_TYPE: BackendType = BackendType.SQLITE

    @abstractmethod
    def initialize(self) -> None:
        """Initialize the backend (create tables, etc.)."""
        pass

    @abstractmethod
    def close(self) -> None:
        """Close backend connections."""
        pass

    # Secret operations
    @abstractmethod
    def create_secret(self, secret: SecretEntry) -> str:
        """Create a new secret. Returns secret ID."""
        pass

    @abstractmethod
    def get_secret(self, secret_id: str) -> SecretEntry | None:
        """Get a secret by ID."""
        pass

    @abstractmethod
    def get_secret_by_name(self, name: str) -> SecretEntry | None:
        """Get a secret by name."""
        pass

    @abstractmethod
    def update_secret(self, secret: SecretEntry) -> bool:
        """Update an existing secret."""
        pass

    @abstractmethod
    def delete_secret(self, secret_id: str) -> bool:
        """Delete a secret."""
        pass

    @abstractmethod
    def list_secrets(
        self,
        secret_type: SecretType | None = None,
        owner_user_id: str | None = None,
        tags: list[str] | None = None,
    ) -> Iterator[SecretEntry]:
        """List secrets with optional filtering."""
        pass

    # User operations
    @abstractmethod
    def create_user(self, user: UserEntry) -> str:
        """Create a new user. Returns user ID."""
        pass

    @abstractmethod
    def get_user(self, user_id: str) -> UserEntry | None:
        """Get a user by ID."""
        pass

    @abstractmethod
    def get_user_by_username(self, username: str) -> UserEntry | None:
        """Get a user by username."""
        pass

    @abstractmethod
    def update_user(self, user: UserEntry) -> bool:
        """Update an existing user."""
        pass

    @abstractmethod
    def delete_user(self, user_id: str) -> bool:
        """Delete a user."""
        pass

    @abstractmethod
    def list_users(
        self,
        group: str | None = None,
        enabled: bool | None = None,
    ) -> Iterator[UserEntry]:
        """List users with optional filtering."""
        pass

    # ARN operations
    @abstractmethod
    def create_arn_link(self, arn_link: ARNLink) -> str:
        """Create an ARN link. Returns link ID."""
        pass

    @abstractmethod
    def get_arn_link(self, link_id: str) -> ARNLink | None:
        """Get an ARN link by ID."""
        pass

    @abstractmethod
    def get_arn_link_by_arn(self, arn: str) -> ARNLink | None:
        """Get an ARN link by ARN string."""
        pass

    @abstractmethod
    def update_arn_link(self, arn_link: ARNLink) -> bool:
        """Update an ARN link."""
        pass

    @abstractmethod
    def delete_arn_link(self, link_id: str) -> bool:
        """Delete an ARN link."""
        pass

    @abstractmethod
    def list_arn_links(
        self,
        aws_account_id: str | None = None,
        service: str | None = None,
    ) -> Iterator[ARNLink]:
        """List ARN links with optional filtering."""
        pass

    # Resource operations
    @abstractmethod
    def create_resource_link(self, resource: ResourceLink) -> str:
        """Create a resource link. Returns link ID."""
        pass

    @abstractmethod
    def get_resource_link(self, link_id: str) -> ResourceLink | None:
        """Get a resource link by ID."""
        pass

    @abstractmethod
    def update_resource_link(self, resource: ResourceLink) -> bool:
        """Update a resource link."""
        pass

    @abstractmethod
    def delete_resource_link(self, link_id: str) -> bool:
        """Delete a resource link."""
        pass

    @abstractmethod
    def list_resource_links(
        self,
        resource_type: ResourceType | None = None,
    ) -> Iterator[ResourceLink]:
        """List resource links with optional filtering."""
        pass

    # Linking operations
    def link_user_to_arn(self, user_id: str, arn: str) -> bool:
        """Link a user to an ARN."""
        user = self.get_user(user_id)
        if not user:
            return False

        if arn not in user.aws_arns:
            user.aws_arns.append(arn)
            user.updated_at = datetime.now()
            self.update_user(user)

        # Also update ARN link
        arn_link = self.get_arn_link_by_arn(arn)
        if arn_link:
            if user_id not in arn_link.linked_user_ids:
                arn_link.linked_user_ids.append(user_id)
                arn_link.updated_at = datetime.now()
                self.update_arn_link(arn_link)

        return True

    def link_secret_to_resource(self, secret_id: str, resource_id: str) -> bool:
        """Link a secret to a resource."""
        secret = self.get_secret(secret_id)
        if not secret:
            return False

        if resource_id not in secret.linked_resources:
            secret.linked_resources.append(resource_id)
            secret.updated_at = datetime.now()
            self.update_secret(secret)

        return True
