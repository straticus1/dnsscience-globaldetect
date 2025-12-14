"""
SQLite backend for secrets storage.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import json
import os
import sqlite3
import hashlib
import secrets as py_secrets
from datetime import datetime
from pathlib import Path
from typing import Iterator

from globaldetect.backup.secrets.base import (
    SecretsBackend,
    BackendType,
    SecretEntry,
    SecretType,
    UserEntry,
    ARNLink,
    ResourceLink,
    ResourceType,
)
from globaldetect.backup.secrets.config import SecretsConfig


class SQLiteBackend(SecretsBackend):
    """SQLite-based secrets storage backend."""

    BACKEND_TYPE = BackendType.SQLITE

    SCHEMA_VERSION = 1

    def __init__(self, config: SecretsConfig):
        """Initialize SQLite backend.

        Args:
            config: Secrets configuration
        """
        self.config = config
        self.db_path = config.get_sqlite_path()
        self._conn: sqlite3.Connection | None = None

    def initialize(self) -> None:
        """Initialize the database and create tables."""
        # Ensure directory exists
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self._conn = sqlite3.connect(
            str(self.db_path),
            detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES,
        )
        self._conn.row_factory = sqlite3.Row

        # Set secure file permissions
        os.chmod(self.db_path, 0o600)

        self._create_tables()

    def close(self) -> None:
        """Close database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None

    def _create_tables(self) -> None:
        """Create database tables."""
        cursor = self._conn.cursor()

        # Schema version tracking
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY
            )
        """)

        # Secrets table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS secrets (
                id TEXT PRIMARY KEY,
                name TEXT UNIQUE NOT NULL,
                description TEXT,
                secret_type TEXT NOT NULL,
                secret_value TEXT,
                version INTEGER DEFAULT 1,
                enabled INTEGER DEFAULT 1,
                rotation_enabled INTEGER DEFAULT 0,
                rotation_days INTEGER,
                last_rotated TEXT,
                expires_at TEXT,
                owner_user_id TEXT,
                owner_group TEXT,
                allowed_users TEXT,
                allowed_groups TEXT,
                allowed_arns TEXT,
                linked_resources TEXT,
                tags TEXT,
                custom_fields TEXT,
                confidant_id TEXT,
                confidant_revision INTEGER,
                created_at TEXT,
                updated_at TEXT,
                accessed_at TEXT
            )
        """)

        # Users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email TEXT,
                full_name TEXT,
                password_hash TEXT,
                ssh_public_keys TEXT,
                uid INTEGER,
                gid INTEGER,
                home_directory TEXT,
                shell TEXT DEFAULT '/bin/bash',
                gecos TEXT,
                groups TEXT,
                primary_group TEXT,
                aws_arns TEXT,
                aws_account_id TEXT,
                enabled INTEGER DEFAULT 1,
                locked INTEGER DEFAULT 0,
                password_expires TEXT,
                last_login TEXT,
                is_admin INTEGER DEFAULT 0,
                can_create_secrets INTEGER DEFAULT 1,
                can_delete_secrets INTEGER DEFAULT 0,
                linked_resources TEXT,
                tags TEXT,
                custom_fields TEXT,
                created_at TEXT,
                updated_at TEXT
            )
        """)

        # ARN links table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS arn_links (
                id TEXT PRIMARY KEY,
                arn TEXT UNIQUE NOT NULL,
                aws_account_id TEXT,
                aws_region TEXT,
                service TEXT,
                resource_type TEXT,
                resource_id TEXT,
                linked_user_ids TEXT,
                linked_secret_ids TEXT,
                linked_system_ids TEXT,
                name TEXT,
                description TEXT,
                tags TEXT,
                created_at TEXT,
                updated_at TEXT,
                last_verified TEXT
            )
        """)

        # Resource links table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS resource_links (
                id TEXT PRIMARY KEY,
                resource_type TEXT NOT NULL,
                resource_id TEXT,
                resource_name TEXT,
                linked_secret_ids TEXT,
                linked_user_ids TEXT,
                linked_arn_ids TEXT,
                inventory_system_id INTEGER,
                description TEXT,
                tags TEXT,
                custom_fields TEXT,
                created_at TEXT,
                updated_at TEXT
            )
        """)

        # Create indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_secrets_name ON secrets(name)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_secrets_type ON secrets(secret_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_arn_links_arn ON arn_links(arn)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_arn_links_account ON arn_links(aws_account_id)")

        self._conn.commit()

    def _generate_id(self, prefix: str = "") -> str:
        """Generate a unique ID."""
        random_part = py_secrets.token_hex(8)
        if prefix:
            return f"{prefix}_{random_part}"
        return random_part

    # Secret operations
    def create_secret(self, secret: SecretEntry) -> str:
        """Create a new secret."""
        if not secret.id:
            secret.id = self._generate_id("sec")

        secret.created_at = datetime.now()
        secret.updated_at = datetime.now()

        cursor = self._conn.cursor()
        cursor.execute("""
            INSERT INTO secrets (
                id, name, description, secret_type, secret_value, version,
                enabled, rotation_enabled, rotation_days, last_rotated,
                expires_at, owner_user_id, owner_group, allowed_users,
                allowed_groups, allowed_arns, linked_resources, tags,
                custom_fields, confidant_id, confidant_revision,
                created_at, updated_at, accessed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            secret.id,
            secret.name,
            secret.description,
            secret.secret_type.value,
            secret.secret_value,
            secret.version,
            int(secret.enabled),
            int(secret.rotation_enabled),
            secret.rotation_days,
            secret.last_rotated.isoformat() if secret.last_rotated else None,
            secret.expires_at.isoformat() if secret.expires_at else None,
            secret.owner_user_id,
            secret.owner_group,
            json.dumps(secret.allowed_users),
            json.dumps(secret.allowed_groups),
            json.dumps(secret.allowed_arns),
            json.dumps(secret.linked_resources),
            json.dumps(secret.tags),
            json.dumps(secret.custom_fields),
            secret.confidant_id,
            secret.confidant_revision,
            secret.created_at.isoformat(),
            secret.updated_at.isoformat(),
            secret.accessed_at.isoformat() if secret.accessed_at else None,
        ))
        self._conn.commit()
        return secret.id

    def get_secret(self, secret_id: str) -> SecretEntry | None:
        """Get a secret by ID."""
        cursor = self._conn.cursor()
        cursor.execute("SELECT * FROM secrets WHERE id = ?", (secret_id,))
        row = cursor.fetchone()
        if not row:
            return None
        return self._row_to_secret(row)

    def get_secret_by_name(self, name: str) -> SecretEntry | None:
        """Get a secret by name."""
        cursor = self._conn.cursor()
        cursor.execute("SELECT * FROM secrets WHERE name = ?", (name,))
        row = cursor.fetchone()
        if not row:
            return None
        return self._row_to_secret(row)

    def update_secret(self, secret: SecretEntry) -> bool:
        """Update an existing secret."""
        if not secret.id:
            return False

        secret.updated_at = datetime.now()
        secret.version += 1

        cursor = self._conn.cursor()
        cursor.execute("""
            UPDATE secrets SET
                name = ?, description = ?, secret_type = ?, secret_value = ?,
                version = ?, enabled = ?, rotation_enabled = ?, rotation_days = ?,
                last_rotated = ?, expires_at = ?, owner_user_id = ?, owner_group = ?,
                allowed_users = ?, allowed_groups = ?, allowed_arns = ?,
                linked_resources = ?, tags = ?, custom_fields = ?,
                confidant_id = ?, confidant_revision = ?, updated_at = ?
            WHERE id = ?
        """, (
            secret.name,
            secret.description,
            secret.secret_type.value,
            secret.secret_value,
            secret.version,
            int(secret.enabled),
            int(secret.rotation_enabled),
            secret.rotation_days,
            secret.last_rotated.isoformat() if secret.last_rotated else None,
            secret.expires_at.isoformat() if secret.expires_at else None,
            secret.owner_user_id,
            secret.owner_group,
            json.dumps(secret.allowed_users),
            json.dumps(secret.allowed_groups),
            json.dumps(secret.allowed_arns),
            json.dumps(secret.linked_resources),
            json.dumps(secret.tags),
            json.dumps(secret.custom_fields),
            secret.confidant_id,
            secret.confidant_revision,
            secret.updated_at.isoformat(),
            secret.id,
        ))
        self._conn.commit()
        return cursor.rowcount > 0

    def delete_secret(self, secret_id: str) -> bool:
        """Delete a secret."""
        cursor = self._conn.cursor()
        cursor.execute("DELETE FROM secrets WHERE id = ?", (secret_id,))
        self._conn.commit()
        return cursor.rowcount > 0

    def list_secrets(
        self,
        secret_type: SecretType | None = None,
        owner_user_id: str | None = None,
        tags: list[str] | None = None,
    ) -> Iterator[SecretEntry]:
        """List secrets with optional filtering."""
        query = "SELECT * FROM secrets WHERE 1=1"
        params = []

        if secret_type:
            query += " AND secret_type = ?"
            params.append(secret_type.value)

        if owner_user_id:
            query += " AND owner_user_id = ?"
            params.append(owner_user_id)

        cursor = self._conn.cursor()
        cursor.execute(query, params)

        for row in cursor.fetchall():
            secret = self._row_to_secret(row)

            # Filter by tags if specified
            if tags:
                if not any(t in secret.tags for t in tags):
                    continue

            yield secret

    def _row_to_secret(self, row: sqlite3.Row) -> SecretEntry:
        """Convert database row to SecretEntry."""
        return SecretEntry(
            id=row["id"],
            name=row["name"],
            description=row["description"],
            secret_type=SecretType(row["secret_type"]),
            secret_value=row["secret_value"],
            version=row["version"],
            enabled=bool(row["enabled"]),
            rotation_enabled=bool(row["rotation_enabled"]),
            rotation_days=row["rotation_days"],
            last_rotated=datetime.fromisoformat(row["last_rotated"]) if row["last_rotated"] else None,
            expires_at=datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None,
            owner_user_id=row["owner_user_id"],
            owner_group=row["owner_group"],
            allowed_users=json.loads(row["allowed_users"] or "[]"),
            allowed_groups=json.loads(row["allowed_groups"] or "[]"),
            allowed_arns=json.loads(row["allowed_arns"] or "[]"),
            linked_resources=json.loads(row["linked_resources"] or "[]"),
            tags=json.loads(row["tags"] or "[]"),
            custom_fields=json.loads(row["custom_fields"] or "{}"),
            confidant_id=row["confidant_id"],
            confidant_revision=row["confidant_revision"],
            created_at=datetime.fromisoformat(row["created_at"]) if row["created_at"] else None,
            updated_at=datetime.fromisoformat(row["updated_at"]) if row["updated_at"] else None,
            accessed_at=datetime.fromisoformat(row["accessed_at"]) if row["accessed_at"] else None,
        )

    # User operations
    def create_user(self, user: UserEntry) -> str:
        """Create a new user."""
        if not user.id:
            user.id = self._generate_id("usr")

        user.created_at = datetime.now()
        user.updated_at = datetime.now()

        cursor = self._conn.cursor()
        cursor.execute("""
            INSERT INTO users (
                id, username, email, full_name, password_hash, ssh_public_keys,
                uid, gid, home_directory, shell, gecos, groups, primary_group,
                aws_arns, aws_account_id, enabled, locked, password_expires,
                last_login, is_admin, can_create_secrets, can_delete_secrets,
                linked_resources, tags, custom_fields, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            user.id,
            user.username,
            user.email,
            user.full_name,
            user.password_hash,
            json.dumps(user.ssh_public_keys),
            user.uid,
            user.gid,
            user.home_directory,
            user.shell,
            user.gecos,
            json.dumps(user.groups),
            user.primary_group,
            json.dumps(user.aws_arns),
            user.aws_account_id,
            int(user.enabled),
            int(user.locked),
            user.password_expires.isoformat() if user.password_expires else None,
            user.last_login.isoformat() if user.last_login else None,
            int(user.is_admin),
            int(user.can_create_secrets),
            int(user.can_delete_secrets),
            json.dumps(user.linked_resources),
            json.dumps(user.tags),
            json.dumps(user.custom_fields),
            user.created_at.isoformat(),
            user.updated_at.isoformat(),
        ))
        self._conn.commit()
        return user.id

    def get_user(self, user_id: str) -> UserEntry | None:
        """Get a user by ID."""
        cursor = self._conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        if not row:
            return None
        return self._row_to_user(row)

    def get_user_by_username(self, username: str) -> UserEntry | None:
        """Get a user by username."""
        cursor = self._conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        if not row:
            return None
        return self._row_to_user(row)

    def update_user(self, user: UserEntry) -> bool:
        """Update an existing user."""
        if not user.id:
            return False

        user.updated_at = datetime.now()

        cursor = self._conn.cursor()
        cursor.execute("""
            UPDATE users SET
                username = ?, email = ?, full_name = ?, password_hash = ?,
                ssh_public_keys = ?, uid = ?, gid = ?, home_directory = ?,
                shell = ?, gecos = ?, groups = ?, primary_group = ?,
                aws_arns = ?, aws_account_id = ?, enabled = ?, locked = ?,
                password_expires = ?, last_login = ?, is_admin = ?,
                can_create_secrets = ?, can_delete_secrets = ?,
                linked_resources = ?, tags = ?, custom_fields = ?, updated_at = ?
            WHERE id = ?
        """, (
            user.username,
            user.email,
            user.full_name,
            user.password_hash,
            json.dumps(user.ssh_public_keys),
            user.uid,
            user.gid,
            user.home_directory,
            user.shell,
            user.gecos,
            json.dumps(user.groups),
            user.primary_group,
            json.dumps(user.aws_arns),
            user.aws_account_id,
            int(user.enabled),
            int(user.locked),
            user.password_expires.isoformat() if user.password_expires else None,
            user.last_login.isoformat() if user.last_login else None,
            int(user.is_admin),
            int(user.can_create_secrets),
            int(user.can_delete_secrets),
            json.dumps(user.linked_resources),
            json.dumps(user.tags),
            json.dumps(user.custom_fields),
            user.updated_at.isoformat(),
            user.id,
        ))
        self._conn.commit()
        return cursor.rowcount > 0

    def delete_user(self, user_id: str) -> bool:
        """Delete a user."""
        cursor = self._conn.cursor()
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        self._conn.commit()
        return cursor.rowcount > 0

    def list_users(
        self,
        group: str | None = None,
        enabled: bool | None = None,
    ) -> Iterator[UserEntry]:
        """List users with optional filtering."""
        query = "SELECT * FROM users WHERE 1=1"
        params = []

        if enabled is not None:
            query += " AND enabled = ?"
            params.append(int(enabled))

        cursor = self._conn.cursor()
        cursor.execute(query, params)

        for row in cursor.fetchall():
            user = self._row_to_user(row)

            # Filter by group if specified
            if group and group not in user.groups:
                continue

            yield user

    def _row_to_user(self, row: sqlite3.Row) -> UserEntry:
        """Convert database row to UserEntry."""
        return UserEntry(
            id=row["id"],
            username=row["username"],
            email=row["email"],
            full_name=row["full_name"],
            password_hash=row["password_hash"],
            ssh_public_keys=json.loads(row["ssh_public_keys"] or "[]"),
            uid=row["uid"],
            gid=row["gid"],
            home_directory=row["home_directory"],
            shell=row["shell"] or "/bin/bash",
            gecos=row["gecos"],
            groups=json.loads(row["groups"] or "[]"),
            primary_group=row["primary_group"],
            aws_arns=json.loads(row["aws_arns"] or "[]"),
            aws_account_id=row["aws_account_id"],
            enabled=bool(row["enabled"]),
            locked=bool(row["locked"]),
            password_expires=datetime.fromisoformat(row["password_expires"]) if row["password_expires"] else None,
            last_login=datetime.fromisoformat(row["last_login"]) if row["last_login"] else None,
            is_admin=bool(row["is_admin"]),
            can_create_secrets=bool(row["can_create_secrets"]),
            can_delete_secrets=bool(row["can_delete_secrets"]),
            linked_resources=json.loads(row["linked_resources"] or "[]"),
            tags=json.loads(row["tags"] or "[]"),
            custom_fields=json.loads(row["custom_fields"] or "{}"),
            created_at=datetime.fromisoformat(row["created_at"]) if row["created_at"] else None,
            updated_at=datetime.fromisoformat(row["updated_at"]) if row["updated_at"] else None,
        )

    # ARN operations
    def create_arn_link(self, arn_link: ARNLink) -> str:
        """Create an ARN link."""
        if not arn_link.id:
            arn_link.id = self._generate_id("arn")

        arn_link.created_at = datetime.now()
        arn_link.updated_at = datetime.now()

        # Parse ARN components
        parsed = arn_link.parse_arn()
        if parsed:
            arn_link.aws_account_id = arn_link.aws_account_id or parsed.get("account")
            arn_link.aws_region = arn_link.aws_region or parsed.get("region")
            arn_link.service = arn_link.service or parsed.get("service")

        cursor = self._conn.cursor()
        cursor.execute("""
            INSERT INTO arn_links (
                id, arn, aws_account_id, aws_region, service, resource_type,
                resource_id, linked_user_ids, linked_secret_ids, linked_system_ids,
                name, description, tags, created_at, updated_at, last_verified
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            arn_link.id,
            arn_link.arn,
            arn_link.aws_account_id,
            arn_link.aws_region,
            arn_link.service,
            arn_link.resource_type,
            arn_link.resource_id,
            json.dumps(arn_link.linked_user_ids),
            json.dumps(arn_link.linked_secret_ids),
            json.dumps(arn_link.linked_system_ids),
            arn_link.name,
            arn_link.description,
            json.dumps(arn_link.tags),
            arn_link.created_at.isoformat(),
            arn_link.updated_at.isoformat(),
            arn_link.last_verified.isoformat() if arn_link.last_verified else None,
        ))
        self._conn.commit()
        return arn_link.id

    def get_arn_link(self, link_id: str) -> ARNLink | None:
        """Get an ARN link by ID."""
        cursor = self._conn.cursor()
        cursor.execute("SELECT * FROM arn_links WHERE id = ?", (link_id,))
        row = cursor.fetchone()
        if not row:
            return None
        return self._row_to_arn_link(row)

    def get_arn_link_by_arn(self, arn: str) -> ARNLink | None:
        """Get an ARN link by ARN string."""
        cursor = self._conn.cursor()
        cursor.execute("SELECT * FROM arn_links WHERE arn = ?", (arn,))
        row = cursor.fetchone()
        if not row:
            return None
        return self._row_to_arn_link(row)

    def update_arn_link(self, arn_link: ARNLink) -> bool:
        """Update an ARN link."""
        if not arn_link.id:
            return False

        arn_link.updated_at = datetime.now()

        cursor = self._conn.cursor()
        cursor.execute("""
            UPDATE arn_links SET
                arn = ?, aws_account_id = ?, aws_region = ?, service = ?,
                resource_type = ?, resource_id = ?, linked_user_ids = ?,
                linked_secret_ids = ?, linked_system_ids = ?, name = ?,
                description = ?, tags = ?, updated_at = ?, last_verified = ?
            WHERE id = ?
        """, (
            arn_link.arn,
            arn_link.aws_account_id,
            arn_link.aws_region,
            arn_link.service,
            arn_link.resource_type,
            arn_link.resource_id,
            json.dumps(arn_link.linked_user_ids),
            json.dumps(arn_link.linked_secret_ids),
            json.dumps(arn_link.linked_system_ids),
            arn_link.name,
            arn_link.description,
            json.dumps(arn_link.tags),
            arn_link.updated_at.isoformat(),
            arn_link.last_verified.isoformat() if arn_link.last_verified else None,
            arn_link.id,
        ))
        self._conn.commit()
        return cursor.rowcount > 0

    def delete_arn_link(self, link_id: str) -> bool:
        """Delete an ARN link."""
        cursor = self._conn.cursor()
        cursor.execute("DELETE FROM arn_links WHERE id = ?", (link_id,))
        self._conn.commit()
        return cursor.rowcount > 0

    def list_arn_links(
        self,
        aws_account_id: str | None = None,
        service: str | None = None,
    ) -> Iterator[ARNLink]:
        """List ARN links with optional filtering."""
        query = "SELECT * FROM arn_links WHERE 1=1"
        params = []

        if aws_account_id:
            query += " AND aws_account_id = ?"
            params.append(aws_account_id)

        if service:
            query += " AND service = ?"
            params.append(service)

        cursor = self._conn.cursor()
        cursor.execute(query, params)

        for row in cursor.fetchall():
            yield self._row_to_arn_link(row)

    def _row_to_arn_link(self, row: sqlite3.Row) -> ARNLink:
        """Convert database row to ARNLink."""
        return ARNLink(
            id=row["id"],
            arn=row["arn"],
            aws_account_id=row["aws_account_id"],
            aws_region=row["aws_region"],
            service=row["service"],
            resource_type=row["resource_type"],
            resource_id=row["resource_id"],
            linked_user_ids=json.loads(row["linked_user_ids"] or "[]"),
            linked_secret_ids=json.loads(row["linked_secret_ids"] or "[]"),
            linked_system_ids=json.loads(row["linked_system_ids"] or "[]"),
            name=row["name"],
            description=row["description"],
            tags=json.loads(row["tags"] or "[]"),
            created_at=datetime.fromisoformat(row["created_at"]) if row["created_at"] else None,
            updated_at=datetime.fromisoformat(row["updated_at"]) if row["updated_at"] else None,
            last_verified=datetime.fromisoformat(row["last_verified"]) if row["last_verified"] else None,
        )

    # Resource operations
    def create_resource_link(self, resource: ResourceLink) -> str:
        """Create a resource link."""
        if not resource.id:
            resource.id = self._generate_id("res")

        resource.created_at = datetime.now()
        resource.updated_at = datetime.now()

        cursor = self._conn.cursor()
        cursor.execute("""
            INSERT INTO resource_links (
                id, resource_type, resource_id, resource_name,
                linked_secret_ids, linked_user_ids, linked_arn_ids,
                inventory_system_id, description, tags, custom_fields,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            resource.id,
            resource.resource_type.value,
            resource.resource_id,
            resource.resource_name,
            json.dumps(resource.linked_secret_ids),
            json.dumps(resource.linked_user_ids),
            json.dumps(resource.linked_arn_ids),
            resource.inventory_system_id,
            resource.description,
            json.dumps(resource.tags),
            json.dumps(resource.custom_fields),
            resource.created_at.isoformat(),
            resource.updated_at.isoformat(),
        ))
        self._conn.commit()
        return resource.id

    def get_resource_link(self, link_id: str) -> ResourceLink | None:
        """Get a resource link by ID."""
        cursor = self._conn.cursor()
        cursor.execute("SELECT * FROM resource_links WHERE id = ?", (link_id,))
        row = cursor.fetchone()
        if not row:
            return None
        return self._row_to_resource_link(row)

    def update_resource_link(self, resource: ResourceLink) -> bool:
        """Update a resource link."""
        if not resource.id:
            return False

        resource.updated_at = datetime.now()

        cursor = self._conn.cursor()
        cursor.execute("""
            UPDATE resource_links SET
                resource_type = ?, resource_id = ?, resource_name = ?,
                linked_secret_ids = ?, linked_user_ids = ?, linked_arn_ids = ?,
                inventory_system_id = ?, description = ?, tags = ?,
                custom_fields = ?, updated_at = ?
            WHERE id = ?
        """, (
            resource.resource_type.value,
            resource.resource_id,
            resource.resource_name,
            json.dumps(resource.linked_secret_ids),
            json.dumps(resource.linked_user_ids),
            json.dumps(resource.linked_arn_ids),
            resource.inventory_system_id,
            resource.description,
            json.dumps(resource.tags),
            json.dumps(resource.custom_fields),
            resource.updated_at.isoformat(),
            resource.id,
        ))
        self._conn.commit()
        return cursor.rowcount > 0

    def delete_resource_link(self, link_id: str) -> bool:
        """Delete a resource link."""
        cursor = self._conn.cursor()
        cursor.execute("DELETE FROM resource_links WHERE id = ?", (link_id,))
        self._conn.commit()
        return cursor.rowcount > 0

    def list_resource_links(
        self,
        resource_type: ResourceType | None = None,
    ) -> Iterator[ResourceLink]:
        """List resource links with optional filtering."""
        query = "SELECT * FROM resource_links WHERE 1=1"
        params = []

        if resource_type:
            query += " AND resource_type = ?"
            params.append(resource_type.value)

        cursor = self._conn.cursor()
        cursor.execute(query, params)

        for row in cursor.fetchall():
            yield self._row_to_resource_link(row)

    def _row_to_resource_link(self, row: sqlite3.Row) -> ResourceLink:
        """Convert database row to ResourceLink."""
        return ResourceLink(
            id=row["id"],
            resource_type=ResourceType(row["resource_type"]),
            resource_id=row["resource_id"],
            resource_name=row["resource_name"],
            linked_secret_ids=json.loads(row["linked_secret_ids"] or "[]"),
            linked_user_ids=json.loads(row["linked_user_ids"] or "[]"),
            linked_arn_ids=json.loads(row["linked_arn_ids"] or "[]"),
            inventory_system_id=row["inventory_system_id"],
            description=row["description"],
            tags=json.loads(row["tags"] or "[]"),
            custom_fields=json.loads(row["custom_fields"] or "{}"),
            created_at=datetime.fromisoformat(row["created_at"]) if row["created_at"] else None,
            updated_at=datetime.fromisoformat(row["updated_at"]) if row["updated_at"] else None,
        )
