"""
PostgreSQL backend for secrets storage.

Supports regular PostgreSQL, Aurora PostgreSQL, and AWS RDS PostgreSQL.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import json
import secrets as py_secrets
from datetime import datetime
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


class PostgreSQLBackend(SecretsBackend):
    """PostgreSQL-based secrets storage backend.

    Works with regular PostgreSQL, Aurora PostgreSQL, and RDS PostgreSQL.
    """

    BACKEND_TYPE = BackendType.POSTGRESQL

    SCHEMA_VERSION = 1

    def __init__(self, config: SecretsConfig):
        """Initialize PostgreSQL backend.

        Args:
            config: Secrets configuration
        """
        self.config = config
        self._conn = None
        self._pool = None

    def initialize(self) -> None:
        """Initialize database connection and create tables."""
        try:
            import psycopg2
            from psycopg2.extras import RealDictCursor

            connect_kwargs = {
                "host": self.config.pg_host,
                "port": self.config.pg_port,
                "database": self.config.pg_database,
                "user": self.config.pg_user,
                "cursor_factory": RealDictCursor,
            }

            # Handle Aurora endpoint
            if self.config.aurora_cluster_endpoint:
                connect_kwargs["host"] = self.config.aurora_cluster_endpoint

            # Handle password or IAM auth
            if self.config.rds_use_iam_auth:
                # Generate IAM auth token
                connect_kwargs["password"] = self._get_rds_auth_token()
            elif self.config.pg_password:
                connect_kwargs["password"] = self.config.pg_password

            # SSL mode
            if self.config.pg_ssl_mode != "disable":
                connect_kwargs["sslmode"] = self.config.pg_ssl_mode
                if self.config.pg_ssl_cert:
                    connect_kwargs["sslcert"] = self.config.pg_ssl_cert
                if self.config.pg_ssl_key:
                    connect_kwargs["sslkey"] = self.config.pg_ssl_key
                if self.config.pg_ssl_root_cert:
                    connect_kwargs["sslrootcert"] = self.config.pg_ssl_root_cert

            self._conn = psycopg2.connect(**connect_kwargs)
            self._create_tables()

        except ImportError:
            raise ImportError("psycopg2 required for PostgreSQL backend. Install with: pip install psycopg2-binary")

    def _get_rds_auth_token(self) -> str:
        """Generate RDS IAM authentication token."""
        try:
            import boto3

            client = boto3.client("rds")
            token = client.generate_db_auth_token(
                DBHostname=self.config.pg_host,
                Port=self.config.pg_port,
                DBUsername=self.config.pg_user,
            )
            return token
        except ImportError:
            raise ImportError("boto3 required for RDS IAM auth. Install with: pip install boto3")

    def close(self) -> None:
        """Close database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None

    def _create_tables(self) -> None:
        """Create database tables."""
        cursor = self._conn.cursor()

        # Secrets table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS secrets (
                id TEXT PRIMARY KEY,
                name TEXT UNIQUE NOT NULL,
                description TEXT,
                secret_type TEXT NOT NULL,
                secret_value TEXT,
                version INTEGER DEFAULT 1,
                enabled BOOLEAN DEFAULT TRUE,
                rotation_enabled BOOLEAN DEFAULT FALSE,
                rotation_days INTEGER,
                last_rotated TIMESTAMP,
                expires_at TIMESTAMP,
                owner_user_id TEXT,
                owner_group TEXT,
                allowed_users JSONB DEFAULT '[]',
                allowed_groups JSONB DEFAULT '[]',
                allowed_arns JSONB DEFAULT '[]',
                linked_resources JSONB DEFAULT '[]',
                tags JSONB DEFAULT '[]',
                custom_fields JSONB DEFAULT '{}',
                confidant_id TEXT,
                confidant_revision INTEGER,
                created_at TIMESTAMP DEFAULT NOW(),
                updated_at TIMESTAMP DEFAULT NOW(),
                accessed_at TIMESTAMP
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
                ssh_public_keys JSONB DEFAULT '[]',
                uid INTEGER,
                gid INTEGER,
                home_directory TEXT,
                shell TEXT DEFAULT '/bin/bash',
                gecos TEXT,
                groups JSONB DEFAULT '[]',
                primary_group TEXT,
                aws_arns JSONB DEFAULT '[]',
                aws_account_id TEXT,
                enabled BOOLEAN DEFAULT TRUE,
                locked BOOLEAN DEFAULT FALSE,
                password_expires TIMESTAMP,
                last_login TIMESTAMP,
                is_admin BOOLEAN DEFAULT FALSE,
                can_create_secrets BOOLEAN DEFAULT TRUE,
                can_delete_secrets BOOLEAN DEFAULT FALSE,
                linked_resources JSONB DEFAULT '[]',
                tags JSONB DEFAULT '[]',
                custom_fields JSONB DEFAULT '{}',
                mfa_config JSONB DEFAULT '{}',
                created_at TIMESTAMP DEFAULT NOW(),
                updated_at TIMESTAMP DEFAULT NOW()
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
                linked_user_ids JSONB DEFAULT '[]',
                linked_secret_ids JSONB DEFAULT '[]',
                linked_system_ids JSONB DEFAULT '[]',
                name TEXT,
                description TEXT,
                tags JSONB DEFAULT '[]',
                created_at TIMESTAMP DEFAULT NOW(),
                updated_at TIMESTAMP DEFAULT NOW(),
                last_verified TIMESTAMP
            )
        """)

        # Resource links table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS resource_links (
                id TEXT PRIMARY KEY,
                resource_type TEXT NOT NULL,
                resource_id TEXT,
                resource_name TEXT,
                linked_secret_ids JSONB DEFAULT '[]',
                linked_user_ids JSONB DEFAULT '[]',
                linked_arn_ids JSONB DEFAULT '[]',
                inventory_system_id INTEGER,
                description TEXT,
                tags JSONB DEFAULT '[]',
                custom_fields JSONB DEFAULT '{}',
                created_at TIMESTAMP DEFAULT NOW(),
                updated_at TIMESTAMP DEFAULT NOW()
            )
        """)

        # MFA tokens table (for TOTP seeds, S/KEY sequences, etc.)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS mfa_tokens (
                id TEXT PRIMARY KEY,
                user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
                mfa_type TEXT NOT NULL,
                name TEXT,
                token_data JSONB NOT NULL,
                enabled BOOLEAN DEFAULT TRUE,
                last_used TIMESTAMP,
                created_at TIMESTAMP DEFAULT NOW(),
                updated_at TIMESTAMP DEFAULT NOW()
            )
        """)

        # SSH keys table (separate for better management)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ssh_keys (
                id TEXT PRIMARY KEY,
                user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
                name TEXT,
                public_key TEXT NOT NULL,
                private_key_encrypted TEXT,
                key_type TEXT,
                fingerprint TEXT,
                comment TEXT,
                enabled BOOLEAN DEFAULT TRUE,
                expires_at TIMESTAMP,
                last_used TIMESTAMP,
                created_at TIMESTAMP DEFAULT NOW()
            )
        """)

        # Create indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_secrets_name ON secrets(name)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_secrets_type ON secrets(secret_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_arn_links_arn ON arn_links(arn)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_mfa_tokens_user ON mfa_tokens(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_ssh_keys_user ON ssh_keys(user_id)")

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
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            secret.id,
            secret.name,
            secret.description,
            secret.secret_type.value,
            secret.secret_value,
            secret.version,
            secret.enabled,
            secret.rotation_enabled,
            secret.rotation_days,
            secret.last_rotated,
            secret.expires_at,
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
            secret.created_at,
            secret.updated_at,
            secret.accessed_at,
        ))
        self._conn.commit()
        return secret.id

    def get_secret(self, secret_id: str) -> SecretEntry | None:
        """Get a secret by ID."""
        cursor = self._conn.cursor()
        cursor.execute("SELECT * FROM secrets WHERE id = %s", (secret_id,))
        row = cursor.fetchone()
        if not row:
            return None
        return self._row_to_secret(row)

    def get_secret_by_name(self, name: str) -> SecretEntry | None:
        """Get a secret by name."""
        cursor = self._conn.cursor()
        cursor.execute("SELECT * FROM secrets WHERE name = %s", (name,))
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
                name = %s, description = %s, secret_type = %s, secret_value = %s,
                version = %s, enabled = %s, rotation_enabled = %s, rotation_days = %s,
                last_rotated = %s, expires_at = %s, owner_user_id = %s, owner_group = %s,
                allowed_users = %s, allowed_groups = %s, allowed_arns = %s,
                linked_resources = %s, tags = %s, custom_fields = %s,
                confidant_id = %s, confidant_revision = %s, updated_at = %s
            WHERE id = %s
        """, (
            secret.name,
            secret.description,
            secret.secret_type.value,
            secret.secret_value,
            secret.version,
            secret.enabled,
            secret.rotation_enabled,
            secret.rotation_days,
            secret.last_rotated,
            secret.expires_at,
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
            secret.updated_at,
            secret.id,
        ))
        self._conn.commit()
        return cursor.rowcount > 0

    def delete_secret(self, secret_id: str) -> bool:
        """Delete a secret."""
        cursor = self._conn.cursor()
        cursor.execute("DELETE FROM secrets WHERE id = %s", (secret_id,))
        self._conn.commit()
        return cursor.rowcount > 0

    def list_secrets(
        self,
        secret_type: SecretType | None = None,
        owner_user_id: str | None = None,
        tags: list[str] | None = None,
    ) -> Iterator[SecretEntry]:
        """List secrets with optional filtering."""
        query = "SELECT * FROM secrets WHERE TRUE"
        params = []

        if secret_type:
            query += " AND secret_type = %s"
            params.append(secret_type.value)

        if owner_user_id:
            query += " AND owner_user_id = %s"
            params.append(owner_user_id)

        if tags:
            query += " AND tags ?| %s"
            params.append(tags)

        cursor = self._conn.cursor()
        cursor.execute(query, params)

        for row in cursor.fetchall():
            yield self._row_to_secret(row)

    def _row_to_secret(self, row: dict) -> SecretEntry:
        """Convert database row to SecretEntry."""
        return SecretEntry(
            id=row["id"],
            name=row["name"],
            description=row["description"],
            secret_type=SecretType(row["secret_type"]),
            secret_value=row["secret_value"],
            version=row["version"],
            enabled=row["enabled"],
            rotation_enabled=row["rotation_enabled"],
            rotation_days=row["rotation_days"],
            last_rotated=row["last_rotated"],
            expires_at=row["expires_at"],
            owner_user_id=row["owner_user_id"],
            owner_group=row["owner_group"],
            allowed_users=row["allowed_users"] or [],
            allowed_groups=row["allowed_groups"] or [],
            allowed_arns=row["allowed_arns"] or [],
            linked_resources=row["linked_resources"] or [],
            tags=row["tags"] or [],
            custom_fields=row["custom_fields"] or {},
            confidant_id=row["confidant_id"],
            confidant_revision=row["confidant_revision"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            accessed_at=row["accessed_at"],
        )

    # User operations (similar pattern to SQLite, using %s placeholders)
    def create_user(self, user: UserEntry) -> str:
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
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            user.id, user.username, user.email, user.full_name, user.password_hash,
            json.dumps(user.ssh_public_keys), user.uid, user.gid, user.home_directory,
            user.shell, user.gecos, json.dumps(user.groups), user.primary_group,
            json.dumps(user.aws_arns), user.aws_account_id, user.enabled, user.locked,
            user.password_expires, user.last_login, user.is_admin, user.can_create_secrets,
            user.can_delete_secrets, json.dumps(user.linked_resources), json.dumps(user.tags),
            json.dumps(user.custom_fields), user.created_at, user.updated_at,
        ))
        self._conn.commit()
        return user.id

    def get_user(self, user_id: str) -> UserEntry | None:
        cursor = self._conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        row = cursor.fetchone()
        return self._row_to_user(row) if row else None

    def get_user_by_username(self, username: str) -> UserEntry | None:
        cursor = self._conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        row = cursor.fetchone()
        return self._row_to_user(row) if row else None

    def update_user(self, user: UserEntry) -> bool:
        if not user.id:
            return False
        user.updated_at = datetime.now()

        cursor = self._conn.cursor()
        cursor.execute("""
            UPDATE users SET
                username = %s, email = %s, full_name = %s, password_hash = %s,
                ssh_public_keys = %s, uid = %s, gid = %s, home_directory = %s,
                shell = %s, gecos = %s, groups = %s, primary_group = %s,
                aws_arns = %s, aws_account_id = %s, enabled = %s, locked = %s,
                password_expires = %s, last_login = %s, is_admin = %s,
                can_create_secrets = %s, can_delete_secrets = %s,
                linked_resources = %s, tags = %s, custom_fields = %s, updated_at = %s
            WHERE id = %s
        """, (
            user.username, user.email, user.full_name, user.password_hash,
            json.dumps(user.ssh_public_keys), user.uid, user.gid, user.home_directory,
            user.shell, user.gecos, json.dumps(user.groups), user.primary_group,
            json.dumps(user.aws_arns), user.aws_account_id, user.enabled, user.locked,
            user.password_expires, user.last_login, user.is_admin, user.can_create_secrets,
            user.can_delete_secrets, json.dumps(user.linked_resources), json.dumps(user.tags),
            json.dumps(user.custom_fields), user.updated_at, user.id,
        ))
        self._conn.commit()
        return cursor.rowcount > 0

    def delete_user(self, user_id: str) -> bool:
        cursor = self._conn.cursor()
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        self._conn.commit()
        return cursor.rowcount > 0

    def list_users(self, group: str | None = None, enabled: bool | None = None) -> Iterator[UserEntry]:
        query = "SELECT * FROM users WHERE TRUE"
        params = []
        if enabled is not None:
            query += " AND enabled = %s"
            params.append(enabled)

        cursor = self._conn.cursor()
        cursor.execute(query, params)

        for row in cursor.fetchall():
            user = self._row_to_user(row)
            if group and group not in user.groups:
                continue
            yield user

    def _row_to_user(self, row: dict) -> UserEntry:
        return UserEntry(
            id=row["id"],
            username=row["username"],
            email=row["email"],
            full_name=row["full_name"],
            password_hash=row["password_hash"],
            ssh_public_keys=row["ssh_public_keys"] or [],
            uid=row["uid"],
            gid=row["gid"],
            home_directory=row["home_directory"],
            shell=row["shell"] or "/bin/bash",
            gecos=row["gecos"],
            groups=row["groups"] or [],
            primary_group=row["primary_group"],
            aws_arns=row["aws_arns"] or [],
            aws_account_id=row["aws_account_id"],
            enabled=row["enabled"],
            locked=row["locked"],
            password_expires=row["password_expires"],
            last_login=row["last_login"],
            is_admin=row["is_admin"],
            can_create_secrets=row["can_create_secrets"],
            can_delete_secrets=row["can_delete_secrets"],
            linked_resources=row["linked_resources"] or [],
            tags=row["tags"] or [],
            custom_fields=row["custom_fields"] or {},
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    # ARN operations
    def create_arn_link(self, arn_link: ARNLink) -> str:
        if not arn_link.id:
            arn_link.id = self._generate_id("arn")
        arn_link.created_at = datetime.now()
        arn_link.updated_at = datetime.now()

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
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            arn_link.id, arn_link.arn, arn_link.aws_account_id, arn_link.aws_region,
            arn_link.service, arn_link.resource_type, arn_link.resource_id,
            json.dumps(arn_link.linked_user_ids), json.dumps(arn_link.linked_secret_ids),
            json.dumps(arn_link.linked_system_ids), arn_link.name, arn_link.description,
            json.dumps(arn_link.tags), arn_link.created_at, arn_link.updated_at, arn_link.last_verified,
        ))
        self._conn.commit()
        return arn_link.id

    def get_arn_link(self, link_id: str) -> ARNLink | None:
        cursor = self._conn.cursor()
        cursor.execute("SELECT * FROM arn_links WHERE id = %s", (link_id,))
        row = cursor.fetchone()
        return self._row_to_arn_link(row) if row else None

    def get_arn_link_by_arn(self, arn: str) -> ARNLink | None:
        cursor = self._conn.cursor()
        cursor.execute("SELECT * FROM arn_links WHERE arn = %s", (arn,))
        row = cursor.fetchone()
        return self._row_to_arn_link(row) if row else None

    def update_arn_link(self, arn_link: ARNLink) -> bool:
        if not arn_link.id:
            return False
        arn_link.updated_at = datetime.now()

        cursor = self._conn.cursor()
        cursor.execute("""
            UPDATE arn_links SET
                arn = %s, aws_account_id = %s, aws_region = %s, service = %s,
                resource_type = %s, resource_id = %s, linked_user_ids = %s,
                linked_secret_ids = %s, linked_system_ids = %s, name = %s,
                description = %s, tags = %s, updated_at = %s, last_verified = %s
            WHERE id = %s
        """, (
            arn_link.arn, arn_link.aws_account_id, arn_link.aws_region, arn_link.service,
            arn_link.resource_type, arn_link.resource_id, json.dumps(arn_link.linked_user_ids),
            json.dumps(arn_link.linked_secret_ids), json.dumps(arn_link.linked_system_ids),
            arn_link.name, arn_link.description, json.dumps(arn_link.tags),
            arn_link.updated_at, arn_link.last_verified, arn_link.id,
        ))
        self._conn.commit()
        return cursor.rowcount > 0

    def delete_arn_link(self, link_id: str) -> bool:
        cursor = self._conn.cursor()
        cursor.execute("DELETE FROM arn_links WHERE id = %s", (link_id,))
        self._conn.commit()
        return cursor.rowcount > 0

    def list_arn_links(self, aws_account_id: str | None = None, service: str | None = None) -> Iterator[ARNLink]:
        query = "SELECT * FROM arn_links WHERE TRUE"
        params = []
        if aws_account_id:
            query += " AND aws_account_id = %s"
            params.append(aws_account_id)
        if service:
            query += " AND service = %s"
            params.append(service)

        cursor = self._conn.cursor()
        cursor.execute(query, params)
        for row in cursor.fetchall():
            yield self._row_to_arn_link(row)

    def _row_to_arn_link(self, row: dict) -> ARNLink:
        return ARNLink(
            id=row["id"], arn=row["arn"], aws_account_id=row["aws_account_id"],
            aws_region=row["aws_region"], service=row["service"],
            resource_type=row["resource_type"], resource_id=row["resource_id"],
            linked_user_ids=row["linked_user_ids"] or [],
            linked_secret_ids=row["linked_secret_ids"] or [],
            linked_system_ids=row["linked_system_ids"] or [],
            name=row["name"], description=row["description"], tags=row["tags"] or [],
            created_at=row["created_at"], updated_at=row["updated_at"],
            last_verified=row["last_verified"],
        )

    # Resource operations
    def create_resource_link(self, resource: ResourceLink) -> str:
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
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            resource.id, resource.resource_type.value, resource.resource_id,
            resource.resource_name, json.dumps(resource.linked_secret_ids),
            json.dumps(resource.linked_user_ids), json.dumps(resource.linked_arn_ids),
            resource.inventory_system_id, resource.description, json.dumps(resource.tags),
            json.dumps(resource.custom_fields), resource.created_at, resource.updated_at,
        ))
        self._conn.commit()
        return resource.id

    def get_resource_link(self, link_id: str) -> ResourceLink | None:
        cursor = self._conn.cursor()
        cursor.execute("SELECT * FROM resource_links WHERE id = %s", (link_id,))
        row = cursor.fetchone()
        return self._row_to_resource_link(row) if row else None

    def update_resource_link(self, resource: ResourceLink) -> bool:
        if not resource.id:
            return False
        resource.updated_at = datetime.now()

        cursor = self._conn.cursor()
        cursor.execute("""
            UPDATE resource_links SET
                resource_type = %s, resource_id = %s, resource_name = %s,
                linked_secret_ids = %s, linked_user_ids = %s, linked_arn_ids = %s,
                inventory_system_id = %s, description = %s, tags = %s,
                custom_fields = %s, updated_at = %s
            WHERE id = %s
        """, (
            resource.resource_type.value, resource.resource_id, resource.resource_name,
            json.dumps(resource.linked_secret_ids), json.dumps(resource.linked_user_ids),
            json.dumps(resource.linked_arn_ids), resource.inventory_system_id,
            resource.description, json.dumps(resource.tags), json.dumps(resource.custom_fields),
            resource.updated_at, resource.id,
        ))
        self._conn.commit()
        return cursor.rowcount > 0

    def delete_resource_link(self, link_id: str) -> bool:
        cursor = self._conn.cursor()
        cursor.execute("DELETE FROM resource_links WHERE id = %s", (link_id,))
        self._conn.commit()
        return cursor.rowcount > 0

    def list_resource_links(self, resource_type: ResourceType | None = None) -> Iterator[ResourceLink]:
        query = "SELECT * FROM resource_links WHERE TRUE"
        params = []
        if resource_type:
            query += " AND resource_type = %s"
            params.append(resource_type.value)

        cursor = self._conn.cursor()
        cursor.execute(query, params)
        for row in cursor.fetchall():
            yield self._row_to_resource_link(row)

    def _row_to_resource_link(self, row: dict) -> ResourceLink:
        return ResourceLink(
            id=row["id"], resource_type=ResourceType(row["resource_type"]),
            resource_id=row["resource_id"], resource_name=row["resource_name"],
            linked_secret_ids=row["linked_secret_ids"] or [],
            linked_user_ids=row["linked_user_ids"] or [],
            linked_arn_ids=row["linked_arn_ids"] or [],
            inventory_system_id=row["inventory_system_id"], description=row["description"],
            tags=row["tags"] or [], custom_fields=row["custom_fields"] or {},
            created_at=row["created_at"], updated_at=row["updated_at"],
        )
