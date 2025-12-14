"""
Configuration for secrets management backends.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from globaldetect.backup.secrets.base import BackendType


@dataclass
class SecretsConfig:
    """Configuration for secrets management."""

    # Backend selection (user picks ONE)
    backend_type: BackendType = BackendType.SQLITE

    # SQLite settings
    sqlite_path: str | Path | None = None

    # PostgreSQL settings (works for regular, Aurora, RDS)
    pg_host: str = "localhost"
    pg_port: int = 5432
    pg_database: str = "globaldetect_secrets"
    pg_user: str = "globaldetect"
    pg_password: str | None = None
    pg_ssl_mode: str = "prefer"  # disable, allow, prefer, require, verify-ca, verify-full
    pg_ssl_cert: str | None = None
    pg_ssl_key: str | None = None
    pg_ssl_root_cert: str | None = None

    # Aurora-specific settings
    aurora_cluster_endpoint: str | None = None
    aurora_reader_endpoint: str | None = None

    # RDS-specific settings
    rds_instance_identifier: str | None = None
    rds_use_iam_auth: bool = False

    # Confidant settings
    confidant_url: str | None = None
    confidant_auth_key: str | None = None
    confidant_auth_context: dict[str, str] = field(default_factory=dict)
    confidant_token_version: int = 2
    confidant_user_type: str = "service"  # service or user

    # Confidant fallback mode
    # When enabled, check Confidant first, then fall back to SQL backend
    confidant_enabled: bool = False
    confidant_fallback: bool = True  # Fall back to SQL if Confidant fails

    # Encryption key for local storage (derived from master password)
    encryption_key: bytes | None = None
    master_password: str | None = None

    # Cache settings
    cache_enabled: bool = True
    cache_ttl_seconds: int = 300  # 5 minutes

    @classmethod
    def from_env(cls) -> "SecretsConfig":
        """Load configuration from environment variables."""
        backend_str = os.environ.get("GLOBALDETECT_SECRETS_BACKEND", "sqlite")
        try:
            backend_type = BackendType(backend_str.lower())
        except ValueError:
            backend_type = BackendType.SQLITE

        config = cls(
            backend_type=backend_type,

            # SQLite
            sqlite_path=os.environ.get("GLOBALDETECT_SECRETS_SQLITE_PATH"),

            # PostgreSQL
            pg_host=os.environ.get("GLOBALDETECT_SECRETS_PG_HOST", "localhost"),
            pg_port=int(os.environ.get("GLOBALDETECT_SECRETS_PG_PORT", "5432")),
            pg_database=os.environ.get("GLOBALDETECT_SECRETS_PG_DATABASE", "globaldetect_secrets"),
            pg_user=os.environ.get("GLOBALDETECT_SECRETS_PG_USER", "globaldetect"),
            pg_password=os.environ.get("GLOBALDETECT_SECRETS_PG_PASSWORD"),
            pg_ssl_mode=os.environ.get("GLOBALDETECT_SECRETS_PG_SSL_MODE", "prefer"),

            # Aurora
            aurora_cluster_endpoint=os.environ.get("GLOBALDETECT_SECRETS_AURORA_ENDPOINT"),
            aurora_reader_endpoint=os.environ.get("GLOBALDETECT_SECRETS_AURORA_READER"),

            # RDS
            rds_instance_identifier=os.environ.get("GLOBALDETECT_SECRETS_RDS_INSTANCE"),
            rds_use_iam_auth=os.environ.get("GLOBALDETECT_SECRETS_RDS_IAM_AUTH", "").lower() == "true",

            # Confidant
            confidant_url=os.environ.get("GLOBALDETECT_CONFIDANT_URL"),
            confidant_auth_key=os.environ.get("GLOBALDETECT_CONFIDANT_AUTH_KEY"),
            confidant_enabled=os.environ.get("GLOBALDETECT_CONFIDANT_ENABLED", "").lower() in ("true", "yes", "1"),
            confidant_fallback=os.environ.get("GLOBALDETECT_CONFIDANT_FALLBACK", "true").lower() in ("true", "yes", "1"),

            # Encryption
            master_password=os.environ.get("GLOBALDETECT_SECRETS_MASTER_PASSWORD"),
        )

        return config

    def get_sqlite_path(self) -> Path:
        """Get SQLite database path."""
        if self.sqlite_path:
            return Path(self.sqlite_path)
        return Path.home() / ".globaldetect" / "secrets" / "secrets.db"

    def get_pg_connection_string(self) -> str:
        """Get PostgreSQL connection string."""
        # Handle Aurora/RDS endpoints
        host = self.pg_host
        if self.backend_type == BackendType.AURORA_POSTGRESQL and self.aurora_cluster_endpoint:
            host = self.aurora_cluster_endpoint
        elif self.backend_type == BackendType.RDS_POSTGRESQL and self.rds_instance_identifier:
            # RDS endpoint format: <instance-id>.<region>.rds.amazonaws.com
            host = self.pg_host  # Should be set to RDS endpoint

        password_part = f":{self.pg_password}" if self.pg_password else ""
        ssl_part = f"?sslmode={self.pg_ssl_mode}" if self.pg_ssl_mode != "disable" else ""

        return f"postgresql://{self.pg_user}{password_part}@{host}:{self.pg_port}/{self.pg_database}{ssl_part}"

    def validate(self) -> list[str]:
        """Validate configuration. Returns list of errors."""
        errors = []

        if self.backend_type in (BackendType.POSTGRESQL, BackendType.AURORA_POSTGRESQL, BackendType.RDS_POSTGRESQL):
            if not self.pg_host and not self.aurora_cluster_endpoint:
                errors.append("PostgreSQL host or Aurora endpoint required")
            if not self.pg_password and not self.rds_use_iam_auth:
                errors.append("PostgreSQL password required (or enable IAM auth for RDS)")

        if self.backend_type == BackendType.CONFIDANT:
            if not self.confidant_url:
                errors.append("Confidant URL required")
            if not self.confidant_auth_key:
                errors.append("Confidant auth key required")

        if self.confidant_enabled and not self.confidant_url:
            errors.append("Confidant URL required when Confidant is enabled")

        return errors

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary (excludes sensitive values)."""
        return {
            "backend_type": self.backend_type.value,
            "sqlite_path": str(self.sqlite_path) if self.sqlite_path else None,
            "pg_host": self.pg_host,
            "pg_port": self.pg_port,
            "pg_database": self.pg_database,
            "pg_user": self.pg_user,
            "pg_ssl_mode": self.pg_ssl_mode,
            "aurora_cluster_endpoint": self.aurora_cluster_endpoint,
            "rds_instance_identifier": self.rds_instance_identifier,
            "rds_use_iam_auth": self.rds_use_iam_auth,
            "confidant_url": self.confidant_url,
            "confidant_enabled": self.confidant_enabled,
            "confidant_fallback": self.confidant_fallback,
            "cache_enabled": self.cache_enabled,
            "cache_ttl_seconds": self.cache_ttl_seconds,
        }
