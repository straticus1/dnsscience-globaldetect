"""
Secrets management with multiple backend support.

Supports:
- SQLite (local/embedded)
- PostgreSQL (regular, Aurora, RDS)
- Lyft Confidant (secrets management service)

When Confidant is enabled with fallback mode, secrets are checked in Confidant
first, then fall back to the SQL backend.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

from globaldetect.backup.secrets.base import (
    SecretsBackend,
    BackendType,
    SecretEntry,
    UserEntry,
    ARNLink,
    ResourceLink,
)
from globaldetect.backup.secrets.config import SecretsConfig
from globaldetect.backup.secrets.manager import SecretsManager

__all__ = [
    "SecretsBackend",
    "BackendType",
    "SecretEntry",
    "UserEntry",
    "ARNLink",
    "ResourceLink",
    "SecretsConfig",
    "SecretsManager",
]
