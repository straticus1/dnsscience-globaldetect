"""
Secrets manager - unified interface for all backends.

Handles backend selection, Confidant integration with fallback,
and provides additional utilities like password file generation.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import os
import hashlib
import crypt
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


class SecretsManager:
    """Unified secrets management with backend abstraction.

    Supports SQLite, PostgreSQL, and Confidant backends with
    automatic fallback when Confidant is enabled.
    """

    def __init__(self, config: SecretsConfig | None = None):
        """Initialize secrets manager.

        Args:
            config: Configuration (loads from env if not provided)
        """
        self.config = config or SecretsConfig.from_env()
        self._backend: SecretsBackend | None = None
        self._initialized = False

    def initialize(self) -> None:
        """Initialize the backend based on configuration."""
        if self._initialized:
            return

        # Validate config
        errors = self.config.validate()
        if errors:
            raise ValueError(f"Configuration errors: {', '.join(errors)}")

        # Create backend based on type
        self._backend = self._create_backend()
        self._backend.initialize()
        self._initialized = True

    def _create_backend(self) -> SecretsBackend:
        """Create the appropriate backend."""
        from globaldetect.backup.secrets.sqlite_backend import SQLiteBackend
        from globaldetect.backup.secrets.postgresql_backend import PostgreSQLBackend
        from globaldetect.backup.secrets.confidant_backend import ConfidantBackend

        # Always create SQL backend (used standalone or as fallback)
        if self.config.backend_type in (
            BackendType.POSTGRESQL,
            BackendType.AURORA_POSTGRESQL,
            BackendType.RDS_POSTGRESQL,
        ):
            sql_backend = PostgreSQLBackend(self.config)
        else:
            sql_backend = SQLiteBackend(self.config)

        # If Confidant is the primary backend or enabled with fallback
        if self.config.backend_type == BackendType.CONFIDANT:
            return ConfidantBackend(self.config, fallback_backend=sql_backend)

        # If Confidant is enabled for testing (check Confidant first, then SQL)
        if self.config.confidant_enabled:
            return ConfidantBackend(self.config, fallback_backend=sql_backend)

        # Just use SQL backend
        return sql_backend

    def close(self) -> None:
        """Close backend connections."""
        if self._backend:
            self._backend.close()
            self._backend = None
            self._initialized = False

    @property
    def backend(self) -> SecretsBackend:
        """Get the backend, initializing if needed."""
        if not self._initialized:
            self.initialize()
        return self._backend

    # Delegate all operations to backend
    def create_secret(self, secret: SecretEntry) -> str:
        return self.backend.create_secret(secret)

    def get_secret(self, secret_id: str) -> SecretEntry | None:
        return self.backend.get_secret(secret_id)

    def get_secret_by_name(self, name: str) -> SecretEntry | None:
        return self.backend.get_secret_by_name(name)

    def update_secret(self, secret: SecretEntry) -> bool:
        return self.backend.update_secret(secret)

    def delete_secret(self, secret_id: str) -> bool:
        return self.backend.delete_secret(secret_id)

    def list_secrets(
        self,
        secret_type: SecretType | None = None,
        owner_user_id: str | None = None,
        tags: list[str] | None = None,
    ) -> Iterator[SecretEntry]:
        return self.backend.list_secrets(secret_type, owner_user_id, tags)

    def create_user(self, user: UserEntry) -> str:
        return self.backend.create_user(user)

    def get_user(self, user_id: str) -> UserEntry | None:
        return self.backend.get_user(user_id)

    def get_user_by_username(self, username: str) -> UserEntry | None:
        return self.backend.get_user_by_username(username)

    def update_user(self, user: UserEntry) -> bool:
        return self.backend.update_user(user)

    def delete_user(self, user_id: str) -> bool:
        return self.backend.delete_user(user_id)

    def list_users(
        self,
        group: str | None = None,
        enabled: bool | None = None,
    ) -> Iterator[UserEntry]:
        return self.backend.list_users(group, enabled)

    def create_arn_link(self, arn_link: ARNLink) -> str:
        return self.backend.create_arn_link(arn_link)

    def get_arn_link(self, link_id: str) -> ARNLink | None:
        return self.backend.get_arn_link(link_id)

    def get_arn_link_by_arn(self, arn: str) -> ARNLink | None:
        return self.backend.get_arn_link_by_arn(arn)

    def update_arn_link(self, arn_link: ARNLink) -> bool:
        return self.backend.update_arn_link(arn_link)

    def delete_arn_link(self, link_id: str) -> bool:
        return self.backend.delete_arn_link(link_id)

    def list_arn_links(
        self,
        aws_account_id: str | None = None,
        service: str | None = None,
    ) -> Iterator[ARNLink]:
        return self.backend.list_arn_links(aws_account_id, service)

    def create_resource_link(self, resource: ResourceLink) -> str:
        return self.backend.create_resource_link(resource)

    def get_resource_link(self, link_id: str) -> ResourceLink | None:
        return self.backend.get_resource_link(link_id)

    def update_resource_link(self, resource: ResourceLink) -> bool:
        return self.backend.update_resource_link(resource)

    def delete_resource_link(self, link_id: str) -> bool:
        return self.backend.delete_resource_link(link_id)

    def list_resource_links(
        self,
        resource_type: ResourceType | None = None,
    ) -> Iterator[ResourceLink]:
        return self.backend.list_resource_links(resource_type)

    # Linking shortcuts
    def link_user_to_arn(self, user_id: str, arn: str) -> bool:
        return self.backend.link_user_to_arn(user_id, arn)

    def link_secret_to_resource(self, secret_id: str, resource_id: str) -> bool:
        return self.backend.link_secret_to_resource(secret_id, resource_id)

    # Password file generation
    def generate_passwd_file(
        self,
        users: list[UserEntry] | None = None,
        group: str | None = None,
        enabled_only: bool = True,
    ) -> str:
        """Generate Unix passwd file content.

        Args:
            users: Specific users (or load from backend)
            group: Filter by group
            enabled_only: Only include enabled users

        Returns:
            passwd file content
        """
        if users is None:
            users = list(self.list_users(group=group, enabled=enabled_only if enabled_only else None))

        lines = []
        for user in users:
            if enabled_only and not user.enabled:
                continue
            if group and group not in user.groups:
                continue
            lines.append(user.to_passwd_line())

        return "\n".join(lines) + "\n" if lines else ""

    def generate_shadow_file(
        self,
        users: list[UserEntry] | None = None,
        group: str | None = None,
        enabled_only: bool = True,
    ) -> str:
        """Generate Unix shadow file content.

        Args:
            users: Specific users (or load from backend)
            group: Filter by group
            enabled_only: Only include enabled users

        Returns:
            shadow file content
        """
        if users is None:
            users = list(self.list_users(group=group, enabled=enabled_only if enabled_only else None))

        lines = []
        for user in users:
            if enabled_only and not user.enabled:
                continue
            if group and group not in user.groups:
                continue

            # Use stored hash or locked account marker
            password = user.password_hash or "!"
            if user.locked:
                password = "!" + password

            lines.append(user.to_shadow_line(password))

        return "\n".join(lines) + "\n" if lines else ""

    def generate_group_file(
        self,
        users: list[UserEntry] | None = None,
    ) -> str:
        """Generate Unix group file content.

        Args:
            users: Users to derive groups from

        Returns:
            group file content
        """
        if users is None:
            users = list(self.list_users(enabled=True))

        # Collect groups and their members
        groups: dict[str, dict] = {}

        for user in users:
            if not user.enabled:
                continue

            # Primary group
            if user.primary_group:
                if user.primary_group not in groups:
                    groups[user.primary_group] = {
                        "gid": user.gid or 65534,
                        "members": set()
                    }
                groups[user.primary_group]["members"].add(user.username)

            # Secondary groups
            for grp in user.groups:
                if grp not in groups:
                    groups[grp] = {
                        "gid": 65534,  # Will need to assign proper GIDs
                        "members": set()
                    }
                groups[grp]["members"].add(user.username)

        # Generate file
        lines = []
        for name, data in sorted(groups.items()):
            members = ",".join(sorted(data["members"]))
            lines.append(f"{name}:x:{data['gid']}:{members}")

        return "\n".join(lines) + "\n" if lines else ""

    def generate_authorized_keys(
        self,
        user: UserEntry | None = None,
        username: str | None = None,
    ) -> str:
        """Generate SSH authorized_keys file content.

        Args:
            user: User entry
            username: Username to look up

        Returns:
            authorized_keys content
        """
        if user is None and username:
            user = self.get_user_by_username(username)

        if not user:
            return ""

        lines = []
        for key in user.ssh_public_keys:
            # Optionally add restrictions
            # e.g., from="10.0.0.0/8" or command="/bin/restricted"
            lines.append(key)

        return "\n".join(lines) + "\n" if lines else ""

    def export_all_authorized_keys(
        self,
        output_dir: str | Path,
        group: str | None = None,
    ) -> int:
        """Export authorized_keys files for all users.

        Args:
            output_dir: Output directory
            group: Filter by group

        Returns:
            Number of files written
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        count = 0
        for user in self.list_users(group=group, enabled=True):
            if not user.ssh_public_keys:
                continue

            # Create user's .ssh directory
            user_ssh_dir = output_dir / user.username / ".ssh"
            user_ssh_dir.mkdir(parents=True, exist_ok=True)

            # Write authorized_keys
            ak_file = user_ssh_dir / "authorized_keys"
            ak_content = self.generate_authorized_keys(user=user)
            ak_file.write_text(ak_content)

            # Set permissions
            os.chmod(ak_file, 0o600)
            os.chmod(user_ssh_dir, 0o700)

            count += 1

        return count

    @staticmethod
    def hash_password(password: str, method: str = "sha512") -> str:
        """Hash a password for shadow file.

        Args:
            password: Plain text password
            method: Hash method (sha256, sha512, md5)

        Returns:
            Hashed password string
        """
        if method == "sha512":
            prefix = "$6$"
        elif method == "sha256":
            prefix = "$5$"
        else:
            prefix = "$1$"

        salt = crypt.mksalt(
            crypt.METHOD_SHA512 if method == "sha512"
            else crypt.METHOD_SHA256 if method == "sha256"
            else crypt.METHOD_MD5
        )

        return crypt.crypt(password, salt)

    def set_user_password(
        self,
        user_id: str | None = None,
        username: str | None = None,
        password: str | None = None,
    ) -> bool:
        """Set password for a user.

        Args:
            user_id: User ID
            username: Or username
            password: New password

        Returns:
            True if successful
        """
        user = None
        if user_id:
            user = self.get_user(user_id)
        elif username:
            user = self.get_user_by_username(username)

        if not user:
            return False

        user.password_hash = self.hash_password(password)
        user.updated_at = datetime.now()

        return self.update_user(user)
