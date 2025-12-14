"""
Credential management for device backups.

Provides encrypted storage for device credentials using Fernet symmetric encryption.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import os
import json
import base64
import hashlib
import secrets
from datetime import datetime
from pathlib import Path
from typing import Iterator

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from globaldetect.backup.models import DeviceCredential, DeviceVendor, ConnectionMethod


class CredentialVault:
    """Encrypted credential storage for device access."""

    def __init__(self, vault_path: str | Path, master_password: str | None = None):
        """Initialize the credential vault.

        Args:
            vault_path: Path to the vault directory
            master_password: Master password for encryption (or from env GLOBALDETECT_VAULT_PASSWORD)
        """
        self.vault_path = Path(vault_path)
        self.creds_path = self.vault_path / "credentials"
        self.meta_path = self.vault_path / "vault.json"

        # Get master password
        self._master_password = master_password or os.environ.get("GLOBALDETECT_VAULT_PASSWORD")
        self._fernet: Fernet | None = None
        self._salt: bytes | None = None

    def initialize(self, master_password: str | None = None) -> None:
        """Initialize or unlock the vault.

        Args:
            master_password: Master password (if not provided at init)
        """
        if master_password:
            self._master_password = master_password

        if not self._master_password:
            raise ValueError(
                "Master password required. Set GLOBALDETECT_VAULT_PASSWORD env var "
                "or pass master_password parameter."
            )

        self.vault_path.mkdir(parents=True, exist_ok=True)
        self.creds_path.mkdir(parents=True, exist_ok=True)

        # Check if vault exists
        if self.meta_path.exists():
            # Load existing vault
            meta = json.loads(self.meta_path.read_text())
            self._salt = base64.b64decode(meta["salt"])
        else:
            # Create new vault
            self._salt = secrets.token_bytes(32)
            meta = {
                "salt": base64.b64encode(self._salt).decode(),
                "created_at": datetime.now().isoformat(),
                "version": 1,
            }
            self.meta_path.write_text(json.dumps(meta, indent=2))
            os.chmod(self.meta_path, 0o600)

        # Derive encryption key
        self._fernet = self._derive_key()

    def _derive_key(self) -> Fernet:
        """Derive encryption key from master password."""
        if not self._master_password or not self._salt:
            raise ValueError("Vault not initialized")

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self._salt,
            iterations=480000,  # OWASP recommended minimum
        )
        key = base64.urlsafe_b64encode(
            kdf.derive(self._master_password.encode())
        )
        return Fernet(key)

    def _encrypt(self, data: str) -> str:
        """Encrypt string data."""
        if not self._fernet:
            raise ValueError("Vault not initialized")
        return self._fernet.encrypt(data.encode()).decode()

    def _decrypt(self, data: str) -> str:
        """Decrypt string data."""
        if not self._fernet:
            raise ValueError("Vault not initialized")
        return self._fernet.decrypt(data.encode()).decode()

    def _generate_id(self, hostname: str, vendor: DeviceVendor) -> str:
        """Generate unique credential ID."""
        raw = f"{hostname}:{vendor.value}:{secrets.token_hex(8)}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def add_credential(self, credential: DeviceCredential) -> str:
        """Add a credential to the vault.

        Args:
            credential: Credential to store

        Returns:
            Credential ID
        """
        if not self._fernet:
            raise ValueError("Vault not initialized")

        # Generate ID if not set
        if not credential.id:
            credential.id = self._generate_id(
                credential.device_hostname or "unknown",
                credential.device_vendor
            )

        credential.created_at = datetime.now()
        credential.updated_at = datetime.now()

        # Convert to dict with secrets
        data = credential.to_dict(include_secrets=True)

        # Encrypt sensitive fields
        sensitive_fields = [
            "password", "ssh_key", "ssh_key_passphrase",
            "api_key", "api_secret", "api_token",
            "snmp_community", "snmp_auth_password", "snmp_priv_password",
            "enable_password"
        ]

        for field in sensitive_fields:
            if data.get(field):
                data[field] = self._encrypt(data[field])

        data["_encrypted"] = True

        # Save to file
        cred_file = self.creds_path / f"{credential.id}.json"
        cred_file.write_text(json.dumps(data, indent=2))
        os.chmod(cred_file, 0o600)

        return credential.id

    def get_credential(self, credential_id: str) -> DeviceCredential | None:
        """Get a credential by ID.

        Args:
            credential_id: Credential ID

        Returns:
            DeviceCredential or None if not found
        """
        if not self._fernet:
            raise ValueError("Vault not initialized")

        cred_file = self.creds_path / f"{credential_id}.json"
        if not cred_file.exists():
            return None

        data = json.loads(cred_file.read_text())

        # Decrypt sensitive fields
        if data.get("_encrypted"):
            sensitive_fields = [
                "password", "ssh_key", "ssh_key_passphrase",
                "api_key", "api_secret", "api_token",
                "snmp_community", "snmp_auth_password", "snmp_priv_password",
                "enable_password"
            ]

            for field in sensitive_fields:
                if data.get(field):
                    try:
                        data[field] = self._decrypt(data[field])
                    except Exception:
                        data[field] = None

        # Convert to DeviceCredential
        return DeviceCredential(
            id=data.get("id"),
            name=data.get("name"),
            device_hostname=data.get("device_hostname"),
            device_ip=data.get("device_ip"),
            device_vendor=DeviceVendor(data.get("device_vendor", "unknown")),
            connection_method=ConnectionMethod(data.get("connection_method", "ssh")),
            port=data.get("port"),
            username=data.get("username"),
            password=data.get("password"),
            ssh_key=data.get("ssh_key"),
            ssh_key_passphrase=data.get("ssh_key_passphrase"),
            api_key=data.get("api_key"),
            api_secret=data.get("api_secret"),
            api_token=data.get("api_token"),
            snmp_community=data.get("snmp_community"),
            snmp_version=data.get("snmp_version", "2c"),
            snmp_auth_protocol=data.get("snmp_auth_protocol"),
            snmp_auth_password=data.get("snmp_auth_password"),
            snmp_priv_protocol=data.get("snmp_priv_protocol"),
            snmp_priv_password=data.get("snmp_priv_password"),
            enable_password=data.get("enable_password"),
            privilege_level=data.get("privilege_level", 15),
            timeout_seconds=data.get("timeout_seconds", 30),
            banner_timeout=data.get("banner_timeout", 15),
            notes=data.get("notes"),
            tags=data.get("tags", []),
            created_at=datetime.fromisoformat(data["created_at"]) if data.get("created_at") else None,
            updated_at=datetime.fromisoformat(data["updated_at"]) if data.get("updated_at") else None,
            last_used=datetime.fromisoformat(data["last_used"]) if data.get("last_used") else None,
        )

    def update_credential(self, credential: DeviceCredential) -> bool:
        """Update an existing credential.

        Args:
            credential: Updated credential (must have id set)

        Returns:
            True if updated, False if not found
        """
        if not credential.id:
            raise ValueError("Credential ID required for update")

        cred_file = self.creds_path / f"{credential.id}.json"
        if not cred_file.exists():
            return False

        credential.updated_at = datetime.now()
        self.add_credential(credential)
        return True

    def delete_credential(self, credential_id: str) -> bool:
        """Delete a credential.

        Args:
            credential_id: Credential ID to delete

        Returns:
            True if deleted, False if not found
        """
        cred_file = self.creds_path / f"{credential_id}.json"
        if not cred_file.exists():
            return False

        cred_file.unlink()
        return True

    def list_credentials(
        self,
        vendor: DeviceVendor | None = None,
        hostname_filter: str | None = None,
    ) -> Iterator[DeviceCredential]:
        """List credentials with optional filtering.

        Args:
            vendor: Filter by vendor
            hostname_filter: Filter by hostname (substring match)

        Yields:
            DeviceCredential objects (without decrypted secrets for listing)
        """
        if not self._fernet:
            raise ValueError("Vault not initialized")

        for cred_file in self.creds_path.glob("*.json"):
            try:
                data = json.loads(cred_file.read_text())

                # Apply filters
                if vendor and data.get("device_vendor") != vendor.value:
                    continue

                if hostname_filter:
                    hostname = data.get("device_hostname", "")
                    if hostname_filter.lower() not in hostname.lower():
                        continue

                # Return without decrypting secrets for listing
                yield DeviceCredential(
                    id=data.get("id"),
                    name=data.get("name"),
                    device_hostname=data.get("device_hostname"),
                    device_ip=data.get("device_ip"),
                    device_vendor=DeviceVendor(data.get("device_vendor", "unknown")),
                    connection_method=ConnectionMethod(data.get("connection_method", "ssh")),
                    port=data.get("port"),
                    username=data.get("username"),
                    notes=data.get("notes"),
                    tags=data.get("tags", []),
                    created_at=datetime.fromisoformat(data["created_at"]) if data.get("created_at") else None,
                    updated_at=datetime.fromisoformat(data["updated_at"]) if data.get("updated_at") else None,
                    last_used=datetime.fromisoformat(data["last_used"]) if data.get("last_used") else None,
                )
            except (json.JSONDecodeError, KeyError):
                continue

    def find_credential_for_device(
        self,
        hostname: str,
        ip: str | None = None,
        vendor: DeviceVendor | None = None,
    ) -> DeviceCredential | None:
        """Find the best matching credential for a device.

        Args:
            hostname: Device hostname
            ip: Device IP address
            vendor: Device vendor

        Returns:
            Best matching credential or None
        """
        candidates = []

        for cred in self.list_credentials():
            score = 0

            # Hostname match (highest priority)
            if cred.device_hostname and cred.device_hostname.lower() == hostname.lower():
                score += 100

            # IP match
            if ip and cred.device_ip == ip:
                score += 50

            # Vendor match
            if vendor and cred.device_vendor == vendor:
                score += 25

            if score > 0:
                candidates.append((score, cred.id))

        if not candidates:
            return None

        # Get highest scoring credential
        candidates.sort(key=lambda x: x[0], reverse=True)
        return self.get_credential(candidates[0][1])

    def mark_used(self, credential_id: str) -> None:
        """Mark a credential as recently used.

        Args:
            credential_id: Credential ID
        """
        cred = self.get_credential(credential_id)
        if cred:
            cred.last_used = datetime.now()
            self.update_credential(cred)

    def change_master_password(self, new_password: str) -> None:
        """Change the vault master password.

        Re-encrypts all credentials with new key.

        Args:
            new_password: New master password
        """
        if not self._fernet:
            raise ValueError("Vault not initialized")

        # Load all credentials with current key
        credentials = []
        for cred_file in self.creds_path.glob("*.json"):
            cred_id = cred_file.stem
            cred = self.get_credential(cred_id)
            if cred:
                credentials.append(cred)

        # Generate new salt and key
        self._salt = secrets.token_bytes(32)
        self._master_password = new_password
        self._fernet = self._derive_key()

        # Update vault metadata
        meta = {
            "salt": base64.b64encode(self._salt).decode(),
            "created_at": datetime.now().isoformat(),
            "version": 1,
        }
        self.meta_path.write_text(json.dumps(meta, indent=2))

        # Re-encrypt all credentials
        for cred in credentials:
            self.add_credential(cred)

    def export_credentials(self, include_secrets: bool = False) -> list[dict]:
        """Export all credentials to list.

        Args:
            include_secrets: Whether to include decrypted secrets

        Returns:
            List of credential dictionaries
        """
        result = []

        for cred_file in self.creds_path.glob("*.json"):
            if include_secrets:
                cred = self.get_credential(cred_file.stem)
                if cred:
                    result.append(cred.to_dict(include_secrets=True))
            else:
                # Just load the encrypted data
                data = json.loads(cred_file.read_text())
                # Remove encrypted sensitive fields for export
                for field in ["password", "ssh_key", "ssh_key_passphrase",
                              "api_key", "api_secret", "api_token",
                              "snmp_community", "snmp_auth_password",
                              "snmp_priv_password", "enable_password"]:
                    data.pop(field, None)
                data.pop("_encrypted", None)
                result.append(data)

        return result
