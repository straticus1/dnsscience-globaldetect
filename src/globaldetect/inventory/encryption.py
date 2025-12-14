"""
Encryption at rest for sensitive inventory data.

Supports compliance with:
- PCI-DSS Requirement 3 (Protect stored cardholder data)
- GDPR Article 32 (Security of processing)
- NIST 800-53 SC-28 (Protection of Information at Rest)
- CMMC L3+ (Encryption requirements)
- FedRAMP (FIPS 140-2 validated encryption)

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

# Cryptography library (recommended)
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False


class EncryptionAlgorithm(str, Enum):
    """Supported encryption algorithms."""
    AES_256_GCM = "aes-256-gcm"  # FIPS 140-2 approved
    FERNET = "fernet"  # AES-128-CBC with HMAC (cryptography library)


class KeyDerivationFunction(str, Enum):
    """Supported key derivation functions."""
    PBKDF2_SHA256 = "pbkdf2-sha256"  # NIST SP 800-132
    PBKDF2_SHA512 = "pbkdf2-sha512"


@dataclass
class EncryptionConfig:
    """Encryption configuration."""
    algorithm: EncryptionAlgorithm = EncryptionAlgorithm.FERNET
    kdf: KeyDerivationFunction = KeyDerivationFunction.PBKDF2_SHA256
    iterations: int = 480000  # OWASP 2023 recommendation for PBKDF2-SHA256
    key_length: int = 32  # 256 bits

    # Key management
    key_file: str | None = None  # Path to key file
    key_env_var: str = "GLOBALDETECT_ENCRYPTION_KEY"
    use_kms: bool = False  # Use AWS KMS or similar
    kms_key_id: str | None = None

    # Fields to encrypt (sensitive data)
    encrypted_fields: list[str] | None = None

    @classmethod
    def default_encrypted_fields(cls) -> list[str]:
        """Fields that should be encrypted by default."""
        return [
            # Credentials
            "api_key",
            "password",
            "secret",
            "token",
            "private_key",

            # PII (GDPR, GLBA)
            "contact_email",
            "contact_phone",
            "contact_pagerduty",
            "contact_slack",

            # Financial (SOX, PCI)
            "cost_center",
            "purchase_order",

            # Custom sensitive fields
            "custom_fields",
        ]


class EncryptionManager:
    """Manages encryption/decryption of sensitive data.

    Compliant with:
    - NIST 800-53 SC-12 (Cryptographic Key Establishment and Management)
    - NIST 800-53 SC-28 (Protection of Information at Rest)
    - PCI-DSS Requirement 3.5 (Key Management)
    """

    def __init__(self, config: EncryptionConfig | None = None):
        if not CRYPTOGRAPHY_AVAILABLE:
            raise ImportError(
                "cryptography library required for encryption. "
                "Install with: pip install cryptography"
            )

        self.config = config or EncryptionConfig()
        self._key: bytes | None = None
        self._fernet: Fernet | None = None

        self._initialize_key()

    def _initialize_key(self):
        """Initialize encryption key from configured source."""
        key_data = None

        # Try environment variable first
        if self.config.key_env_var:
            key_data = os.environ.get(self.config.key_env_var)

        # Try key file
        if not key_data and self.config.key_file:
            key_path = Path(self.config.key_file)
            if key_path.exists():
                key_data = key_path.read_text().strip()

        # Try default location
        if not key_data:
            default_key_path = Path.home() / ".config" / "globaldetect" / "encryption.key"
            if default_key_path.exists():
                key_data = default_key_path.read_text().strip()

        if key_data:
            # Decode base64 key
            self._key = base64.urlsafe_b64decode(key_data.encode())
            self._fernet = Fernet(base64.urlsafe_b64encode(self._key[:32]))
        else:
            # Generate new key (should be saved for production use)
            self._key = secrets.token_bytes(32)
            self._fernet = Fernet(base64.urlsafe_b64encode(self._key))

    @classmethod
    def generate_key(cls) -> str:
        """Generate a new encryption key.

        Returns:
            Base64-encoded key string
        """
        key = secrets.token_bytes(32)
        return base64.urlsafe_b64encode(key).decode()

    @classmethod
    def derive_key_from_password(
        cls,
        password: str,
        salt: bytes | None = None,
        iterations: int = 480000,
    ) -> tuple[str, str]:
        """Derive encryption key from password using PBKDF2.

        Args:
            password: User password
            salt: Salt bytes (generated if not provided)
            iterations: PBKDF2 iterations

        Returns:
            Tuple of (base64_key, base64_salt)
        """
        if not CRYPTOGRAPHY_AVAILABLE:
            raise ImportError("cryptography library required")

        if salt is None:
            salt = secrets.token_bytes(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=default_backend(),
        )

        key = kdf.derive(password.encode())

        return (
            base64.urlsafe_b64encode(key).decode(),
            base64.urlsafe_b64encode(salt).decode(),
        )

    def encrypt(self, plaintext: str) -> str:
        """Encrypt a string value.

        Args:
            plaintext: String to encrypt

        Returns:
            Base64-encoded encrypted string
        """
        if not self._fernet:
            raise RuntimeError("Encryption not initialized")

        encrypted = self._fernet.encrypt(plaintext.encode())
        return base64.urlsafe_b64encode(encrypted).decode()

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt an encrypted string.

        Args:
            ciphertext: Base64-encoded encrypted string

        Returns:
            Decrypted plaintext string
        """
        if not self._fernet:
            raise RuntimeError("Encryption not initialized")

        encrypted = base64.urlsafe_b64decode(ciphertext.encode())
        decrypted = self._fernet.decrypt(encrypted)
        return decrypted.decode()

    def encrypt_dict(
        self,
        data: dict[str, Any],
        fields: list[str] | None = None,
    ) -> dict[str, Any]:
        """Encrypt specified fields in a dictionary.

        Args:
            data: Dictionary containing data
            fields: List of field names to encrypt (uses config default if not specified)

        Returns:
            Dictionary with encrypted fields
        """
        fields = fields or self.config.encrypted_fields or EncryptionConfig.default_encrypted_fields()
        result = data.copy()

        for field in fields:
            if field in result and result[field] is not None:
                value = result[field]
                if isinstance(value, str):
                    result[field] = f"ENC:{self.encrypt(value)}"
                elif isinstance(value, dict):
                    result[field] = f"ENC:{self.encrypt(json.dumps(value))}"
                elif isinstance(value, list):
                    result[field] = f"ENC:{self.encrypt(json.dumps(value))}"

        return result

    def decrypt_dict(
        self,
        data: dict[str, Any],
        fields: list[str] | None = None,
    ) -> dict[str, Any]:
        """Decrypt specified fields in a dictionary.

        Args:
            data: Dictionary containing encrypted data
            fields: List of field names to decrypt

        Returns:
            Dictionary with decrypted fields
        """
        fields = fields or self.config.encrypted_fields or EncryptionConfig.default_encrypted_fields()
        result = data.copy()

        for field in fields:
            if field in result and result[field] is not None:
                value = result[field]
                if isinstance(value, str) and value.startswith("ENC:"):
                    encrypted = value[4:]
                    decrypted = self.decrypt(encrypted)
                    # Try to parse as JSON
                    try:
                        result[field] = json.loads(decrypted)
                    except json.JSONDecodeError:
                        result[field] = decrypted

        return result

    def hash_for_search(self, value: str) -> str:
        """Create a searchable hash of a value.

        This allows searching encrypted fields without decrypting them.
        Uses HMAC to prevent rainbow table attacks.

        Args:
            value: Value to hash

        Returns:
            Hex-encoded HMAC hash
        """
        if not self._key:
            raise RuntimeError("Encryption not initialized")

        return hmac.new(
            self._key[:16],
            value.lower().encode(),
            hashlib.sha256,
        ).hexdigest()

    def rotate_key(self, new_key: str, data: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Rotate encryption key for a list of records.

        Args:
            new_key: New base64-encoded encryption key
            data: List of dictionaries with encrypted fields

        Returns:
            List of dictionaries re-encrypted with new key
        """
        # Decrypt with old key
        decrypted_data = [self.decrypt_dict(d) for d in data]

        # Initialize new key
        self._key = base64.urlsafe_b64decode(new_key.encode())
        self._fernet = Fernet(base64.urlsafe_b64encode(self._key[:32]))

        # Re-encrypt with new key
        return [self.encrypt_dict(d) for d in decrypted_data]


class FieldLevelEncryption:
    """Field-level encryption for database columns.

    Provides transparent encryption/decryption for specific fields,
    supporting compliance with data-at-rest encryption requirements.
    """

    def __init__(self, manager: EncryptionManager):
        self.manager = manager

    def encrypt_field(self, value: Any) -> str | None:
        """Encrypt a single field value."""
        if value is None:
            return None

        if isinstance(value, str):
            return f"ENC:{self.manager.encrypt(value)}"
        else:
            return f"ENC:{self.manager.encrypt(json.dumps(value))}"

    def decrypt_field(self, value: str | None) -> Any:
        """Decrypt a single field value."""
        if value is None:
            return None

        if isinstance(value, str) and value.startswith("ENC:"):
            encrypted = value[4:]
            decrypted = self.manager.decrypt(encrypted)
            try:
                return json.loads(decrypted)
            except json.JSONDecodeError:
                return decrypted

        return value

    def is_encrypted(self, value: Any) -> bool:
        """Check if a value is encrypted."""
        return isinstance(value, str) and value.startswith("ENC:")


def save_key_to_file(key: str, path: str | Path, mode: int = 0o600) -> None:
    """Securely save encryption key to file.

    Args:
        key: Base64-encoded encryption key
        path: File path to save key
        mode: File permissions (default: owner read/write only)
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    # Write key
    path.write_text(key)

    # Set restrictive permissions
    os.chmod(path, mode)


def generate_and_save_key(path: str | Path | None = None) -> str:
    """Generate a new encryption key and optionally save it.

    Args:
        path: Optional file path to save the key

    Returns:
        Base64-encoded encryption key
    """
    key = EncryptionManager.generate_key()

    if path:
        save_key_to_file(key, path)

    return key
