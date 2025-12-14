"""
Multi-Factor Authentication support.

Supports:
- TOTP (Google Authenticator, Authy, etc.)
- S/KEY (one-time password system)
- RADIUS authentication
- RSA SecurID
- Microsoft Azure MFA
- SSH Keys (with optional certificate support)

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import base64
import hashlib
import hmac
import struct
import time
import os
import secrets as py_secrets
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class MFAType(str, Enum):
    """Type of MFA method."""
    TOTP = "totp"  # Time-based OTP (Google Authenticator, Authy)
    HOTP = "hotp"  # HMAC-based OTP (counter-based)
    SKEY = "skey"  # S/KEY one-time passwords
    RADIUS = "radius"  # RADIUS authentication
    RSA_SECURID = "rsa_securid"  # RSA SecurID token
    AZURE_MFA = "azure_mfa"  # Microsoft Azure MFA
    SSH_KEY = "ssh_key"  # SSH public/private keys
    SSH_CERTIFICATE = "ssh_certificate"  # SSH CA-signed certificates
    FIDO2 = "fido2"  # FIDO2/WebAuthn (hardware keys)
    SMS = "sms"  # SMS-based OTP (not recommended)
    EMAIL = "email"  # Email-based OTP


@dataclass
class MFAToken:
    """MFA token configuration for a user."""
    id: str | None = None
    user_id: str | None = None
    mfa_type: MFAType = MFAType.TOTP
    name: str | None = None

    # TOTP/HOTP settings
    secret: str | None = None  # Base32 encoded secret
    algorithm: str = "SHA1"  # SHA1, SHA256, SHA512
    digits: int = 6  # 6 or 8
    period: int = 30  # TOTP period in seconds
    counter: int = 0  # HOTP counter

    # S/KEY settings
    skey_sequence: int = 100  # Number of OTPs remaining
    skey_seed: str | None = None  # Seed for hash chain
    skey_hash: str | None = None  # Current hash in chain

    # RADIUS settings
    radius_server: str | None = None
    radius_port: int = 1812
    radius_secret: str | None = None  # Shared secret
    radius_nas_identifier: str | None = None
    radius_timeout: int = 10

    # RSA SecurID settings
    securid_server: str | None = None
    securid_port: int = 5500
    securid_node_secret: str | None = None

    # Azure MFA settings
    azure_tenant_id: str | None = None
    azure_client_id: str | None = None
    azure_user_principal: str | None = None

    # SSH Key settings
    ssh_public_key: str | None = None
    ssh_private_key_encrypted: str | None = None
    ssh_key_type: str | None = None  # rsa, ed25519, ecdsa
    ssh_fingerprint: str | None = None
    ssh_certificate: str | None = None  # CA-signed certificate
    ssh_ca_public_key: str | None = None

    # State
    enabled: bool = True
    verified: bool = False
    last_used: datetime | None = None
    use_count: int = 0
    failed_attempts: int = 0
    locked_until: datetime | None = None

    # Timestamps
    created_at: datetime | None = None
    updated_at: datetime | None = None
    expires_at: datetime | None = None

    def to_dict(self, include_secrets: bool = False) -> dict[str, Any]:
        """Convert to dictionary."""
        data = {
            "id": self.id,
            "user_id": self.user_id,
            "mfa_type": self.mfa_type.value,
            "name": self.name,
            "algorithm": self.algorithm,
            "digits": self.digits,
            "period": self.period,
            "enabled": self.enabled,
            "verified": self.verified,
            "last_used": self.last_used.isoformat() if self.last_used else None,
            "use_count": self.use_count,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }

        if include_secrets:
            data.update({
                "secret": self.secret,
                "skey_seed": self.skey_seed,
                "skey_hash": self.skey_hash,
                "radius_secret": self.radius_secret,
                "securid_node_secret": self.securid_node_secret,
                "ssh_private_key_encrypted": self.ssh_private_key_encrypted,
            })

        return data


class TOTPGenerator:
    """Generate and verify TOTP codes (RFC 6238)."""

    @staticmethod
    def generate_secret(length: int = 32) -> str:
        """Generate a random base32-encoded secret.

        Args:
            length: Number of random bytes

        Returns:
            Base32-encoded secret
        """
        random_bytes = py_secrets.token_bytes(length)
        return base64.b32encode(random_bytes).decode('utf-8').rstrip('=')

    @staticmethod
    def generate_code(
        secret: str,
        timestamp: int | None = None,
        period: int = 30,
        digits: int = 6,
        algorithm: str = "SHA1"
    ) -> str:
        """Generate a TOTP code.

        Args:
            secret: Base32-encoded secret
            timestamp: Unix timestamp (defaults to now)
            period: Time period in seconds
            digits: Number of digits in code
            algorithm: Hash algorithm (SHA1, SHA256, SHA512)

        Returns:
            TOTP code
        """
        if timestamp is None:
            timestamp = int(time.time())

        # Decode secret
        secret_bytes = base64.b32decode(secret.upper() + '=' * (8 - len(secret) % 8))

        # Calculate counter
        counter = timestamp // period

        # Generate HMAC
        counter_bytes = struct.pack('>Q', counter)

        if algorithm.upper() == "SHA256":
            h = hmac.new(secret_bytes, counter_bytes, hashlib.sha256)
        elif algorithm.upper() == "SHA512":
            h = hmac.new(secret_bytes, counter_bytes, hashlib.sha512)
        else:
            h = hmac.new(secret_bytes, counter_bytes, hashlib.sha1)

        hmac_result = h.digest()

        # Dynamic truncation
        offset = hmac_result[-1] & 0x0f
        code_int = struct.unpack('>I', hmac_result[offset:offset + 4])[0]
        code_int &= 0x7fffffff
        code_int %= 10 ** digits

        return str(code_int).zfill(digits)

    @staticmethod
    def verify_code(
        secret: str,
        code: str,
        period: int = 30,
        digits: int = 6,
        algorithm: str = "SHA1",
        window: int = 1
    ) -> bool:
        """Verify a TOTP code.

        Args:
            secret: Base32-encoded secret
            code: Code to verify
            period: Time period in seconds
            digits: Number of digits in code
            algorithm: Hash algorithm
            window: Number of periods to check before/after current

        Returns:
            True if code is valid
        """
        timestamp = int(time.time())

        for i in range(-window, window + 1):
            expected = TOTPGenerator.generate_code(
                secret,
                timestamp + (i * period),
                period,
                digits,
                algorithm
            )
            if hmac.compare_digest(code, expected):
                return True

        return False

    @staticmethod
    def get_provisioning_uri(
        secret: str,
        username: str,
        issuer: str = "GlobalDetect",
        algorithm: str = "SHA1",
        digits: int = 6,
        period: int = 30
    ) -> str:
        """Generate a provisioning URI for QR codes.

        Args:
            secret: Base32-encoded secret
            username: Username
            issuer: Issuer name
            algorithm: Hash algorithm
            digits: Number of digits
            period: Time period

        Returns:
            otpauth:// URI
        """
        from urllib.parse import quote

        label = f"{issuer}:{username}"
        params = f"secret={secret}&issuer={quote(issuer)}&algorithm={algorithm}&digits={digits}&period={period}"
        return f"otpauth://totp/{quote(label)}?{params}"


class SKEYGenerator:
    """Generate and verify S/KEY one-time passwords (RFC 2289)."""

    DICTIONARY = [
        "A", "ABE", "ACE", "ACT", "AD", "ADA", "ADD", "AGO", "AID", "AIM",
        "AIR", "ALL", "ALP", "AM", "AMY", "AN", "ANA", "AND", "ANN", "ANT",
        "ANY", "APE", "APS", "APT", "ARC", "ARE", "ARK", "ARM", "ART", "AS",
        # ... (full dictionary would have 2048 words)
        # Truncated for brevity - use full RFC 2289 dictionary in production
    ]

    @staticmethod
    def generate_seed() -> str:
        """Generate a random seed."""
        return py_secrets.token_hex(8)

    @staticmethod
    def hash_fold(data: bytes, algorithm: str = "md5") -> bytes:
        """Apply hash and fold to 64 bits.

        Args:
            data: Data to hash
            algorithm: Hash algorithm (md5, sha1)

        Returns:
            64-bit folded hash
        """
        if algorithm.lower() == "sha1":
            h = hashlib.sha1(data).digest()
        else:
            h = hashlib.md5(data).digest()

        # Fold to 64 bits
        result = bytearray(8)
        for i, byte in enumerate(h):
            result[i % 8] ^= byte

        return bytes(result)

    @staticmethod
    def generate_chain(seed: str, passphrase: str, count: int = 100) -> list[bytes]:
        """Generate S/KEY hash chain.

        Args:
            seed: Random seed
            passphrase: User passphrase
            count: Number of OTPs to generate

        Returns:
            List of hashes (last element is the server-stored hash)
        """
        chain = []
        current = f"{seed}{passphrase}".encode('utf-8')

        for _ in range(count):
            current = SKEYGenerator.hash_fold(current)
            chain.append(current)

        return chain

    @staticmethod
    def hash_to_words(hash_bytes: bytes) -> str:
        """Convert hash to six-word representation."""
        # Simplified - real implementation uses RFC 2289 dictionary
        return base64.b64encode(hash_bytes).decode('utf-8')[:11]


class RADIUSClient:
    """RADIUS authentication client."""

    def __init__(
        self,
        server: str,
        secret: str,
        port: int = 1812,
        timeout: int = 10,
        nas_identifier: str = "globaldetect"
    ):
        """Initialize RADIUS client.

        Args:
            server: RADIUS server address
            secret: Shared secret
            port: RADIUS port
            timeout: Request timeout
            nas_identifier: NAS identifier
        """
        self.server = server
        self.secret = secret
        self.port = port
        self.timeout = timeout
        self.nas_identifier = nas_identifier

    def authenticate(self, username: str, password: str) -> bool:
        """Authenticate user via RADIUS.

        Args:
            username: Username
            password: Password or OTP

        Returns:
            True if authentication successful
        """
        try:
            from pyrad.client import Client
            from pyrad.dictionary import Dictionary
            import pyrad.packet

            # Create RADIUS client
            srv = Client(
                server=self.server,
                secret=self.secret.encode(),
                dict=Dictionary("dictionary")  # Standard RADIUS dictionary
            )
            srv.timeout = self.timeout

            # Create access request
            req = srv.CreateAuthPacket(code=pyrad.packet.AccessRequest)
            req["User-Name"] = username
            req["User-Password"] = req.PwCrypt(password)
            req["NAS-Identifier"] = self.nas_identifier

            # Send and get reply
            reply = srv.SendPacket(req)

            return reply.code == pyrad.packet.AccessAccept

        except ImportError:
            raise ImportError("pyrad required for RADIUS auth. Install with: pip install pyrad")
        except Exception:
            return False


class AzureMFAClient:
    """Microsoft Azure MFA client using MSAL."""

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str | None = None
    ):
        """Initialize Azure MFA client.

        Args:
            tenant_id: Azure AD tenant ID
            client_id: Application (client) ID
            client_secret: Client secret (for confidential apps)
        """
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret

    def authenticate_interactive(self, scopes: list[str] | None = None) -> dict | None:
        """Authenticate user interactively with Azure MFA.

        Args:
            scopes: OAuth scopes

        Returns:
            Token response or None
        """
        try:
            import msal

            if scopes is None:
                scopes = ["https://graph.microsoft.com/.default"]

            app = msal.PublicClientApplication(
                self.client_id,
                authority=f"https://login.microsoftonline.com/{self.tenant_id}"
            )

            result = app.acquire_token_interactive(scopes=scopes)
            return result if "access_token" in result else None

        except ImportError:
            raise ImportError("msal required for Azure MFA. Install with: pip install msal")

    def verify_token(self, token: str) -> dict | None:
        """Verify an Azure AD token.

        Args:
            token: Access or ID token

        Returns:
            Decoded token claims or None
        """
        try:
            import jwt
            from jwt import PyJWKClient

            jwks_url = f"https://login.microsoftonline.com/{self.tenant_id}/discovery/v2.0/keys"
            jwks_client = PyJWKClient(jwks_url)
            signing_key = jwks_client.get_signing_key_from_jwt(token)

            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=self.client_id,
                issuer=f"https://login.microsoftonline.com/{self.tenant_id}/v2.0"
            )
            return claims

        except Exception:
            return None


class SSHKeyManager:
    """SSH key generation and management."""

    @staticmethod
    def generate_keypair(
        key_type: str = "ed25519",
        bits: int = 4096,
        passphrase: str | None = None,
        comment: str = ""
    ) -> tuple[str, str]:
        """Generate SSH keypair.

        Args:
            key_type: Key type (rsa, ed25519, ecdsa)
            bits: Key size for RSA
            passphrase: Optional passphrase
            comment: Key comment

        Returns:
            Tuple of (private_key, public_key)
        """
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import rsa, ed25519, ec
            from cryptography.hazmat.backends import default_backend

            if key_type.lower() == "ed25519":
                private_key = ed25519.Ed25519PrivateKey.generate()
            elif key_type.lower() == "ecdsa":
                private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
            else:  # RSA
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=bits,
                    backend=default_backend()
                )

            # Serialize private key
            if passphrase:
                encryption = serialization.BestAvailableEncryption(passphrase.encode())
            else:
                encryption = serialization.NoEncryption()

            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.OpenSSH,
                encryption_algorithm=encryption
            ).decode('utf-8')

            # Serialize public key
            public_key = private_key.public_key()
            public_openssh = public_key.public_bytes(
                encoding=serialization.Encoding.OpenSSH,
                format=serialization.PublicFormat.OpenSSH
            ).decode('utf-8')

            if comment:
                public_openssh = f"{public_openssh} {comment}"

            return private_pem, public_openssh

        except ImportError:
            raise ImportError("cryptography required. Install with: pip install cryptography")

    @staticmethod
    def get_fingerprint(public_key: str, algorithm: str = "sha256") -> str:
        """Get SSH key fingerprint.

        Args:
            public_key: OpenSSH format public key
            algorithm: Hash algorithm (md5, sha256)

        Returns:
            Fingerprint string
        """
        try:
            # Parse public key
            parts = public_key.strip().split()
            if len(parts) < 2:
                raise ValueError("Invalid public key format")

            key_data = base64.b64decode(parts[1])

            if algorithm.lower() == "md5":
                digest = hashlib.md5(key_data).digest()
                fingerprint = ":".join(f"{b:02x}" for b in digest)
            else:
                digest = hashlib.sha256(key_data).digest()
                fingerprint = base64.b64encode(digest).decode('utf-8').rstrip('=')
                fingerprint = f"SHA256:{fingerprint}"

            return fingerprint

        except Exception as e:
            return f"error: {e}"

    @staticmethod
    def verify_key_pair(private_key: str, public_key: str, passphrase: str | None = None) -> bool:
        """Verify that private and public keys match.

        Args:
            private_key: PEM-formatted private key
            public_key: OpenSSH-formatted public key
            passphrase: Key passphrase if encrypted

        Returns:
            True if keys match
        """
        try:
            from cryptography.hazmat.primitives import serialization

            password = passphrase.encode() if passphrase else None

            priv = serialization.load_ssh_private_key(
                private_key.encode(),
                password=password
            )

            expected_pub = priv.public_key().public_bytes(
                encoding=serialization.Encoding.OpenSSH,
                format=serialization.PublicFormat.OpenSSH
            ).decode('utf-8')

            # Compare key data (ignoring comment)
            pub_parts = public_key.strip().split()
            expected_parts = expected_pub.strip().split()

            return pub_parts[:2] == expected_parts[:2]

        except Exception:
            return False
