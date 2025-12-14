"""
Lyft Confidant secrets backend integration.

Confidant is a secrets management service that provides credential storage.
When enabled, Confidant is checked first, then falls back to SQL backend.

https://lyft.github.io/confidant/

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import json
import logging
from datetime import datetime
from typing import Iterator, Any

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

logger = logging.getLogger(__name__)


class ConfidantClient:
    """Client for Lyft Confidant API."""

    def __init__(self, config: SecretsConfig):
        """Initialize Confidant client.

        Args:
            config: Secrets configuration with Confidant settings
        """
        self.config = config
        self.base_url = config.confidant_url.rstrip('/') if config.confidant_url else ""
        self.auth_key = config.confidant_auth_key
        self.auth_context = config.confidant_auth_context
        self.token_version = config.confidant_token_version
        self.user_type = config.confidant_user_type
        self._session = None

    def _get_auth_token(self) -> str:
        """Generate KMS auth token for Confidant.

        Returns:
            KMS-encrypted auth token
        """
        try:
            import boto3

            kms_client = boto3.client('kms')

            # Confidant uses KMS for authentication
            context = self.auth_context.copy()
            context['from'] = self.user_type
            context['to'] = 'confidant'

            response = kms_client.encrypt(
                KeyId=self.auth_key,
                Plaintext=json.dumps({'not_before': datetime.utcnow().isoformat()}).encode(),
                EncryptionContext=context,
            )

            import base64
            return base64.b64encode(response['CiphertextBlob']).decode('utf-8')

        except ImportError:
            raise ImportError("boto3 required for Confidant. Install with: pip install boto3")
        except Exception as e:
            logger.error(f"Failed to generate Confidant auth token: {e}")
            raise

    async def _ensure_session(self):
        """Ensure HTTP session exists."""
        if self._session is None:
            import aiohttp
            self._session = aiohttp.ClientSession()

    async def close(self):
        """Close HTTP session."""
        if self._session:
            await self._session.close()
            self._session = None

    async def _request(
        self,
        method: str,
        endpoint: str,
        data: dict | None = None
    ) -> dict | None:
        """Make authenticated request to Confidant API.

        Args:
            method: HTTP method
            endpoint: API endpoint
            data: Request data

        Returns:
            Response data or None
        """
        await self._ensure_session()

        url = f"{self.base_url}{endpoint}"
        token = self._get_auth_token()

        headers = {
            "Content-Type": "application/json",
            "X-Auth-Token": token,
            "X-Auth-From": self.user_type,
        }

        try:
            if method.upper() == "GET":
                async with self._session.get(url, headers=headers) as resp:
                    if resp.status == 200:
                        return await resp.json()
                    logger.warning(f"Confidant request failed: {resp.status}")
                    return None

            elif method.upper() == "POST":
                async with self._session.post(url, headers=headers, json=data) as resp:
                    if resp.status in (200, 201):
                        return await resp.json()
                    logger.warning(f"Confidant request failed: {resp.status}")
                    return None

            elif method.upper() == "PUT":
                async with self._session.put(url, headers=headers, json=data) as resp:
                    if resp.status == 200:
                        return await resp.json()
                    return None

        except Exception as e:
            logger.error(f"Confidant request error: {e}")
            return None

    # Service/Credential operations
    async def get_service(self, service_id: str) -> dict | None:
        """Get a service and its credentials.

        Args:
            service_id: Service identifier

        Returns:
            Service data with credentials
        """
        return await self._request("GET", f"/v1/services/{service_id}")

    async def get_credential(self, credential_id: str) -> dict | None:
        """Get a credential.

        Args:
            credential_id: Credential identifier

        Returns:
            Credential data
        """
        return await self._request("GET", f"/v1/credentials/{credential_id}")

    async def list_credentials(self) -> list[dict]:
        """List all credentials.

        Returns:
            List of credentials
        """
        result = await self._request("GET", "/v1/credentials")
        return result.get("credentials", []) if result else []

    async def create_credential(
        self,
        name: str,
        credential_pairs: dict[str, str],
        metadata: dict | None = None,
        enabled: bool = True
    ) -> dict | None:
        """Create a new credential in Confidant.

        Args:
            name: Credential name
            credential_pairs: Key-value pairs of secrets
            metadata: Optional metadata
            enabled: Whether credential is enabled

        Returns:
            Created credential data
        """
        data = {
            "name": name,
            "credential_pairs": credential_pairs,
            "enabled": enabled,
            "metadata": metadata or {},
        }
        return await self._request("POST", "/v1/credentials", data)

    async def update_credential(
        self,
        credential_id: str,
        credential_pairs: dict[str, str],
        enabled: bool = True
    ) -> dict | None:
        """Update a credential.

        Args:
            credential_id: Credential ID
            credential_pairs: Updated key-value pairs
            enabled: Whether credential is enabled

        Returns:
            Updated credential data
        """
        data = {
            "credential_pairs": credential_pairs,
            "enabled": enabled,
        }
        return await self._request("PUT", f"/v1/credentials/{credential_id}", data)

    async def get_service_credentials(self, service_id: str) -> dict[str, str]:
        """Get decrypted credentials for a service.

        Args:
            service_id: Service identifier

        Returns:
            Dictionary of credential key-value pairs
        """
        service = await self.get_service(service_id)
        if not service:
            return {}

        credentials = {}
        for cred in service.get("credentials", []):
            for key, value in cred.get("credential_pairs", {}).items():
                credentials[key] = value

        return credentials


class ConfidantBackend(SecretsBackend):
    """Confidant-based secrets storage with SQL fallback.

    When Confidant is the primary backend, it stores secrets in Confidant
    and uses SQL for users/ARNs/resources (which Confidant doesn't support).

    With fallback mode enabled, secrets are checked in Confidant first,
    then fall back to the SQL backend.
    """

    BACKEND_TYPE = BackendType.CONFIDANT

    def __init__(self, config: SecretsConfig, fallback_backend: SecretsBackend | None = None):
        """Initialize Confidant backend.

        Args:
            config: Secrets configuration
            fallback_backend: SQL backend for fallback and user/ARN storage
        """
        self.config = config
        self.client = ConfidantClient(config)
        self.fallback = fallback_backend
        self._initialized = False

    def initialize(self) -> None:
        """Initialize Confidant connection and fallback backend."""
        if self.fallback:
            self.fallback.initialize()
        self._initialized = True

    def close(self) -> None:
        """Close connections."""
        import asyncio
        try:
            loop = asyncio.get_event_loop()
            loop.run_until_complete(self.client.close())
        except Exception:
            pass

        if self.fallback:
            self.fallback.close()

    def _run_async(self, coro):
        """Run async method synchronously."""
        import asyncio
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        return loop.run_until_complete(coro)

    # Secret operations - use Confidant with SQL fallback
    def create_secret(self, secret: SecretEntry) -> str:
        """Create a secret in Confidant."""
        credential_pairs = {secret.name: secret.secret_value}

        result = self._run_async(self.client.create_credential(
            name=secret.name,
            credential_pairs=credential_pairs,
            metadata={
                "type": secret.secret_type.value,
                "description": secret.description,
                "tags": secret.tags,
            },
            enabled=secret.enabled,
        ))

        if result:
            secret.confidant_id = result.get("id")
            secret.confidant_revision = result.get("revision")

            # Also store in fallback for metadata
            if self.fallback:
                self.fallback.create_secret(secret)

            return secret.confidant_id

        # Fallback to SQL
        if self.fallback and self.config.confidant_fallback:
            return self.fallback.create_secret(secret)

        raise RuntimeError("Failed to create secret in Confidant")

    def get_secret(self, secret_id: str) -> SecretEntry | None:
        """Get a secret by ID (Confidant ID or local ID)."""
        # Try Confidant first
        result = self._run_async(self.client.get_credential(secret_id))
        if result:
            return self._confidant_to_secret(result)

        # Fallback to SQL
        if self.fallback:
            return self.fallback.get_secret(secret_id)

        return None

    def get_secret_by_name(self, name: str) -> SecretEntry | None:
        """Get a secret by name."""
        # List and find by name
        credentials = self._run_async(self.client.list_credentials())
        for cred in credentials:
            if cred.get("name") == name:
                return self._confidant_to_secret(cred)

        # Fallback to SQL
        if self.fallback:
            return self.fallback.get_secret_by_name(name)

        return None

    def update_secret(self, secret: SecretEntry) -> bool:
        """Update a secret."""
        if secret.confidant_id:
            credential_pairs = {secret.name: secret.secret_value}
            result = self._run_async(self.client.update_credential(
                secret.confidant_id,
                credential_pairs,
                secret.enabled,
            ))
            if result:
                secret.confidant_revision = result.get("revision")
                if self.fallback:
                    self.fallback.update_secret(secret)
                return True

        if self.fallback:
            return self.fallback.update_secret(secret)

        return False

    def delete_secret(self, secret_id: str) -> bool:
        """Delete a secret (disable in Confidant)."""
        # Confidant doesn't really delete, just disables
        secret = self.get_secret(secret_id)
        if secret and secret.confidant_id:
            secret.enabled = False
            return self.update_secret(secret)

        if self.fallback:
            return self.fallback.delete_secret(secret_id)

        return False

    def list_secrets(
        self,
        secret_type: SecretType | None = None,
        owner_user_id: str | None = None,
        tags: list[str] | None = None,
    ) -> Iterator[SecretEntry]:
        """List secrets from Confidant and fallback."""
        seen_ids = set()

        # Get from Confidant
        credentials = self._run_async(self.client.list_credentials())
        for cred in credentials:
            secret = self._confidant_to_secret(cred)
            if secret_type and secret.secret_type != secret_type:
                continue
            seen_ids.add(secret.id)
            yield secret

        # Get from fallback (excluding already seen)
        if self.fallback:
            for secret in self.fallback.list_secrets(secret_type, owner_user_id, tags):
                if secret.id not in seen_ids:
                    yield secret

    def _confidant_to_secret(self, cred: dict) -> SecretEntry:
        """Convert Confidant credential to SecretEntry."""
        metadata = cred.get("metadata", {})
        credential_pairs = cred.get("credential_pairs", {})

        # Get first secret value
        secret_value = None
        name = cred.get("name", "")
        if credential_pairs:
            if name in credential_pairs:
                secret_value = credential_pairs[name]
            else:
                secret_value = next(iter(credential_pairs.values()), None)

        return SecretEntry(
            id=cred.get("id"),
            name=name,
            description=metadata.get("description"),
            secret_type=SecretType(metadata.get("type", "generic")),
            secret_value=secret_value,
            version=cred.get("revision", 1),
            enabled=cred.get("enabled", True),
            tags=metadata.get("tags", []),
            confidant_id=cred.get("id"),
            confidant_revision=cred.get("revision"),
            created_at=datetime.fromisoformat(cred["modified_date"]) if cred.get("modified_date") else None,
            updated_at=datetime.fromisoformat(cred["modified_date"]) if cred.get("modified_date") else None,
        )

    # User operations - delegated to fallback (Confidant doesn't support users)
    def create_user(self, user: UserEntry) -> str:
        if not self.fallback:
            raise NotImplementedError("User management requires SQL fallback backend")
        return self.fallback.create_user(user)

    def get_user(self, user_id: str) -> UserEntry | None:
        return self.fallback.get_user(user_id) if self.fallback else None

    def get_user_by_username(self, username: str) -> UserEntry | None:
        return self.fallback.get_user_by_username(username) if self.fallback else None

    def update_user(self, user: UserEntry) -> bool:
        return self.fallback.update_user(user) if self.fallback else False

    def delete_user(self, user_id: str) -> bool:
        return self.fallback.delete_user(user_id) if self.fallback else False

    def list_users(self, group: str | None = None, enabled: bool | None = None) -> Iterator[UserEntry]:
        if self.fallback:
            yield from self.fallback.list_users(group, enabled)

    # ARN operations - delegated to fallback
    def create_arn_link(self, arn_link: ARNLink) -> str:
        if not self.fallback:
            raise NotImplementedError("ARN management requires SQL fallback backend")
        return self.fallback.create_arn_link(arn_link)

    def get_arn_link(self, link_id: str) -> ARNLink | None:
        return self.fallback.get_arn_link(link_id) if self.fallback else None

    def get_arn_link_by_arn(self, arn: str) -> ARNLink | None:
        return self.fallback.get_arn_link_by_arn(arn) if self.fallback else None

    def update_arn_link(self, arn_link: ARNLink) -> bool:
        return self.fallback.update_arn_link(arn_link) if self.fallback else False

    def delete_arn_link(self, link_id: str) -> bool:
        return self.fallback.delete_arn_link(link_id) if self.fallback else False

    def list_arn_links(self, aws_account_id: str | None = None, service: str | None = None) -> Iterator[ARNLink]:
        if self.fallback:
            yield from self.fallback.list_arn_links(aws_account_id, service)

    # Resource operations - delegated to fallback
    def create_resource_link(self, resource: ResourceLink) -> str:
        if not self.fallback:
            raise NotImplementedError("Resource management requires SQL fallback backend")
        return self.fallback.create_resource_link(resource)

    def get_resource_link(self, link_id: str) -> ResourceLink | None:
        return self.fallback.get_resource_link(link_id) if self.fallback else None

    def update_resource_link(self, resource: ResourceLink) -> bool:
        return self.fallback.update_resource_link(resource) if self.fallback else False

    def delete_resource_link(self, link_id: str) -> bool:
        return self.fallback.delete_resource_link(link_id) if self.fallback else False

    def list_resource_links(self, resource_type: ResourceType | None = None) -> Iterator[ResourceLink]:
        if self.fallback:
            yield from self.fallback.list_resource_links(resource_type)
