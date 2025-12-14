"""
Have I Been Pwned API client.

Implements the HIBP v3 API for breach checking with support for:
- Email breach lookups
- Password checking with k-anonymity
- Batch operations
- Rate limiting

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import asyncio
import hashlib
import logging
import os
import time
from datetime import datetime
from typing import AsyncIterator

import aiohttp

from globaldetect.hibp.models import (
    Breach,
    BreachCheckResult,
    PasswordCheckResult,
    PasteEntry,
    DomainSearchResult,
)

logger = logging.getLogger(__name__)


class HIBPClient:
    """Client for Have I Been Pwned API v3.

    Provides methods for checking email addresses against known
    data breaches and validating password security using k-anonymity.
    """

    # API endpoints
    HIBP_API_BASE = "https://haveibeenpwned.com/api/v3"
    PWNED_PASSWORDS_API = "https://api.pwnedpasswords.com"

    # Rate limiting (HIBP allows ~10 requests per minute for free tier)
    DEFAULT_RATE_LIMIT = 6.0  # seconds between requests
    BATCH_DELAY = 1.5  # seconds between batch requests

    def __init__(
        self,
        api_key: str | None = None,
        user_agent: str = "GlobalDetect-Network-Tools/1.0",
        rate_limit: float | None = None,
    ):
        """Initialize HIBP client.

        Args:
            api_key: HIBP API key (required for email breach lookups)
            user_agent: User-Agent header for requests
            rate_limit: Seconds between requests (default: 6.0)
        """
        self.api_key = api_key or os.environ.get("HIBP_API_KEY")
        self.user_agent = user_agent
        self.rate_limit = rate_limit or self.DEFAULT_RATE_LIMIT
        self._session: aiohttp.ClientSession | None = None
        self._last_request_time: float = 0

    async def _ensure_session(self) -> aiohttp.ClientSession:
        """Ensure HTTP session exists."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session

    async def close(self) -> None:
        """Close HTTP session."""
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None

    async def __aenter__(self) -> "HIBPClient":
        """Async context manager entry."""
        await self._ensure_session()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        await self.close()

    async def _rate_limit_wait(self) -> None:
        """Wait for rate limiting."""
        now = time.time()
        elapsed = now - self._last_request_time
        if elapsed < self.rate_limit:
            await asyncio.sleep(self.rate_limit - elapsed)
        self._last_request_time = time.time()

    async def _request(
        self,
        method: str,
        url: str,
        headers: dict | None = None,
        require_api_key: bool = True,
    ) -> tuple[int, str | dict | list | None]:
        """Make rate-limited request to API.

        Args:
            method: HTTP method
            url: Full URL
            headers: Additional headers
            require_api_key: Whether API key is required

        Returns:
            Tuple of (status_code, response_data)
        """
        if require_api_key and not self.api_key:
            raise ValueError("HIBP API key required. Set HIBP_API_KEY environment variable.")

        await self._rate_limit_wait()

        session = await self._ensure_session()

        request_headers = {
            "User-Agent": self.user_agent,
        }
        if self.api_key and require_api_key:
            request_headers["hibp-api-key"] = self.api_key

        if headers:
            request_headers.update(headers)

        try:
            async with session.request(
                method,
                url,
                headers=request_headers,
                timeout=aiohttp.ClientTimeout(total=30),
            ) as response:
                status = response.status

                if status == 200:
                    content_type = response.headers.get("Content-Type", "")
                    if "application/json" in content_type:
                        return status, await response.json()
                    else:
                        return status, await response.text()
                elif status == 404:
                    # Not found - no breaches for this account
                    return status, None
                elif status == 429:
                    # Rate limited
                    retry_after = response.headers.get("Retry-After", "60")
                    logger.warning(f"Rate limited. Retry after {retry_after}s")
                    return status, {"error": f"Rate limited. Retry after {retry_after}s"}
                elif status == 401:
                    return status, {"error": "Invalid API key"}
                elif status == 403:
                    return status, {"error": "API key required or access denied"}
                else:
                    text = await response.text()
                    return status, {"error": f"HTTP {status}: {text[:200]}"}

        except asyncio.TimeoutError:
            return 0, {"error": "Request timeout"}
        except aiohttp.ClientError as e:
            return 0, {"error": f"Request failed: {str(e)}"}

    # =========================================================================
    # Email Breach Checking
    # =========================================================================

    async def check_email(
        self,
        email: str,
        truncate_response: bool = False,
        include_unverified: bool = True,
    ) -> BreachCheckResult:
        """Check if an email address has been in any data breaches.

        Args:
            email: Email address to check
            truncate_response: If True, only return breach names
            include_unverified: Include unverified breaches

        Returns:
            BreachCheckResult with breach details
        """
        email = email.lower().strip()

        url = (
            f"{self.HIBP_API_BASE}/breachedaccount/{email}"
            f"?truncateResponse={'true' if truncate_response else 'false'}"
            f"&includeUnverified={'true' if include_unverified else 'false'}"
        )

        status, data = await self._request("GET", url)

        result = BreachCheckResult(email=email)

        if status == 404:
            # No breaches found
            return result

        if status != 200:
            result.error = data.get("error") if isinstance(data, dict) else str(data)
            return result

        if isinstance(data, list):
            for breach_data in data:
                breach = Breach.from_api_response(breach_data)
                result.breaches.append(breach)
                result.total_pwn_count += breach.pwn_count

            result.breach_count = len(result.breaches)

        return result

    async def check_emails_batch(
        self,
        emails: list[str],
        truncate_response: bool = False,
    ) -> AsyncIterator[BreachCheckResult]:
        """Check multiple email addresses for breaches.

        Args:
            emails: List of email addresses
            truncate_response: If True, only return breach names

        Yields:
            BreachCheckResult for each email
        """
        for email in emails:
            result = await self.check_email(email, truncate_response)
            yield result
            # Additional delay for batch operations
            await asyncio.sleep(self.BATCH_DELAY)

    # =========================================================================
    # Password Checking (K-Anonymity)
    # =========================================================================

    async def check_password(self, password: str) -> PasswordCheckResult:
        """Check if a password has been exposed in data breaches.

        Uses k-anonymity model - only the first 5 characters of the
        SHA-1 hash are sent to the API. The full password never leaves
        this system.

        Args:
            password: Password to check (NOT stored or logged)

        Returns:
            PasswordCheckResult with exposure count
        """
        # Generate SHA-1 hash
        password_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix = password_hash[:5]
        suffix = password_hash[5:]

        # Clear the password from memory
        password = None  # noqa: F841

        url = f"{self.PWNED_PASSWORDS_API}/range/{prefix}"

        # Password API doesn't require API key
        status, data = await self._request("GET", url, require_api_key=False)

        result = PasswordCheckResult(hash_prefix=prefix)

        if status != 200:
            result.error = data.get("error") if isinstance(data, dict) else str(data)
            return result

        if isinstance(data, str):
            # Response format: "SUFFIX:COUNT\r\n"
            for line in data.strip().split("\r\n"):
                if ":" in line:
                    hash_suffix, count = line.split(":")
                    if hash_suffix.upper() == suffix:
                        result.occurrences = int(count)
                        break

        return result

    async def check_password_hash(self, sha1_hash: str) -> PasswordCheckResult:
        """Check a pre-computed SHA-1 hash against Pwned Passwords.

        Args:
            sha1_hash: Full SHA-1 hash of the password

        Returns:
            PasswordCheckResult with exposure count
        """
        sha1_hash = sha1_hash.upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        url = f"{self.PWNED_PASSWORDS_API}/range/{prefix}"

        status, data = await self._request("GET", url, require_api_key=False)

        result = PasswordCheckResult(hash_prefix=prefix)

        if status != 200:
            result.error = data.get("error") if isinstance(data, dict) else str(data)
            return result

        if isinstance(data, str):
            for line in data.strip().split("\r\n"):
                if ":" in line:
                    hash_suffix, count = line.split(":")
                    if hash_suffix.upper() == suffix:
                        result.occurrences = int(count)
                        break

        return result

    # =========================================================================
    # Paste Checking
    # =========================================================================

    async def check_pastes(self, email: str) -> list[PasteEntry]:
        """Check if an email has appeared in any pastes.

        Args:
            email: Email address to check

        Returns:
            List of paste entries
        """
        email = email.lower().strip()

        url = f"{self.HIBP_API_BASE}/pasteaccount/{email}"

        status, data = await self._request("GET", url)

        if status == 404 or not data:
            return []

        if status != 200:
            logger.error(f"Paste check failed: {data}")
            return []

        pastes = []
        if isinstance(data, list):
            for paste_data in data:
                paste = PasteEntry.from_api_response(paste_data)
                pastes.append(paste)

        return pastes

    # =========================================================================
    # Breach Database Queries
    # =========================================================================

    async def get_all_breaches(self, domain: str | None = None) -> list[Breach]:
        """Get all breaches in the HIBP database.

        Args:
            domain: Optional domain to filter breaches

        Returns:
            List of all breaches
        """
        url = f"{self.HIBP_API_BASE}/breaches"
        if domain:
            url += f"?domain={domain}"

        # This endpoint doesn't require API key
        status, data = await self._request("GET", url, require_api_key=False)

        if status != 200 or not data:
            return []

        breaches = []
        if isinstance(data, list):
            for breach_data in data:
                breach = Breach.from_api_response(breach_data)
                breaches.append(breach)

        return breaches

    async def get_breach(self, name: str) -> Breach | None:
        """Get details for a specific breach.

        Args:
            name: Breach name (e.g., 'Adobe', 'LinkedIn')

        Returns:
            Breach details or None
        """
        url = f"{self.HIBP_API_BASE}/breach/{name}"

        status, data = await self._request("GET", url, require_api_key=False)

        if status != 200 or not data:
            return None

        return Breach.from_api_response(data)

    async def get_data_classes(self) -> list[str]:
        """Get all data classes (types of compromised data).

        Returns:
            List of data class names
        """
        url = f"{self.HIBP_API_BASE}/dataclasses"

        status, data = await self._request("GET", url, require_api_key=False)

        if status != 200 or not data:
            return []

        return data if isinstance(data, list) else []

    async def search_domain_breaches(self, domain: str) -> DomainSearchResult:
        """Search for breaches affecting a domain.

        Args:
            domain: Domain to search (e.g., 'adobe.com')

        Returns:
            DomainSearchResult with matching breaches
        """
        breaches = await self.get_all_breaches(domain=domain)

        total_accounts = sum(b.pwn_count for b in breaches)

        return DomainSearchResult(
            domain=domain,
            breaches=breaches,
            total_accounts=total_accounts,
        )

    # =========================================================================
    # Subscription Domain Search (Enterprise feature)
    # =========================================================================

    async def search_subscription_domain(
        self,
        domain: str,
    ) -> list[dict]:
        """Search for breached accounts on a subscribed domain.

        Note: Requires a paid subscription and domain verification.

        Args:
            domain: Verified domain to search

        Returns:
            List of breached accounts on the domain
        """
        url = f"{self.HIBP_API_BASE}/subscribeddomains/{domain}/breaches"

        status, data = await self._request("GET", url)

        if status != 200:
            logger.error(f"Domain search failed: {data}")
            return []

        return data if isinstance(data, list) else []


# Convenience function for synchronous usage
def check_email_sync(email: str, api_key: str | None = None) -> BreachCheckResult:
    """Synchronous wrapper for checking email breaches.

    Args:
        email: Email address to check
        api_key: HIBP API key

    Returns:
        BreachCheckResult
    """
    async def _check():
        async with HIBPClient(api_key=api_key) as client:
            return await client.check_email(email)

    return asyncio.run(_check())


def check_password_sync(password: str) -> PasswordCheckResult:
    """Synchronous wrapper for checking password exposure.

    Args:
        password: Password to check

    Returns:
        PasswordCheckResult
    """
    async def _check():
        async with HIBPClient() as client:
            return await client.check_password(password)

    return asyncio.run(_check())
