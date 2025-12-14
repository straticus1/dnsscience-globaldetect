"""
Data models for Have I Been Pwned API responses.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from enum import Enum


class RiskLevel(str, Enum):
    """Risk level based on password exposure."""

    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Breach:
    """Represents a single data breach from HIBP."""

    name: str
    title: str
    domain: str
    breach_date: datetime | None
    added_date: datetime | None
    modified_date: datetime | None
    pwn_count: int
    description: str
    logo_path: str | None
    data_classes: list[str]
    is_verified: bool
    is_fabricated: bool
    is_sensitive: bool
    is_retired: bool
    is_spam_list: bool
    is_malware: bool
    is_subscription_free: bool

    @classmethod
    def from_api_response(cls, data: dict[str, Any]) -> "Breach":
        """Create Breach from HIBP API response."""
        def parse_date(date_str: str | None) -> datetime | None:
            if not date_str:
                return None
            try:
                # HIBP uses ISO format
                return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                try:
                    # Try date only format
                    return datetime.strptime(date_str, "%Y-%m-%d")
                except (ValueError, AttributeError):
                    return None

        return cls(
            name=data.get("Name", ""),
            title=data.get("Title", ""),
            domain=data.get("Domain", ""),
            breach_date=parse_date(data.get("BreachDate")),
            added_date=parse_date(data.get("AddedDate")),
            modified_date=parse_date(data.get("ModifiedDate")),
            pwn_count=data.get("PwnCount", 0),
            description=data.get("Description", ""),
            logo_path=data.get("LogoPath"),
            data_classes=data.get("DataClasses", []),
            is_verified=data.get("IsVerified", False),
            is_fabricated=data.get("IsFabricated", False),
            is_sensitive=data.get("IsSensitive", False),
            is_retired=data.get("IsRetired", False),
            is_spam_list=data.get("IsSpamList", False),
            is_malware=data.get("IsMalware", False),
            is_subscription_free=data.get("IsSubscriptionFree", True),
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "title": self.title,
            "domain": self.domain,
            "breach_date": self.breach_date.isoformat() if self.breach_date else None,
            "added_date": self.added_date.isoformat() if self.added_date else None,
            "pwn_count": self.pwn_count,
            "description": self.description,
            "data_classes": self.data_classes,
            "is_verified": self.is_verified,
            "is_sensitive": self.is_sensitive,
        }


@dataclass
class BreachCheckResult:
    """Result of checking an email against HIBP."""

    email: str
    breaches: list[Breach] = field(default_factory=list)
    breach_count: int = 0
    total_pwn_count: int = 0
    checked_at: datetime = field(default_factory=datetime.now)
    cached: bool = False
    error: str | None = None

    @property
    def is_breached(self) -> bool:
        """Check if email was found in any breaches."""
        return self.breach_count > 0

    @property
    def compromised_data_types(self) -> set[str]:
        """Get all compromised data types across all breaches."""
        types = set()
        for breach in self.breaches:
            types.update(breach.data_classes)
        return types

    @property
    def verified_breaches(self) -> list[Breach]:
        """Get only verified breaches."""
        return [b for b in self.breaches if b.is_verified]

    @property
    def sensitive_breaches(self) -> list[Breach]:
        """Get sensitive breaches (adult sites, etc.)."""
        return [b for b in self.breaches if b.is_sensitive]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "email": self.email,
            "is_breached": self.is_breached,
            "breach_count": self.breach_count,
            "total_pwn_count": self.total_pwn_count,
            "compromised_data_types": list(self.compromised_data_types),
            "verified_breach_count": len(self.verified_breaches),
            "breaches": [b.to_dict() for b in self.breaches],
            "checked_at": self.checked_at.isoformat(),
            "cached": self.cached,
            "error": self.error,
        }


@dataclass
class PasswordCheckResult:
    """Result of checking a password against Pwned Passwords."""

    occurrences: int = 0
    checked_at: datetime = field(default_factory=datetime.now)
    cached: bool = False
    error: str | None = None
    # Never store the actual password!
    hash_prefix: str = ""  # Only first 5 chars of SHA-1

    @property
    def is_pwned(self) -> bool:
        """Check if password was found in breaches."""
        return self.occurrences > 0

    @property
    def risk_level(self) -> RiskLevel:
        """Determine risk level based on occurrences."""
        if self.occurrences == 0:
            return RiskLevel.SAFE
        elif self.occurrences < 10:
            return RiskLevel.LOW
        elif self.occurrences < 100:
            return RiskLevel.MEDIUM
        elif self.occurrences < 10000:
            return RiskLevel.HIGH
        else:
            return RiskLevel.CRITICAL

    @property
    def risk_description(self) -> str:
        """Get human-readable risk description."""
        descriptions = {
            RiskLevel.SAFE: "This password has not been found in any known data breaches.",
            RiskLevel.LOW: f"This password has been seen {self.occurrences} times in data breaches. Consider changing it.",
            RiskLevel.MEDIUM: f"This password has been seen {self.occurrences} times. You should change it.",
            RiskLevel.HIGH: f"This password has been seen {self.occurrences:,} times! Change it immediately.",
            RiskLevel.CRITICAL: f"This password has been seen {self.occurrences:,} times! It's extremely common and must be changed.",
        }
        return descriptions[self.risk_level]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "is_pwned": self.is_pwned,
            "occurrences": self.occurrences,
            "risk_level": self.risk_level.value,
            "risk_description": self.risk_description,
            "checked_at": self.checked_at.isoformat(),
            "cached": self.cached,
            "error": self.error,
        }


@dataclass
class PasteEntry:
    """Represents a paste containing the email address."""

    source: str
    id: str
    title: str | None
    date: datetime | None
    email_count: int

    @classmethod
    def from_api_response(cls, data: dict[str, Any]) -> "PasteEntry":
        """Create PasteEntry from HIBP API response."""
        date = None
        if data.get("Date"):
            try:
                date = datetime.fromisoformat(data["Date"].replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                pass

        return cls(
            source=data.get("Source", ""),
            id=data.get("Id", ""),
            title=data.get("Title"),
            date=date,
            email_count=data.get("EmailCount", 0),
        )


@dataclass
class DomainSearchResult:
    """Result of searching breaches for a domain."""

    domain: str
    breaches: list[Breach] = field(default_factory=list)
    total_accounts: int = 0
    checked_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "domain": self.domain,
            "breach_count": len(self.breaches),
            "total_accounts": self.total_accounts,
            "breaches": [b.to_dict() for b in self.breaches],
            "checked_at": self.checked_at.isoformat(),
        }
