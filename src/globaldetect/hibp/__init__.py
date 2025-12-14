"""
Have I Been Pwned (HIBP) integration module.

Provides breach checking for email addresses and password security
validation using the HIBP API with k-anonymity for passwords.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

from globaldetect.hibp.models import (
    Breach,
    BreachCheckResult,
    PasswordCheckResult,
)
from globaldetect.hibp.client import HIBPClient

__all__ = [
    "HIBPClient",
    "Breach",
    "BreachCheckResult",
    "PasswordCheckResult",
]
