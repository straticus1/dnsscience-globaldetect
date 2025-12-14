"""
Neighbor Discovery Protocol utilities (CDP, LLDP).

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

from globaldetect.neighbors.core import (
    CDPNeighbor,
    LLDPNeighbor,
    CDPListener,
    LLDPListener,
    CombinedListener,
    discover_neighbors,
    get_interfaces,
    get_physical_interfaces,
)

__all__ = [
    "CDPNeighbor",
    "LLDPNeighbor",
    "CDPListener",
    "LLDPListener",
    "CombinedListener",
    "discover_neighbors",
    "get_interfaces",
    "get_physical_interfaces",
]
