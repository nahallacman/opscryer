# SPDX-License-Identifier: Apache-2.0
"""Namespaced OpsCryer Brain/Meshworks bridge subpackage."""

from __future__ import annotations

from opscryer.bridge.hydrogen_cast import (
    handle_hydrogen_cast_request,
    resolve_target_context_from_catalog,
)
from opscryer.bridge.opscryer_bridge import (
    CONTRACT_VERSION,
    build_spatial_contract_from_ecosystem,
    build_spatial_graph_catalog,
    filter_spatial_catalog_by_clearance,
    overlay_ecosystem_onto_catalog,
)

__all__ = [
    "CONTRACT_VERSION",
    "build_spatial_contract_from_ecosystem",
    "build_spatial_graph_catalog",
    "filter_spatial_catalog_by_clearance",
    "handle_hydrogen_cast_request",
    "overlay_ecosystem_onto_catalog",
    "resolve_target_context_from_catalog",
]
