# SPDX-License-Identifier: Apache-2.0
"""Backwards-compatible shim for ``opscryer.bridge.opscryer_bridge``."""

from __future__ import annotations

from opscryer.bridge.opscryer_bridge import (
    CONTRACT_VERSION,
    _CATEGORY_TO_DOMAIN,
    _load_json_safe,
    _map_meshworks_kind,
    _resolve_meshworks_node_id,
    _safe_id,
    build_spatial_contract_from_ecosystem,
    build_spatial_graph_catalog,
    main,
    overlay_ecosystem_onto_catalog,
)

__all__ = [
    "CONTRACT_VERSION",
    "build_spatial_contract_from_ecosystem",
    "build_spatial_graph_catalog",
    "main",
    "overlay_ecosystem_onto_catalog",
]

if __name__ == "__main__":
    raise SystemExit(main())
