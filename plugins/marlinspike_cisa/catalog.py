"""CISA advisory catalog loader."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

DEFAULT_CATALOG_PATH = Path(__file__).resolve().parent / "catalog" / "cisa_catalog.json"


def load_catalog(catalog_path: Path = DEFAULT_CATALOG_PATH) -> dict[str, Any]:
    if not catalog_path.exists():
        raise FileNotFoundError(
            f"CISA catalog not found at {catalog_path}. "
            "Run scripts/sync_cisa_catalog.py to generate it."
        )
    with catalog_path.open() as fh:
        payload = json.load(fh)
    if not isinstance(payload, dict):
        raise ValueError(f"Unexpected catalog format at {catalog_path}")
    return payload


def get_advisories(catalog: dict[str, Any]) -> list[dict[str, Any]]:
    return list(catalog.get("advisories") or [])


def get_source_metadata(catalog: dict[str, Any]) -> dict[str, Any]:
    return dict(catalog.get("sources") or {})
