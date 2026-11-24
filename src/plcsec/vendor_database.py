from __future__ import annotations

import json
from importlib.resources import files
from typing import Any


def load_vendor_database() -> dict[str, Any]:
    resource = files("plcsec").joinpath("data/vendor_profiles.json")
    data = json.loads(resource.read_text(encoding="utf-8"))
    if data.get("schema") != "plcsec.vendor-profiles.v1":
        raise ValueError("Unsupported vendor profile database schema")
    return data


def list_vendors() -> list[dict[str, Any]]:
    return list(load_vendor_database().get("manufacturers", []))


def get_vendor_profile(vendor_id: str) -> dict[str, Any] | None:
    for profile in list_vendors():
        if profile.get("id") == vendor_id:
            return profile
    return None
