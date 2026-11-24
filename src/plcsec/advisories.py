from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from plcsec.inventory import AssetInventory
from plcsec.safeio import read_stable_bytes

ADVISORY_SCHEMA = "plcsec.advisories.v1"
MAX_ADVISORY_FILE_BYTES = 16 * 1024 * 1024
MAX_ADVISORIES = 20_000
MAX_VERSIONS_PER_ADVISORY = 256
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}


@dataclass(frozen=True, slots=True)
class Advisory:
    advisory_id: str
    title: str
    vendor: str
    product: str
    affected_firmware_exact: tuple[str, ...]
    severity: str
    source_url: str
    recommendation: str = ""
    cves: tuple[str, ...] = ()
    published: str = ""


@dataclass(frozen=True, slots=True)
class AdvisoryDatabase:
    source_name: str
    advisories: tuple[Advisory, ...]


def _normal(value: str) -> str:
    return " ".join(value.casefold().strip().split())


def load_advisory_database(path: str | Path) -> AdvisoryDatabase:
    source = Path(path)
    raw_bytes = read_stable_bytes(source, max_bytes=MAX_ADVISORY_FILE_BYTES, label="Advisory database")
    try:
        data = json.loads(raw_bytes.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ValueError("Advisory database must be UTF-8 JSON") from exc
    if not isinstance(data, dict) or data.get("schema") != ADVISORY_SCHEMA:
        raise ValueError(f"Unsupported advisory database schema: {source}")
    if set(data) != {"schema", "source_name", "advisories"}:
        raise ValueError("Advisory database contains missing or unsupported top-level fields")
    raw_source_name = data.get("source_name")
    if not isinstance(raw_source_name, str):
        raise ValueError("Advisory database requires source_name as a string")
    source_name = raw_source_name.strip()
    if not source_name or len(source_name) > 256:
        raise ValueError("Advisory database requires source_name (1..256 characters)")
    raw_advisories = data.get("advisories")
    if not isinstance(raw_advisories, list) or not 1 <= len(raw_advisories) <= MAX_ADVISORIES:
        raise ValueError(f"Advisory database must contain 1..{MAX_ADVISORIES} records")
    result: list[Advisory] = []
    seen: set[str] = set()
    for index, raw in enumerate(raw_advisories):
        if not isinstance(raw, dict):
            raise ValueError(f"advisories[{index}] must be an object")
        allowed_fields = {
            "advisory_id", "title", "vendor", "product", "affected_firmware_exact",
            "severity", "source_url", "recommendation", "cves", "published",
        }
        if not set(raw).issubset(allowed_fields):
            raise ValueError(f"advisories[{index}] contains unsupported fields")
        text_values = (raw.get("advisory_id"), raw.get("title"), raw.get("vendor"), raw.get("product"))
        if not all(isinstance(value, str) for value in text_values):
            raise ValueError(f"advisories[{index}] identity fields must be strings")
        advisory_id, title_raw, vendor_raw, product_raw = text_values
        advisory_id = advisory_id.strip()
        duplicate_key = advisory_id.casefold()
        if not _ID.fullmatch(advisory_id) or duplicate_key in seen:
            raise ValueError(f"advisories[{index}] has an invalid or duplicate advisory_id")
        title = title_raw.strip()
        vendor = vendor_raw.strip()
        product = product_raw.strip()
        if not title or len(title) > 512 or not vendor or len(vendor) > 128 or not product or len(product) > 256:
            raise ValueError(f"advisories[{index}] requires bounded title, vendor and product")
        versions = raw.get("affected_firmware_exact")
        if not isinstance(versions, list) or not 1 <= len(versions) <= MAX_VERSIONS_PER_ADVISORY:
            raise ValueError(f"advisories[{index}].affected_firmware_exact must contain 1..{MAX_VERSIONS_PER_ADVISORY} exact strings")
        cleaned_versions: list[str] = []
        for version in versions:
            if not isinstance(version, str):
                raise ValueError(f"advisories[{index}] firmware versions must be strings")
            text = version.strip()
            if not text or len(text) > 128:
                raise ValueError(f"advisories[{index}] contains an empty or overlong firmware version")
            if _normal(text) not in {_normal(item) for item in cleaned_versions}:
                cleaned_versions.append(text)
        raw_severity = raw.get("severity")
        if not isinstance(raw_severity, str):
            raise ValueError(f"advisories[{index}].severity must be a string")
        severity = raw_severity.strip().lower()
        if severity not in _VALID_SEVERITIES:
            raise ValueError(f"advisories[{index}].severity must be one of {sorted(_VALID_SEVERITIES)}")
        raw_source_url = raw.get("source_url")
        if not isinstance(raw_source_url, str):
            raise ValueError(f"advisories[{index}].source_url must be a string")
        source_url = raw_source_url.strip()
        parsed_url = urlparse(source_url)
        try:
            port = parsed_url.port
        except ValueError as exc:
            raise ValueError(f"advisories[{index}].source_url has an invalid port") from exc
        if (
            parsed_url.scheme != "https"
            or not parsed_url.hostname
            or parsed_url.username is not None
            or parsed_url.password is not None
            or (port is not None and not 1 <= port <= 65535)
            or len(source_url) > 2048
        ):
            raise ValueError(f"advisories[{index}].source_url must be a bounded HTTPS URL without userinfo")
        recommendation_raw = raw.get("recommendation", "")
        if not isinstance(recommendation_raw, str):
            raise ValueError(f"advisories[{index}].recommendation must be a string")
        recommendation = recommendation_raw
        if len(recommendation) > 4096:
            raise ValueError(f"advisories[{index}].recommendation exceeds 4096 characters")
        cves_raw = raw.get("cves", [])
        if not isinstance(cves_raw, list) or len(cves_raw) > 64:
            raise ValueError(f"advisories[{index}].cves must be an array of at most 64 CVE IDs")
        cves: list[str] = []
        for cve in cves_raw:
            if not isinstance(cve, str):
                raise ValueError(f"advisories[{index}] CVE identifiers must be strings")
            text = cve.upper()
            if not _CVE.fullmatch(text):
                raise ValueError(f"advisories[{index}] contains an invalid CVE identifier")
            cves.append(text)
        published_raw = raw.get("published", "")
        if not isinstance(published_raw, str):
            raise ValueError(f"advisories[{index}].published must be a string")
        published = published_raw
        if published:
            if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", published):
                raise ValueError(f"advisories[{index}].published must be YYYY-MM-DD")
            try:
                date.fromisoformat(published)
            except ValueError as exc:
                raise ValueError(f"advisories[{index}].published must be YYYY-MM-DD") from exc
        result.append(Advisory(
            advisory_id=advisory_id, title=title, vendor=vendor, product=product,
            affected_firmware_exact=tuple(cleaned_versions), severity=severity,
            source_url=source_url, recommendation=recommendation,
            cves=tuple(cves), published=published,
        ))
        seen.add(duplicate_key)
    return AdvisoryDatabase(source_name, tuple(result))


def validate_advisory_database(path: str | Path) -> dict[str, Any]:
    database = load_advisory_database(path)
    return {
        "schema": ADVISORY_SCHEMA,
        "source_name": database.source_name,
        "advisory_count": len(database.advisories),
        "cve_reference_count": sum(len(item.cves) for item in database.advisories),
        "match_policy": "exact normalized vendor, product/model and firmware string; no fuzzy/range matching",
    }


def match_advisories(inventory: AssetInventory, database: AdvisoryDatabase) -> dict[str, Any]:
    matches: list[dict[str, Any]] = []
    missing_identity: list[dict[str, str]] = []
    for asset in inventory.assets:
        if not asset.vendor.strip() or not asset.model.strip() or not asset.firmware.strip():
            missing_identity.append({"asset_id": asset.asset_id, "ip": asset.ip, "reason": "vendor_model_or_firmware_missing"})
            continue
        asset_vendor = _normal(asset.vendor)
        asset_model = _normal(asset.model)
        asset_firmware = _normal(asset.firmware)
        for advisory in database.advisories:
            if asset_vendor != _normal(advisory.vendor) or asset_model != _normal(advisory.product):
                continue
            if asset_firmware not in {_normal(version) for version in advisory.affected_firmware_exact}:
                continue
            matches.append({
                "asset_id": asset.asset_id,
                "ip": asset.ip,
                "vendor": asset.vendor,
                "model": asset.model,
                "observed_firmware": asset.firmware,
                "advisory_id": advisory.advisory_id,
                "title": advisory.title,
                "severity": advisory.severity,
                "cves": list(advisory.cves),
                "published": advisory.published,
                "source_name": database.source_name,
                "source_url": advisory.source_url,
                "recommendation": advisory.recommendation,
                "match_confidence": "exact-normalized-string-match",
                "interpretation": "Candidate advisory match against operator-supplied inventory and advisory data; confirm product revision, firmware provenance and vendor applicability before remediation.",
            })
    return {
        "schema": "plcsec.advisory-matches.v1",
        "site_id": inventory.site_id,
        "advisory_source": database.source_name,
        "match_policy": "exact normalized vendor, product/model and firmware string; no semver inference, wildcard or fuzzy matching",
        "match_count": len(matches),
        "matches": matches,
        "assets_missing_identity": missing_identity,
        "is_vendor_applicability_confirmed": False,
    }


def match_advisory_files(inventory_path: str | Path, advisory_path: str | Path) -> dict[str, Any]:
    from plcsec.inventory import load_inventory
    return match_advisories(load_inventory(inventory_path), load_advisory_database(advisory_path))
