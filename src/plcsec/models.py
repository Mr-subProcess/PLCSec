from __future__ import annotations

from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(slots=True)
class Finding:
    finding_id: str
    title: str
    severity: Severity
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""
    confidence: str = "medium"
    source: str = "plcsec"
    priority_score: int = 0
    tags: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ServiceObservation:
    protocol: str
    port: int
    packets: int = 0
    client_to_server: int = 0
    server_to_client: int = 0
    notes: list[str] = field(default_factory=list)
    bytes_observed: int = 0
    flows_observed: int = 0


@dataclass(slots=True)
class FlowObservation:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    transport: str
    packets: int = 0
    bytes_observed: int = 0
    first_seen: str | None = None
    last_seen: str | None = None


@dataclass(slots=True)
class Asset:
    ip: str
    mac_addresses: list[str] = field(default_factory=list)
    observed_services: list[ServiceObservation] = field(default_factory=list)
    packets_seen: int = 0
    first_seen: str | None = None
    last_seen: str | None = None
    labels: list[str] = field(default_factory=list)
    vendor_hints: list[str] = field(default_factory=list)
    inventory_metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class AssessmentReport:
    tool: str
    tool_version: str
    assessment_type: str
    started_at: str
    completed_at: str
    scope: dict[str, Any]
    assets: list[Asset] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    events: list[dict[str, Any]] = field(default_factory=list)
    flows: list[FlowObservation] = field(default_factory=list)
    schema_version: str = "plcsec.report.v2"

    @classmethod
    def create(cls, assessment_type: str, scope: dict[str, Any]) -> "AssessmentReport":
        now = utc_now()
        from plcsec import __version__

        return cls(
            tool="PLCSEC",
            tool_version=__version__,
            assessment_type=assessment_type,
            started_at=now,
            completed_at=now,
            scope=scope,
        )

    def finish(self) -> None:
        self.completed_at = utc_now()

    def to_dict(self) -> dict[str, Any]:
        return to_jsonable(asdict(self))


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def to_jsonable(value: Any) -> Any:
    if is_dataclass(value):
        return to_jsonable(asdict(value))
    if isinstance(value, StrEnum):
        return str(value)
    if isinstance(value, dict):
        return {str(k): to_jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [to_jsonable(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if hasattr(value, "__dict__"):
        return to_jsonable(vars(value))
    if hasattr(value, "_asdict"):
        return to_jsonable(value._asdict())
    return str(value)
