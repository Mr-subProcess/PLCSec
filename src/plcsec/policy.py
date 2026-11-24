from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path


class AuthorizationError(PermissionError):
    """Raised when an active check is not explicitly in scope."""


@dataclass(frozen=True, slots=True)
class TargetScope:
    networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]

    @classmethod
    def from_file(cls, path: str | Path) -> "TargetScope":
        networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for line_no, raw in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            try:
                networks.append(ipaddress.ip_network(line, strict=False))
            except ValueError as exc:
                raise ValueError(f"Invalid allowlist entry at {path}:{line_no}: {line}") from exc
        if not networks:
            raise ValueError(f"Allowlist is empty: {path}")
        return cls(tuple(networks))

    def permits(self, target: str) -> bool:
        try:
            address = ipaddress.ip_address(target)
        except ValueError:
            return False
        return any(address.version == net.version and address in net for net in self.networks)


def require_authorized_target(
    target: str,
    allowlist_path: str | Path | None,
    explicitly_authorized: bool,
) -> None:
    if not explicitly_authorized:
        raise AuthorizationError(
            "Active PLC checks require --authorized and an explicit target allowlist."
        )
    if allowlist_path is None:
        raise AuthorizationError("Active PLC checks require --allowlist FILE.")
    scope = TargetScope.from_file(allowlist_path)
    if not scope.permits(target):
        raise AuthorizationError(
            f"Target {target!r} is not covered by the supplied allowlist. No network request sent."
        )
