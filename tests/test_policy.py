from pathlib import Path

import pytest

from plcsec.policy import AuthorizationError, TargetScope, require_authorized_target


def test_allowlist_exact_ip_and_cidr(tmp_path: Path) -> None:
    allowlist = tmp_path / "targets.txt"
    allowlist.write_text("# lab scope\n192.0.2.10\n198.51.100.0/24\n", encoding="utf-8")
    scope = TargetScope.from_file(allowlist)
    assert scope.permits("192.0.2.10")
    assert scope.permits("198.51.100.24")
    assert not scope.permits("192.0.2.11")
    assert not scope.permits("example.com")


def test_active_requires_explicit_authorization(tmp_path: Path) -> None:
    allowlist = tmp_path / "targets.txt"
    allowlist.write_text("192.0.2.10\n", encoding="utf-8")
    with pytest.raises(AuthorizationError):
        require_authorized_target("192.0.2.10", allowlist, False)


def test_active_rejects_target_outside_allowlist(tmp_path: Path) -> None:
    allowlist = tmp_path / "targets.txt"
    allowlist.write_text("192.0.2.10\n", encoding="utf-8")
    with pytest.raises(AuthorizationError):
        require_authorized_target("192.0.2.11", allowlist, True)


def test_active_accepts_explicit_in_scope_target(tmp_path: Path) -> None:
    allowlist = tmp_path / "targets.txt"
    allowlist.write_text("192.0.2.0/24\n", encoding="utf-8")
    require_authorized_target("192.0.2.42", allowlist, True)


def test_invalid_allowlist_line_fails_closed(tmp_path: Path) -> None:
    allowlist = tmp_path / "targets.txt"
    allowlist.write_text("192.0.2.1\nnot-a-network\n", encoding="utf-8")
    with pytest.raises(ValueError):
        TargetScope.from_file(allowlist)
