from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from plcsec.signing import SignatureError, generate_ed25519_keypair, sign_baseline, verify_baseline


def test_ed25519_baseline_signature_roundtrip_and_tamper_detection(tmp_path: Path) -> None:
    private = tmp_path / "baseline-private.pem"
    public = tmp_path / "baseline-public.pem"
    baseline = tmp_path / "site-baseline.json"
    signature = tmp_path / "site-baseline.sig.json"
    baseline.write_text('{"schema":"plcsec.baseline.v1","site_id":"test","assets":{}}\n')

    meta = generate_ed25519_keypair(private, public)
    assert private.stat().st_mode & 0o777 == 0o600
    assert len(meta["public_key_sha256"]) == 64
    sign_baseline(baseline, private, signature)
    result = verify_baseline(baseline, public, signature)
    assert result["valid"] is True

    baseline.write_text('{"schema":"plcsec.baseline.v1","site_id":"tampered","assets":{}}\n')
    with pytest.raises(SignatureError, match="SHA-256"):
        verify_baseline(baseline, public, signature)


def test_keygen_will_not_overwrite_without_force(tmp_path: Path) -> None:
    private, public = tmp_path / "private.pem", tmp_path / "public.pem"
    generate_ed25519_keypair(private, public)
    with pytest.raises(FileExistsError):
        generate_ed25519_keypair(private, public)
