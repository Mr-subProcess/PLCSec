from plcsec.cli import main


def test_modules_list(capsys) -> None:
    assert main(["modules", "list"]) == 0
    output = capsys.readouterr().out
    assert "protocol.modbus.tcp" in output
    assert "protocol.s7comm.tpkt" in output
    assert "baseline.asset-drift" in output


def test_active_command_fails_closed_without_authorized_flag(tmp_path, capsys) -> None:
    allowlist = tmp_path / "targets.txt"
    allowlist.write_text("192.0.2.5\n", encoding="utf-8")
    result = main([
        "audit", "modbus-id", "--target", "192.0.2.5",
        "--allowlist", str(allowlist), "--out", str(tmp_path / "report"),
    ])
    assert result == 2
    assert "require --authorized" in capsys.readouterr().err
