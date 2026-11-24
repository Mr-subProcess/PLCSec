from types import SimpleNamespace

from plcsec.plugins.s7 import audit_s7_identity


def test_s7_adapter_calls_identity_methods_only(monkeypatch) -> None:
    calls: list[str] = []

    class FakeClient:
        def __init__(self, **kwargs) -> None:
            assert kwargs["auto_reconnect"] is False
            assert kwargs["max_retries"] == 0

        def connect(self, target, rack, slot, tcp_port=102):
            calls.append("connect")

        def get_cpu_info(self):
            calls.append("get_cpu_info")
            return {"module": "CPU 1511"}

        def get_order_code(self):
            calls.append("get_order_code")
            return {"order_code": "6ES7-TEST", "firmware": "1.0"}

        def disconnect(self):
            calls.append("disconnect")

        def db_read(self, *args, **kwargs):  # pragma: no cover - must never be called
            raise AssertionError("process memory reads are not part of identity audit")

    monkeypatch.setitem(__import__("sys").modules, "snap7", SimpleNamespace(Client=FakeClient))
    report = audit_s7_identity("192.0.2.10")
    assert calls == ["connect", "get_cpu_info", "get_order_code", "disconnect"]
    assert report.metadata["memory_area_reads"] == 0
    assert report.metadata["writes_sent"] == 0
