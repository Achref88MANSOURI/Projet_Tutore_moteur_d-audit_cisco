"""Known VTY transport normalization gap, isolated for a follow-up parser/normalizer task."""
import pytest
from cli import normalize


@pytest.mark.xfail(strict=True, reason="TTP capture validates services_transport, but normalizer does not consume that rule")
def test_vty_transport_capture_reaches_router_contract():
    document = normalize("hostname LAB\nline vty 0 4\n transport input ssh telnet\n!\n")
    lines = document["system"]["management"]["lines"]
    assert lines
    assert lines[0]["allowed_transports"] == ["ssh", "telnet"]
