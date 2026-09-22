"""Dev sender policy checks using stubs only; no HTTP requests."""
import argparse
import ssl

import pytest

from scripts import send_test_notification as sender


def test_sender_requires_explicit_pairing_and_never_rebinds_on_401(monkeypatch):
    calls = []
    monkeypatch.setattr(sender, "_load_cache", lambda _: None)
    monkeypatch.setattr(sender, "_save_cache", lambda *args: None)
    args = argparse.Namespace(base_url="https://localhost", pair_code="", no_cache=False)
    with pytest.raises(ValueError, match="pair-code"):
        sender._get_token(args)

    def pair(*args, **kwargs):
        calls.append(args)
        return {"access_token": "paired-access"}

    monkeypatch.setattr(sender, "_request", pair)
    args.pair_code = "abcd-efgh"
    assert sender._get_token(args) == "paired-access"
    assert calls[0][2] == "/api/v1/devices/pair/consume"
    assert calls[0][3]["code"] == "ABCD-EFGH"

    def expired(*args):
        calls.append(args)
        raise sender.HttpError(401, "Expired")

    monkeypatch.setattr(sender, "_request", expired)
    with pytest.raises(ValueError, match="fresh --pair-code"):
        sender._create(args.base_url, "expired-token", {})
    assert len(calls) == 2


def test_sender_remote_transport_requires_trust_and_no_redirects():
    assert sender._ssl_context("https://server.example").verify_mode == ssl.CERT_REQUIRED
    assert sender._ssl_context("https://localhost").verify_mode == ssl.CERT_NONE
    with pytest.raises(ValueError, match="HTTPS"):
        sender._ssl_context("http://server.example")
    assert sender.NoRedirect().redirect_request(None, None, 302, "", {}, "https://other.example") is None
