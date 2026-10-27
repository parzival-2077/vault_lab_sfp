import base64
import hashlib

from app.core.security.pkce import verify_pkce


def _challenge(verifier: str) -> str:
    return base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()


def test_pkce_s256_ok():
    verifier = "a" * 50
    assert verify_pkce(verifier, _challenge(verifier), "S256")


def test_pkce_wrong():
    assert not verify_pkce("x" * 50, "wrong", "S256")


def test_pkce_short():
    assert not verify_pkce("short", _challenge("short"), "S256")


def test_pkce_too_long():
    verifier = "a" * 129
    assert not verify_pkce(verifier, _challenge(verifier), "S256")


def test_pkce_plain():
    verifier = "a" * 50
    assert verify_pkce(verifier, verifier, "plain")