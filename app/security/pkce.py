import base64
import hashlib
import hmac


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def verify_pkce(
    code_verifier: str,
    code_challenge: str,
    method: str
) -> bool:
    if not code_verifier or not code_challenge:
        return False

    if not (43 <= len(code_verifier) <= 128):
        return False

    if method == "S256":
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        computed = _b64url(digest)
        return hmac.compare_digest(computed, code_challenge)

    if method == "plain":
        return hmac.compare_digest(code_verifier, code_challenge)

    return False