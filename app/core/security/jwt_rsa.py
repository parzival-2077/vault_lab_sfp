from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from jose import JWTError, jwt

from app.config import settings


@lru_cache
def load_private_key():
    pem = Path(settings.rsa_key_path).read_bytes()

    return serialization.load_pem_private_key(
        pem,
        password=None
    )


@lru_cache
def load_public_key():
    return load_private_key().public_key()


@lru_cache
def private_pem():
    return load_private_key().private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )


@lru_cache
def public_pem():
    return load_public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def sign_access_token(
    sub: str,
    client_id: str,
    scopes: list[str],
    ttl_sec: int | None = None
):
    now = datetime.now(timezone.utc)
    ttl = ttl_sec or settings.access_token_ttl_sec

    payload = {
        "iss": settings.issuer,
        "sub": str(sub),
        "aud": client_id,
        "client_id": client_id,
        "scope": " ".join(scopes),
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=ttl)).timestamp()),
        "jti": str(uuid4()),
        "typ": "access"
    }

    return jwt.encode(
        payload,
        private_pem(),
        algorithm="RS256",
        headers={
            "kid": settings.rsa_key_id,
            "typ": "JWT"
        }
    )


def sign_id_token(
    sub: str,
    client_id: str,
    nonce: str | None = None,
    user=None,
    scopes: list[str] | None = None,
    ttl_sec: int | None = None
):
    now = datetime.now(timezone.utc)
    ttl = ttl_sec or settings.access_token_ttl_sec
    scopes = scopes or []

    payload = {
        "iss": settings.issuer,
        "sub": str(sub),
        "aud": client_id,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=ttl)).timestamp())
    }

    if nonce:
        payload["nonce"] = nonce

    if user is not None:
        if "email" in scopes:
            payload["email"] = user.email
            payload["email_verified"] = False

        if "profile" in scopes:
            payload["preferred_username"] = user.email
            payload["name"] = user.email

    return jwt.encode(
        payload,
        private_pem(),
        algorithm="RS256",
        headers={
            "kid": settings.rsa_key_id,
            "typ": "JWT"
        }
    )


def verify_token(
    token: str,
    audience: str | None = None,
    expected_type: str = "access"
):
    try:
        payload = jwt.decode(
            token,
            public_pem(),
            algorithms=["RS256"],
            issuer=settings.issuer,
            audience=audience,
            options={
                "verify_aud": audience is not None,
                "require_exp": True,
                "require_iat": True,
                "require_iss": True,
                "require_sub": True
            }
        )

        if expected_type == "access":
            if payload.get("typ") != "access":
                raise ValueError("Invalid token type")

        elif expected_type == "id":
            if payload.get("typ") is not None:
                raise ValueError("Invalid ID token")

        else:
            raise ValueError("Unsupported token type")

        if jwt.get_unverified_header(token).get("kid") != settings.rsa_key_id:
            raise ValueError("Unknown key ID")

        return payload

    except (JWTError, ValueError) as exc:
        raise ValueError("Invalid or expired token") from exc