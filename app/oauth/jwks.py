import base64

from fastapi import APIRouter
from cryptography.hazmat.primitives.asymmetric import rsa

from app.config import settings
from app.core.security.jwt_rsa import load_public_key


router = APIRouter(tags=["OAuth2 / JWKS"])


def base64url_uint(value: int) -> str:
    size = (value.bit_length() + 7) // 8
    raw = value.to_bytes(size, "big")

    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def build_jwks():
    public_key = load_public_key()

    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("Expected RSA public key")

    numbers = public_key.public_numbers()

    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": settings.rsa_key_id,
                "n": base64url_uint(numbers.n),
                "e": base64url_uint(numbers.e)
            }
        ]
    }


@router.get("/.well-known/jwks.json")
def get_jwks():
    return build_jwks()