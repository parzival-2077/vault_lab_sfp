
import hashlib
import secrets


def generate_opaque_token() -> str:
    """Случайная opaque-строка для refresh-токена / auth-кода."""
    return secrets.token_urlsafe(48)


def hash_token(token: str) -> str:
    """SHA-256 хэш токена. В БД хранится только он."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()