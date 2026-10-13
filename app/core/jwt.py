from datetime import datetime, timedelta, timezone
from uuid import uuid4

from jose import jwt, JWTError

from app.config import settings


def create_access_token(sub, ttl_min=None):
    now = datetime.now(timezone.utc)

    minutes = (
        ttl_min
        if ttl_min is not None
        else settings.access_token_ttl_min
    )

    data = {
        "sub": str(sub),
        "iat": now,
        "exp": now + timedelta(minutes=minutes),
        "jti": str(uuid4()),
        "typ": "access"
    }

    return jwt.encode(
        data,
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm
    )


def decode_token(token):
    try:
        data = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm]
        )

        if data.get("typ") != "access":
            raise ValueError("Invalid token type")

        if not data.get("sub"):
            raise ValueError("Invalid token subject")

        return data

    except JWTError:
        raise ValueError("Invalid or expired token")