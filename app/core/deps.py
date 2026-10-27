from fastapi import Depends, HTTPException, Header
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.models import User
from app.core.security.jwt_rsa import verify_token
from app.redis_client import is_blacklisted


def get_current_user(
    authorization: str | None = Header(None),
    db: Session = Depends(get_db)
):
    """
    Возвращает текущего пользователя по Bearer-токену.

    Принимает как OAuth2 access-токены (aud=client_id),
    так и легаси-токены из /auth/* (aud="vault-internal").
    В обоих случаях sub == str(user.id).
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Authentication required")

    token = authorization.split(" ", 1)[1]

    try:
        payload = verify_token(token)
    except ValueError:
        raise HTTPException(401, "Invalid token")

    if is_blacklisted(payload.get("jti", "")):
        raise HTTPException(401, "Token revoked")

    try:
        user_id = int(payload["sub"])
    except (KeyError, ValueError):
        raise HTTPException(401, "Invalid token subject")

    user = db.scalar(select(User).where(User.id == user_id))

    if not user or not user.is_active:
        raise HTTPException(401, "Invalid user")

    return user


def require_admin(user=Depends(get_current_user)):
    """Требует is_admin=True, иначе 403."""
    if not user.is_admin:
        raise HTTPException(403, "Admin only")

    return user