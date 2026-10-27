from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.models import User
from app.core.security.jwt_rsa import verify_token
from app.redis_client import is_blacklisted


router = APIRouter(tags=["OIDC / UserInfo"])


@router.get("/oauth/userinfo")
def userinfo(
    authorization: str | None = Header(None),
    db: Session = Depends(get_db)
):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Bearer required")

    try:
        payload = verify_token(authorization.split(" ", 1)[1])
    except ValueError:
        raise HTTPException(401, "Invalid token")

    if is_blacklisted(payload.get("jti", "")):
        raise HTTPException(401, "Token revoked")

    user = db.scalar(
        select(User).where(User.id == int(payload["sub"]))
    )
    if not user or not user.is_active:
        raise HTTPException(401, "Invalid user")

    scopes = set((payload.get("scope") or "").split())
    result = {"sub": str(user.id)}

    if "email" in scopes:
        result["email"] = user.email
        result["email_verified"] = False

    if "profile" in scopes:
        result["preferred_username"] = user.email
        result["name"] = user.email
        result["updated_at"] = int(user.created_at.timestamp())

    return result