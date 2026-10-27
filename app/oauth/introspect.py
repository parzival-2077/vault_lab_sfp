import time
from datetime import datetime, timezone

from fastapi import APIRouter, Form, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.models import OAuthClient, RefreshToken
from app.core.security.tokens import hash_token
from app.core.security.jwt_rsa import verify_token
from app.redis_client import is_blacklisted
from app.oauth.helpers import authenticate_client, oauth_error


router = APIRouter(tags=["OAuth2 / Introspect"])


@router.post("/oauth/introspect")
def introspect(
    token: str = Form(...),
    token_type_hint: str | None = Form(None),
    client_id: str = Form(...),
    client_secret: str | None = Form(None),
    db: Session = Depends(get_db)
):
    client = authenticate_client(db, client_id, client_secret)
    if not client.hashed_secret:
        oauth_error("invalid_client", status_code=401)

    # access
    try:
        payload = verify_token(token)
        if not is_blacklisted(payload.get("jti", "")) \
                and payload.get("exp", 0) > int(time.time()):
            return {
                "active": True,
                "token_type": "Bearer",
                "sub": payload.get("sub"),
                "scope": payload.get("scope"),
                "client_id": payload.get("client_id"),
                "exp": payload.get("exp"),
                "iss": payload.get("iss")
            }
    except ValueError:
        pass

    # refresh
    rt = db.scalar(
        select(RefreshToken).where(
            RefreshToken.token_hash == hash_token(token)
        )
    )
    if rt and rt.revoked_at is None and rt.used_at is None \
            and rt.expires_at > datetime.now(timezone.utc):
        return {
            "active": True,
            "token_type": "refresh_token",
            "sub": str(rt.user_id),
            "client_id": rt.client_id,
            "exp": int(rt.expires_at.timestamp())
        }

    return {"active": False}