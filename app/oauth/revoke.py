from datetime import datetime, timezone
import time

from fastapi import APIRouter, Form, Depends
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.models import RefreshToken, UserSession
from app.core.security.tokens import hash_token
from app.core.security.jwt_rsa import verify_token
from app.redis_client import blacklist_jti
from app.audit.service import write_event


router = APIRouter(tags=["OAuth2 / Revoke"])


@router.post("/oauth/revoke")
def revoke(
    token: str = Form(...),
    token_type_hint: str | None = Form(None),
    db: Session = Depends(get_db)
):
    # refresh
    rt = db.scalar(
        select(RefreshToken).where(
            RefreshToken.token_hash == hash_token(token)
        )
    )
    if rt and rt.revoked_at is None:
        rt.revoked_at = datetime.now(timezone.utc)
        db.execute(
            update(UserSession)
            .where(UserSession.family_id == rt.family_id)
            .values(revoked_at=datetime.now(timezone.utc))
        )
        write_event(
            db, "token.revoked",
            actor_id=rt.user_id,
            client_id=rt.client_id,
            metadata={"family_id": rt.family_id, "type": "refresh"}
        )
        return {"ok": True}

    # access
    try:
        payload = verify_token(token)
        jti = payload.get("jti")
        exp = payload.get("exp", 0)
        ttl = max(0, exp - int(time.time()))
        if jti:
            blacklist_jti(jti, ttl)
            write_event(
                db, "token.revoked",
                client_id=payload.get("client_id"),
                metadata={"jti": jti, "type": "access"}
            )
    except ValueError:
        pass

    return {"ok": True}