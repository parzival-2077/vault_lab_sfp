from datetime import datetime, timezone, timedelta
from uuid import uuid4

from fastapi import Request
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.config import settings
from app.models.models import (
    RefreshToken, OAuthClient, UserSession, User
)
from app.core.security.tokens import (
    generate_opaque_token, hash_token
)
from app.oauth.helpers import issue_tokens, oauth_error
from app.audit.service import write_event


def handle(
    db: Session,
    client: OAuthClient,
    refresh_token: str,
    scope: str | None,
    request: Request
):
    if "refresh_token" not in (client.grant_types or []):
        oauth_error("unauthorized_client")

    token_hash = hash_token(refresh_token)
    rt = db.scalar(
        select(RefreshToken).where(RefreshToken.token_hash == token_hash)
    )

    if not rt:
        oauth_error("invalid_grant", "Unknown refresh token")

    # ---- Reuse detection ----
    if rt.used_at is not None:
        now = datetime.now(timezone.utc)
        db.execute(
            update(RefreshToken)
            .where(RefreshToken.family_id == rt.family_id)
            .values(revoked_at=now)
        )
        db.execute(
            update(UserSession)
            .where(UserSession.family_id == rt.family_id)
            .values(revoked_at=now)
        )
        write_event(
            db, "token.reuse_detected",
            client_id=rt.client_id,
            actor_id=rt.user_id,
            ip=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            metadata={"family_id": rt.family_id},
            commit=False
        )
        db.commit()
        oauth_error("invalid_grant", "Refresh token reuse detected")

    if rt.revoked_at is not None:
        oauth_error("invalid_grant", "Refresh token revoked")

    if rt.expires_at < datetime.now(timezone.utc):
        oauth_error("invalid_grant", "Refresh token expired")

    if rt.client_id != client.client_id:
        oauth_error("invalid_grant", "Client mismatch")

    user = db.get(User, rt.user_id)
    if not user or not user.is_active:
        oauth_error("invalid_grant", "User inactive")

    # Scope narrowing
    new_scope = rt.scope
    if scope:
        requested = set(scope.split())
        if not requested.issubset(set(rt.scope.split())):
            oauth_error("invalid_scope")
        new_scope = scope

    # Rotation
    new_plain = generate_opaque_token()
    new_hash = hash_token(new_plain)

    rt.used_at = datetime.now(timezone.utc)
    rt.replaced_by_hash = new_hash

    new_rt = RefreshToken(
        jti=str(uuid4()),
        family_id=rt.family_id,
        token_hash=new_hash,
        user_id=rt.user_id,
        client_id=rt.client_id,
        scope=new_scope,
        expires_at=datetime.now(timezone.utc) + timedelta(
            days=settings.refresh_token_ttl_days
        )
    )
    db.add(new_rt)

    sess = db.scalar(
        select(UserSession).where(UserSession.family_id == rt.family_id)
    )
    if sess:
        sess.last_seen_at = datetime.now(timezone.utc)

    write_event(
        db, "token.refreshed",
        actor_id=user.id,
        client_id=client.client_id,
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        metadata={"family_id": rt.family_id},
        commit=False
    )

    # Единая выдача: пишет token.issued, подписывает access и (если openid) id_token
    result = issue_tokens(
        db, user, client, new_scope,
        grant_type="refresh_token",
        family_id=rt.family_id,
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        include_refresh=False,   # refresh уже создан вручную выше
        commit=False
    )

    # Подменяем access-токен в ответе на новый refresh
    result["refresh_token"] = new_plain

    db.commit()
    return result