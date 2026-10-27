from datetime import datetime, timezone, timedelta
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.models.models import (
    OAuthClient, RefreshToken, UserSession
)
from app.core.passwords import verify_password
from app.core.security.jwt_rsa import (
    sign_access_token, sign_id_token
)
from app.core.security.tokens import (
    generate_opaque_token, hash_token
)
from app.audit.service import write_event


def oauth_error(
    error: str,
    description: str | None = None,
    status_code: int = 400
):
    body = {"error": error}
    if description:
        body["error_description"] = description
    raise HTTPException(status_code, detail=body)


def authenticate_client(
    db: Session,
    client_id: str,
    client_secret: str | None
) -> OAuthClient:
    client = db.scalar(
        select(OAuthClient).where(
            OAuthClient.client_id == client_id
        )
    )

    if not client or not client.is_active:
        oauth_error("invalid_client", status_code=401)

    if client.hashed_secret:
        if not client_secret or not verify_password(
            client_secret, client.hashed_secret
        ):
            oauth_error("invalid_client", status_code=401)

    return client


def issue_tokens(
    db: Session,
    user,
    client: OAuthClient,
    scope_str: str,
    *,
    grant_type: str,
    family_id: str | None = None,
    nonce: str | None = None,
    ip: str | None = None,
    user_agent: str | None = None,
    include_refresh: bool = True,
    commit: bool = True
):
    scopes = [s for s in scope_str.split() if s]

    access = sign_access_token(
        sub=str(user.id) if user else client.client_id,
        client_id=client.client_id,
        scopes=scopes
    )

    refresh_plain = None
    refresh_hash = None

    if include_refresh and user is not None:
        refresh_plain = generate_opaque_token()
        refresh_hash = hash_token(refresh_plain)

        if not family_id:
            family_id = str(uuid4())

        rt = RefreshToken(
            jti=str(uuid4()),
            family_id=family_id,
            token_hash=refresh_hash,
            user_id=user.id,
            client_id=client.client_id,
            scope=scope_str,
            expires_at=datetime.now(timezone.utc) + timedelta(
                days=settings.refresh_token_ttl_days
            )
        )
        db.add(rt)
        db.flush()

        # Первая выдача семейства → создать UserSession
        if not db.scalar(
            select(UserSession).where(
                UserSession.family_id == family_id
            )
        ):
            db.add(UserSession(
                user_id=user.id,
                client_id=client.client_id,
                family_id=family_id,
                ip=ip,
                user_agent=user_agent
            ))

    id_token = None
    if user is not None and "openid" in scopes:
        id_token = sign_id_token(
            sub=str(user.id),
            client_id=client.client_id,
            nonce=nonce,
            user=user,
            scopes=scopes
        )

    write_event(
        db, "token.issued",
        actor_id=user.id if user else None,
        client_id=client.client_id,
        ip=ip, user_agent=user_agent,
        metadata={"grant_type": grant_type, "scope": scope_str},
        commit=False
    )

    if commit:
        db.commit()

    result = {
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": settings.access_token_ttl_sec,
        "scope": scope_str
    }
    if refresh_plain:
        result["refresh_token"] = refresh_plain
    if id_token:
        result["id_token"] = id_token
    return result