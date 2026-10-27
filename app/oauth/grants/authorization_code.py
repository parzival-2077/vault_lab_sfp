from datetime import datetime, timezone

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.models.models import AuthCode, OAuthClient, User
from app.core.security.tokens import hash_token
from app.core.security.pkce import verify_pkce
from app.oauth.helpers import issue_tokens, oauth_error
from app.audit.service import write_event


def handle(
    db: Session,
    client: OAuthClient,
    code: str,
    redirect_uri: str,
    code_verifier: str | None,
    request: Request
):
    if "authorization_code" not in (client.grant_types or []):
        oauth_error("unauthorized_client")

    code_hash = hash_token(code)
    ac = db.scalar(
        select(AuthCode).where(AuthCode.code_hash == code_hash)
    )

    if not ac:
        oauth_error("invalid_grant", "Unknown code")

    if ac.used_at is not None:
        write_event(
            db, "auth_code.reuse_detected",
            client_id=ac.client_id,
            actor_id=ac.user_id,
            ip=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            metadata={"code_hash": code_hash}
        )
        oauth_error("invalid_grant", "Code already used")

    if ac.expires_at < datetime.now(timezone.utc):
        oauth_error("invalid_grant", "Code expired")

    if ac.client_id != client.client_id:
        oauth_error("invalid_grant", "Code not for this client")

    if ac.redirect_uri != redirect_uri:
        oauth_error("invalid_grant", "redirect_uri mismatch")

    # PKCE
    if ac.code_challenge:
        if not code_verifier or not verify_pkce(
            code_verifier,
            ac.code_challenge,
            ac.code_challenge_method or "S256"
        ):
            oauth_error("invalid_grant", "PKCE verification failed")
    elif settings.pkce_required_for_public and not client.hashed_secret:
        oauth_error("invalid_grant", "PKCE required")

    user = db.get(User, ac.user_id)
    if not user or not user.is_active:
        oauth_error("invalid_grant", "User inactive")

    ac.used_at = datetime.now(timezone.utc)

    return issue_tokens(
        db, user, client, ac.scope,
        grant_type="authorization_code",
        nonce=ac.nonce,
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent")
    )