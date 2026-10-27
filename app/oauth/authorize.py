import secrets
from datetime import datetime, timezone, timedelta
from urllib.parse import urlencode, urlparse, urlunparse, parse_qsl

from fastapi import APIRouter, Request, Depends, Header
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.db.session import get_db
from app.models.models import OAuthClient, AuthCode, User
from app.core.security.tokens import hash_token
from app.core.security.jwt_rsa import verify_token
from app.redis_client import is_blacklisted
from app.audit.service import write_event


router = APIRouter(tags=["OAuth2 / Authorize"])


def _redirect(uri: str, **params) -> RedirectResponse:
    parts = urlparse(uri)
    existing = dict(parse_qsl(parts.query))
    existing.update({k: v for k, v in params.items() if v is not None})
    new_query = urlencode(existing)
    new_uri = urlunparse(parts._replace(query=new_query))
    return RedirectResponse(new_uri, status_code=302)


def _error_redirect(uri, error, state, desc=None):
    return _redirect(uri, error=error, state=state, error_description=desc)


def _audit_failure(db, request, client_id, redirect_uri, reason, state=None):
    write_event(
        db, "oauth.authorize.failure",
        client_id=client_id,
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        metadata={
            "reason": reason,
            "redirect_uri": redirect_uri,
            "state": state,
        }
    )


@router.get("/oauth/authorize")
def authorize(
    request: Request,
    response_type: str,
    client_id: str,
    redirect_uri: str,
    scope: str = "",
    state: str | None = None,
    code_challenge: str | None = None,
    code_challenge_method: str | None = None,
    nonce: str | None = None,
    db: Session = Depends(get_db),
    authorization: str | None = Header(None)
):
    # state обязателен (CSRF)
    if not state:
        return _error_redirect(
            redirect_uri, "invalid_request", None, "state is required"
        )

    client = db.scalar(
        select(OAuthClient).where(OAuthClient.client_id == client_id)
    )

    if not client or not client.is_active:
        _audit_failure(db, request, client_id, redirect_uri, "invalid_client", state)
        return _error_redirect(redirect_uri, "invalid_client", state)

    if redirect_uri not in (client.redirect_uris or []):
        _audit_failure(db, request, client_id, redirect_uri, "redirect_uri_mismatch", state)
        return _error_redirect(
            redirect_uri, "invalid_request", state, "redirect_uri mismatch"
        )

    if response_type != "code":
        _audit_failure(db, request, client_id, redirect_uri, "unsupported_response_type", state)
        return _error_redirect(redirect_uri, "unsupported_response_type", state)

    # PKCE для публичных
    if not client.hashed_secret and settings.pkce_required_for_public:
        if not code_challenge or code_challenge_method != "S256":
            _audit_failure(db, request, client_id, redirect_uri, "pkce_required", state)
            return _error_redirect(
                redirect_uri, "invalid_request", state, "PKCE required"
            )

    # scope
    requested = [s for s in scope.split() if s]
    if requested and not set(requested).issubset(set(client.scopes or [])):
        _audit_failure(db, request, client_id, redirect_uri, "invalid_scope", state)
        return _error_redirect(redirect_uri, "invalid_scope", state)

    # Аутентификация пользователя
    user = None
    if authorization and authorization.startswith("Bearer "):
        try:
            payload = verify_token(authorization.split(" ", 1)[1])
            if not is_blacklisted(payload.get("jti", "")):
                user = db.scalar(
                    select(User).where(
                        User.id == int(payload["sub"]),
                        User.is_active.is_(True)
                    )
                )
        except (ValueError, KeyError):
            pass

    if not user:
        _audit_failure(db, request, client_id, redirect_uri, "unauthenticated", state)
        return _error_redirect(
            redirect_uri, "access_denied", state, "Authentication required"
        )

    # Генерация кода
    code = secrets.token_urlsafe(48)
    code_hash = hash_token(code)

    db.add(AuthCode(
        code_hash=code_hash,
        client_id=client_id,
        user_id=user.id,
        redirect_uri=redirect_uri,
        scope=scope,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        nonce=nonce,
        expires_at=datetime.now(timezone.utc) + timedelta(
            seconds=settings.auth_code_ttl_sec
        )
    ))

    write_event(
        db, "oauth.authorize.success",
        actor_id=user.id,
        client_id=client_id,
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        metadata={"scope": scope, "redirect_uri": redirect_uri},
        commit=False
    )
    db.commit()

    return _redirect(redirect_uri, code=code, state=state)