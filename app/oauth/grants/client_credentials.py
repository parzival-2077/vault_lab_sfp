from fastapi import Request
from sqlalchemy.orm import Session

from app.models.models import OAuthClient
from app.core.security.jwt_rsa import sign_access_token
from app.config import settings
from app.audit.service import write_event
from app.oauth.helpers import oauth_error


def handle(
    db: Session,
    client: OAuthClient,
    scope: str,
    request: Request
):
    if not client.hashed_secret:
        oauth_error("unauthorized_client", "Public clients cannot use client_credentials")

    if "client_credentials" not in (client.grant_types or []):
        oauth_error("unauthorized_client")

    allowed = set(client.scopes or [])
    requested = [s for s in scope.split() if s]
    if requested and not set(requested).issubset(allowed):
        oauth_error("invalid_scope")

    final_scope = scope or " ".join(client.scopes or [])
    scopes = [s for s in final_scope.split() if s]

    access = sign_access_token(
        sub=client.client_id,
        client_id=client.client_id,
        scopes=scopes
    )

    write_event(
        db, "token.issued",
        client_id=client.client_id,
        ip=request.client.host if request.client else None,
        metadata={"grant_type": "client_credentials", "scope": final_scope}
    )

    return {
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": settings.access_token_ttl_sec,
        "scope": final_scope
    }