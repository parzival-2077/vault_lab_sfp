from fastapi import Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.models import User, OAuthClient
from app.core.passwords import verify_password
from app.oauth.helpers import issue_tokens, oauth_error
from app.audit.service import write_event


def handle(
    db: Session,
    client: OAuthClient,
    username: str,
    password: str,
    scope: str,
    request: Request
):
    if "password" not in (client.grant_types or []):
        oauth_error("unauthorized_client")

    user = db.scalar(select(User).where(User.email == username.lower()))
    if not user or not user.is_active or not verify_password(
        password, user.hashed_password
    ):
        write_event(
            db, "user.login.failure",
            ip=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            metadata={"email": username}
        )
        oauth_error("invalid_grant", "Invalid credentials")

    allowed = set(client.scopes or [])
    requested = [s for s in scope.split() if s]
    if requested and not set(requested).issubset(allowed):
        oauth_error("invalid_scope")

    final_scope = scope or " ".join(client.scopes or [])

    return issue_tokens(
        db, user, client, final_scope,
        grant_type="password",
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent")
    )