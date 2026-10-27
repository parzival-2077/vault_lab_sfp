from datetime import datetime, timezone

from sqlalchemy import String, Boolean, ForeignKey, JSON, DateTime
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


def now():
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(
        String, unique=True, index=True
    )
    hashed_password: Mapped[str] = mapped_column(String)
    is_active: Mapped[bool] = mapped_column(
        Boolean, default=True
    )
    is_admin: Mapped[bool] = mapped_column(
        Boolean, default=False
    )
    created_at: Mapped[datetime] = mapped_column(default=now)


class OAuthClient(Base):
    __tablename__ = "oauth_clients"

    id: Mapped[int] = mapped_column(primary_key=True)
    client_id: Mapped[str] = mapped_column(
        String, unique=True
    )
    name: Mapped[str] = mapped_column(String)
    is_confidential: Mapped[bool] = mapped_column(
        Boolean, default=False
    )
    redirect_uris: Mapped[list] = mapped_column(
        JSON, default=list
    )
    created_at: Mapped[datetime] = mapped_column(default=now)

    # ---- Лаба №3: OAuth2-поля ----
    hashed_secret: Mapped[str | None] = mapped_column(
        String, nullable=True
    )
    scopes: Mapped[list] = mapped_column(JSON, default=list)
    grant_types: Mapped[list] = mapped_column(JSON, default=list)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    updated_at: Mapped[datetime] = mapped_column(
        default=now, onupdate=now
    )


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    event_type: Mapped[str] = mapped_column(
        String, index=True
    )
    actor_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )
    client_id: Mapped[str | None] = mapped_column(
        String, nullable=True
    )
    ip: Mapped[str | None] = mapped_column(
        String, nullable=True
    )
    user_agent: Mapped[str | None] = mapped_column(
        String, nullable=True
    )
    metadata_json: Mapped[dict] = mapped_column(
        JSON, default=dict
    )
    created_at: Mapped[datetime] = mapped_column(default=now)


# ============================================================
# Лаба №3: новые модели
# ============================================================

class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id: Mapped[int] = mapped_column(primary_key=True)
    jti: Mapped[str] = mapped_column(String, unique=True, index=True)
    family_id: Mapped[str] = mapped_column(String, index=True)
    token_hash: Mapped[str] = mapped_column(String, unique=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    client_id: Mapped[str] = mapped_column(String, index=True)
    scope: Mapped[str] = mapped_column(String, default="")
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    replaced_by_hash: Mapped[str | None] = mapped_column(
        String, nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(default=now)


class AuthCode(Base):
    __tablename__ = "auth_codes"

    id: Mapped[int] = mapped_column(primary_key=True)
    code_hash: Mapped[str] = mapped_column(String, unique=True, index=True)
    client_id: Mapped[str] = mapped_column(String, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    redirect_uri: Mapped[str] = mapped_column(String)
    scope: Mapped[str] = mapped_column(String, default="")
    code_challenge: Mapped[str | None] = mapped_column(
        String, nullable=True
    )
    code_challenge_method: Mapped[str | None] = mapped_column(
        String, nullable=True
    )
    nonce: Mapped[str | None] = mapped_column(String, nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(default=now)


class UserSession(Base):
    __tablename__ = "user_sessions"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    client_id: Mapped[str] = mapped_column(String)
    family_id: Mapped[str] = mapped_column(String, index=True)
    ip: Mapped[str | None] = mapped_column(String, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=now)
    last_seen_at: Mapped[datetime] = mapped_column(default=now)
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )