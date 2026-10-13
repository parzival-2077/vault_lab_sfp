from datetime import datetime, timezone

from sqlalchemy import String, Boolean, ForeignKey, JSON
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