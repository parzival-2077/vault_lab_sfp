import json
import secrets
from datetime import datetime, timezone
from uuid import uuid4

from ariadne import (
    QueryType,
    MutationType,
    ObjectType,
    convert_kwargs_to_snake_case
)
from graphql import GraphQLError
from pydantic import EmailStr, TypeAdapter
from sqlalchemy import select, update

from app.models.models import (
    User,
    OAuthClient,
    AuditEvent,
    UserSession,
    RefreshToken
)
from app.core.passwords import (
    validate_policy,
    hash_password,
    WeakPasswordError
)
from app.core.jwt import create_access_token
from app.audit.service import write_event


query = QueryType()
mutation = MutationType()

user_type = ObjectType("User")
client_type = ObjectType("Client")
audit_type = ObjectType("AuditEvent")
session_type = ObjectType("Session")
refresh_info_type = ObjectType("RefreshTokenInfo")
secret_payload_type = ObjectType("ClientSecretPayload")


# ============================================================
# User
# ============================================================

@user_type.field("isActive")
def user_active(obj, info):
    return obj.is_active


@user_type.field("isAdmin")
def user_admin(obj, info):
    return obj.is_admin


@user_type.field("createdAt")
def user_created(obj, info):
    return obj.created_at.isoformat()


# ============================================================
# Client
# ============================================================

@client_type.field("clientId")
def client_id(obj, info):
    return obj.client_id


@client_type.field("isConfidential")
def client_confidential(obj, info):
    return obj.is_confidential


@client_type.field("redirectUris")
def client_redirects(obj, info):
    return obj.redirect_uris


@client_type.field("createdAt")
def client_created(obj, info):
    return obj.created_at.isoformat()


@client_type.field("scopes")
def client_scopes(obj, info):
    return obj.scopes or []


@client_type.field("grantTypes")
def client_grant_types(obj, info):
    return obj.grant_types or []


@client_type.field("isActive")
def client_is_active(obj, info):
    return obj.is_active


@client_type.field("updatedAt")
def client_updated(obj, info):
    return obj.updated_at.isoformat() if obj.updated_at else None


@client_type.field("clientSecret")
def client_secret(obj, info):
    # Одноразовый показ — заполняется только при создании/ротации
    return getattr(obj, "_plain_secret", None)


# ============================================================
# AuditEvent
# ============================================================

@audit_type.field("eventType")
def audit_event_type(obj, info):
    return obj.event_type


@audit_type.field("actorId")
def audit_actor(obj, info):
    return obj.actor_id


@audit_type.field("clientId")
def audit_client_id(obj, info):
    return obj.client_id


@audit_type.field("userAgent")
def audit_agent(obj, info):
    return obj.user_agent


@audit_type.field("metadata")
def audit_metadata(obj, info):
    return json.dumps(obj.metadata_json, ensure_ascii=False)


@audit_type.field("createdAt")
def audit_created(obj, info):
    return obj.created_at.isoformat()


# ============================================================
# Session
# ============================================================

@session_type.field("clientId")
def session_client(obj, info):
    return obj.client_id


@session_type.field("userId")
def session_user(obj, info):
    return obj.user_id


@session_type.field("familyId")
def session_family(obj, info):
    return obj.family_id


@session_type.field("ip")
def session_ip(obj, info):
    return obj.ip


@session_type.field("userAgent")
def session_ua(obj, info):
    return obj.user_agent


@session_type.field("createdAt")
def session_created(obj, info):
    return obj.created_at.isoformat()


@session_type.field("lastSeenAt")
def session_seen(obj, info):
    return obj.last_seen_at.isoformat()


@session_type.field("revokedAt")
def session_revoked(obj, info):
    return obj.revoked_at.isoformat() if obj.revoked_at else None


# ============================================================
# RefreshTokenInfo
# ============================================================

@refresh_info_type.field("familyId")
def rt_family(obj, info):
    return obj.family_id


@refresh_info_type.field("clientId")
def rt_client(obj, info):
    return obj.client_id


@refresh_info_type.field("scope")
def rt_scope(obj, info):
    return obj.scope


@refresh_info_type.field("expiresAt")
def rt_expires(obj, info):
    return obj.expires_at.isoformat()


@refresh_info_type.field("usedAt")
def rt_used(obj, info):
    return obj.used_at.isoformat() if obj.used_at else None


@refresh_info_type.field("revokedAt")
def rt_revoked(obj, info):
    return obj.revoked_at.isoformat() if obj.revoked_at else None


@refresh_info_type.field("createdAt")
def rt_created(obj, info):
    return obj.created_at.isoformat()


# ============================================================
# ClientSecretPayload
# ============================================================

@secret_payload_type.field("clientId")
def sp_client_id(obj, info):
    return obj["client_id"]


@secret_payload_type.field("clientSecret")
def sp_client_secret(obj, info):
    return obj["client_secret"]


# ============================================================
# Queries
# ============================================================

@query.field("me")
def resolve_me(obj, info):
    return info.context["user"]


@query.field("users")
def resolve_users(obj, info, search=None, limit=20, offset=0):
    db = info.context["db"]

    stmt = select(User)

    if search:
        stmt = stmt.where(User.email.ilike(f"%{search}%"))

    return db.scalars(
        stmt.order_by(User.id)
        .offset(max(offset, 0))
        .limit(max(0, min(limit, 100)))
    ).all()


@query.field("clients")
def resolve_clients(obj, info):
    db = info.context["db"]
    return db.scalars(select(OAuthClient)).all()


@query.field("auditEvents")
@convert_kwargs_to_snake_case
def resolve_audit(obj, info, event_type=None, limit=20, offset=0):
    db = info.context["db"]

    stmt = select(AuditEvent)

    if event_type:
        stmt = stmt.where(AuditEvent.event_type == event_type)

    return db.scalars(
        stmt.order_by(AuditEvent.created_at.desc())
        .offset(max(offset, 0))
        .limit(max(0, min(limit, 100)))
    ).all()


@query.field("sessions")
@convert_kwargs_to_snake_case
def resolve_sessions(obj, info, user_id=None, active_only=False):
    db = info.context["db"]

    stmt = select(UserSession)

    if user_id is not None:
        stmt = stmt.where(UserSession.user_id == int(user_id))

    if active_only:
        stmt = stmt.where(UserSession.revoked_at.is_(None))

    return db.scalars(
        stmt.order_by(UserSession.created_at.desc())
    ).all()


@query.field("refreshTokens")
@convert_kwargs_to_snake_case
def resolve_refresh_tokens(obj, info, user_id=None, family_id=None):
    db = info.context["db"]

    stmt = select(RefreshToken)

    if user_id is not None:
        stmt = stmt.where(RefreshToken.user_id == int(user_id))

    if family_id:
        stmt = stmt.where(RefreshToken.family_id == family_id)

    return db.scalars(
        stmt.order_by(RefreshToken.created_at.desc())
    ).all()


# ============================================================
# Mutations: users
# ============================================================

@mutation.field("registerUser")
def register_user(obj, info, email, password):
    db = info.context["db"]

    try:
        email = str(TypeAdapter(EmailStr).validate_python(email)).lower()
    except ValueError:
        raise GraphQLError("Invalid email")

    if db.scalar(select(User).where(User.email == email)):
        raise GraphQLError("Email already registered")

    try:
        validate_policy(password, [email])
    except WeakPasswordError as e:
        raise GraphQLError(str(e))

    user = User(
        email=email,
        hashed_password=hash_password(password)
    )

    try:
        db.add(user)
        db.flush()

        write_event(
            db, "user.created",
            actor_id=user.id,
            commit=False
        )
        db.commit()
    except Exception:
        db.rollback()
        raise

    return {
        "accessToken": create_access_token(user.id),
        "tokenType": "bearer"
    }


@mutation.field("disableUser")
@convert_kwargs_to_snake_case
def disable_user(obj, info, user_id):
    db = info.context["db"]

    user = db.get(User, int(user_id))

    if not user:
        raise GraphQLError("User not found")

    if user.is_active:
        try:
            user.is_active = False

            write_event(
                db,
                "user.disabled",
                actor_id=info.context["user"].id,
                metadata={"user_id": user.id},
                commit=False
            )

            db.commit()
        except Exception:
            db.rollback()
            raise

    db.refresh(user)
    return user


# ============================================================
# Mutations: clients
# ============================================================

@mutation.field("createClient")
@convert_kwargs_to_snake_case
def create_client(
    obj,
    info,
    name,
    is_confidential,
    scopes=None,
    grant_types=None,
    redirect_uris=None
):
    db = info.context["db"]

    plain_secret = None
    hashed_secret = None

    if is_confidential:
        plain_secret = secrets.token_urlsafe(48)
        hashed_secret = hash_password(plain_secret)

    client = OAuthClient(
        client_id=str(uuid4()),
        name=name,
        is_confidential=is_confidential,
        hashed_secret=hashed_secret,
        scopes=scopes or ["openid", "profile", "email"],
        grant_types=grant_types or [
            "authorization_code",
            "refresh_token"
        ],
        redirect_uris=redirect_uris or [],
        is_active=True
    )

    try:
        db.add(client)
        db.flush()

        write_event(
            db,
            "client.created",
            actor_id=info.context["user"].id,
            client_id=client.client_id,
            metadata={
                "is_confidential": is_confidential,
                "scopes": client.scopes,
                "grant_types": client.grant_types
            },
            commit=False
        )

        db.commit()
    except Exception:
        db.rollback()
        raise

    db.refresh(client)

    # Одноразовый показ секрета (только для конфиденциального клиента)
    client._plain_secret = plain_secret

    return client


@mutation.field("rotateClientSecret")
@convert_kwargs_to_snake_case
def rotate_client_secret(obj, info, client_id):
    db = info.context["db"]

    client = db.scalar(
        select(OAuthClient).where(OAuthClient.client_id == client_id)
    )

    if not client:
        raise GraphQLError("Client not found")

    if not client.is_confidential:
        raise GraphQLError("Only confidential clients have a secret")

    new_secret = secrets.token_urlsafe(48)
    client.hashed_secret = hash_password(new_secret)
    client.updated_at = datetime.now(timezone.utc)

    try:
        write_event(
            db,
            "client.secret_rotated",
            actor_id=info.context["user"].id,
            client_id=client.client_id,
            commit=False
        )
        db.commit()
    except Exception:
        db.rollback()
        raise

    return {
        "client_id": client.client_id,
        "client_secret": new_secret
    }


@mutation.field("enableClient")
@convert_kwargs_to_snake_case
def enable_client(obj, info, client_id):
    return _set_client_active(info, client_id, True, "client.enabled")


@mutation.field("disableClient")
@convert_kwargs_to_snake_case
def disable_client(obj, info, client_id):
    return _set_client_active(info, client_id, False, "client.disabled")


def _set_client_active(info, client_id, value, event_type):
    db = info.context["db"]

    client = db.scalar(
        select(OAuthClient).where(OAuthClient.client_id == client_id)
    )

    if not client:
        raise GraphQLError("Client not found")

    if client.is_active == value:
        return client

    try:
        client.is_active = value
        client.updated_at = datetime.now(timezone.utc)

        write_event(
            db,
            event_type,
            actor_id=info.context["user"].id,
            client_id=client.client_id,
            commit=False
        )

        db.commit()
    except Exception:
        db.rollback()
        raise

    db.refresh(client)
    return client


# ============================================================
# Mutations: sessions / refresh tokens
# ============================================================

@mutation.field("revokeUserSessions")
@convert_kwargs_to_snake_case
def revoke_user_sessions(obj, info, user_id):
    db = info.context["db"]
    uid = int(user_id)

    user = db.get(User, uid)
    if not user:
        raise GraphQLError("User not found")

    now = datetime.now(timezone.utc)

    try:
        # Отзываем все активные refresh-токены пользователя
        rt_count = db.execute(
            update(RefreshToken)
            .where(
                RefreshToken.user_id == uid,
                RefreshToken.revoked_at.is_(None)
            )
            .values(revoked_at=now)
        ).rowcount

        # Отзываем все активные сессии
        sess_count = db.execute(
            update(UserSession)
            .where(
                UserSession.user_id == uid,
                UserSession.revoked_at.is_(None)
            )
            .values(revoked_at=now)
        ).rowcount

        write_event(
            db,
            "session.revoked",
            actor_id=info.context["user"].id,
            metadata={
                "user_id": uid,
                "sessions": sess_count,
                "refresh_tokens": rt_count
            },
            commit=False
        )

        db.commit()
    except Exception:
        db.rollback()
        raise

    # Возвращаем количество отозванных сессий
    return sess_count