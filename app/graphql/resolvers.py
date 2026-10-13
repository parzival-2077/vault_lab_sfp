import json
from uuid import uuid4

from ariadne import (
    QueryType,
    MutationType,
    ObjectType,
    convert_kwargs_to_snake_case
)
from graphql import GraphQLError
from pydantic import EmailStr, TypeAdapter
from sqlalchemy import select

from app.models.models import User, OAuthClient, AuditEvent
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


# Преобразование полей Python в GraphQL
@user_type.field("isActive")
def user_active(obj, info):
    return obj.is_active


@user_type.field("isAdmin")
def user_admin(obj, info):
    return obj.is_admin


@user_type.field("createdAt")
def user_created(obj, info):
    return obj.created_at.isoformat()


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


@audit_type.field("eventType")
def audit_event_type(obj, info):
    return obj.event_type


@audit_type.field("actorId")
def audit_actor(obj, info):
    return obj.actor_id


@audit_type.field("userAgent")
def audit_agent(obj, info):
    return obj.user_agent


@audit_type.field("metadata")
def audit_metadata(obj, info):
    return json.dumps(obj.metadata_json, ensure_ascii=False)


@audit_type.field("createdAt")
def audit_created(obj, info):
    return obj.created_at.isoformat()


# GraphQL-запросы
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


# GraphQL-мутации
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
        "accessToken": create_access_token(email),
        "tokenType": "bearer"
    }


@mutation.field("createClient")
@convert_kwargs_to_snake_case
def create_client(obj, info, name, is_confidential):
    db = info.context["db"]

    client = OAuthClient(
        client_id=str(uuid4()),
        name=name,
        is_confidential=is_confidential,
        redirect_uris=[]
    )

    try:
        db.add(client)
        db.flush()

        write_event(
            db,
            "client.created",
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