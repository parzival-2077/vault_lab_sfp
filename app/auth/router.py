from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, EmailStr
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.models import User
from app.core.passwords import (
    validate_policy,
    hash_password,
    verify_password,
    WeakPasswordError
)
from app.core.jwt import create_access_token
from app.core.deps import get_current_user
from app.audit.service import write_event


router = APIRouter(prefix="/auth", tags=["Auth"])


class Credentials(BaseModel):
    email: EmailStr
    password: str


@router.post("/register")
def register(
    data: Credentials,
    request: Request,
    db: Session = Depends(get_db)
):
    email = str(data.email).lower()

    existing = db.scalar(select(User).where(User.email == email))
    if existing:
        raise HTTPException(400, "Email already registered")

    try:
        validate_policy(data.password, [email])
    except WeakPasswordError as e:
        raise HTTPException(400, str(e))

    user = User(
        email=email,
        hashed_password=hash_password(data.password)
    )

    db.add(user)
    db.flush()

    write_event(
        db,
        "user.created",
        actor_id=user.id,
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        commit=False
    )
    db.commit()

    return {
        "access_token": create_access_token(user.id),
        "token_type": "bearer"
    }


@router.post("/login")
def login(
    data: Credentials,
    request: Request,
    db: Session = Depends(get_db)
):
    email = str(data.email).lower()

    user = db.scalar(select(User).where(User.email == email))

    if not user or not user.is_active or not verify_password(
        data.password, user.hashed_password
    ):
        write_event(
            db,
            "user.login.failure",
            ip=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            metadata={"email": email}
        )
        raise HTTPException(401, "Invalid credentials")

    write_event(
        db,
        "user.login.success",
        actor_id=user.id,
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent")
    )

    return {
        "access_token": create_access_token(user.id),
        "token_type": "bearer"
    }


@router.get("/me")
def me(user=Depends(get_current_user)):
    return {
        "id": user.id,
        "email": user.email,
        "is_admin": user.is_admin
    }