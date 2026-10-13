from fastapi import Depends, HTTPException, Header
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.db.session import get_db
from app.models.models import User
from app.core.jwt import decode_token


def get_current_user(
    authorization: str | None = Header(None),
    db: Session = Depends(get_db)
):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Authentication required")

    token = authorization.split(" ", 1)[1]

    try:
        data = decode_token(token)
    except ValueError:
        raise HTTPException(401, "Invalid token")

    user = db.scalar(
        select(User).where(User.email == data["sub"])
    )

    if not user or not user.is_active:
        raise HTTPException(401, "Invalid user")

    return user


def require_admin(user=Depends(get_current_user)):
    if not user.is_admin:
        raise HTTPException(403, "Admin only")

    return user