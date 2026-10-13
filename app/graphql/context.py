from sqlalchemy import select

from app.models.models import User
from app.core.jwt import decode_token


async def get_context_value(request, data):
    db = request.state.db
    user = None

    authorization = request.headers.get("Authorization", "")

    if authorization.startswith("Bearer "):
        token = authorization.split(" ", 1)[1]

        try:
            payload = decode_token(token)

            user = db.scalar(
                select(User).where(
                    User.email == payload["sub"],
                    User.is_active.is_(True)
                )
            )
        except ValueError:
            pass

    return {
        "request": request,
        "db": db,
        "user": user
    }