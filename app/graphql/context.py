from sqlalchemy import select

from app.models.models import User
from app.core.security.jwt_rsa import verify_token
from app.redis_client import is_blacklisted


async def get_context_value(request, data):
    db = request.state.db
    user = None

    authorization = request.headers.get("Authorization", "")

    if authorization.startswith("Bearer "):
        token = authorization.split(" ", 1)[1]

        try:
            payload = verify_token(token)
            if not is_blacklisted(payload.get("jti", "")):
                user = db.scalar(
                    select(User).where(
                        User.id == int(payload["sub"]),
                        User.is_active.is_(True)
                    )
                )
        except (ValueError, KeyError):
            pass

    return {
        "request": request,
        "db": db,
        "user": user
    }