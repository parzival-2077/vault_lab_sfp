import redis

from app.config import settings


redis_client = redis.from_url(
    settings.redis_url,
    decode_responses=True
)


def blacklist_jti(jti: str, ttl_sec: int) -> None:
    if ttl_sec <= 0:
        return
    redis_client.setex(f"revoked:{jti}", ttl_sec, "1")


def is_blacklisted(jti: str) -> bool:
    return redis_client.exists(f"revoked:{jti}") == 1


def store_auth_code(code_hash: str, payload: str, ttl_sec: int) -> None:
    redis_client.setex(f"authcode:{code_hash}", ttl_sec, payload)


def pop_auth_code(code_hash: str) -> str | None:
    key = f"authcode:{code_hash}"
    pipe = redis_client.pipeline()
    pipe.get(key)
    pipe.delete(key)
    value, _ = pipe.execute()
    return value