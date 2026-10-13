from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
from zxcvbn import zxcvbn

from app.config import settings


hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    type=__import__("argon2").Type.ID
)


class WeakPasswordError(ValueError):
    pass


def validate_policy(password, user_inputs=None):
    if len(password) < settings.password_min_length: # проверка длины
        raise WeakPasswordError("Password is too short")

    result = zxcvbn(password, user_inputs=user_inputs or []) #проверка сложности 

    if result["score"] < 3:
        raise WeakPasswordError("Password is too weak")


def hash_password(password): #хеширование пароля
    return hasher.hash(password + settings.password_pepper)


def verify_password(password, hashed): #проверка пароля при входе
    try:
        return hasher.verify(
            hashed,
            password + settings.password_pepper
        )
    except (VerifyMismatchError, VerificationError):
        return False