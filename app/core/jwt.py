from app.core.security.jwt_rsa import (
    sign_access_token,
    verify_token
)


LEGACY_CLIENT_ID = "vault-internal"


def create_access_token(sub, ttl_min=None):
    """
    Создаёт access-токен для внутренних (легаси) эндпоинтов /auth/*.

    sub — идентификатор пользователя (user.id).
    Токен подписывается RS256 с aud="vault-internal".
    """
    ttl_sec = None if ttl_min is None else ttl_min * 60

    return sign_access_token(
        sub=str(sub),
        client_id=LEGACY_CLIENT_ID,
        scopes=[],
        ttl_sec=ttl_sec
    )


def decode_token(token):
    """
    Проверяет access-токен, выданный через /auth/* (aud="vault-internal").

    Бросает ValueError при невалидной подписи, истёкшем сроке
    или неверной аудитории.
    """
    return verify_token(token, audience=LEGACY_CLIENT_ID)