import base64
import hashlib
import secrets

from sqlalchemy import select

from app.db.session import SessionLocal
from app.models.models import AuditEvent


def _challenge(verifier: str) -> str:
    return base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()


def _make_user_and_client(client, admin=False):
    client.post("/auth/register", json={
        "email": "u@example.com", "password": "M7!vQ2#rL9@xT4"
    })
    login = client.post("/auth/login", json={
        "email": "u@example.com", "password": "M7!vQ2#rL9@xT4"
    }).json()
    token = login["access_token"]

    from app.db.session import SessionLocal
    from app.models.models import User
    from sqlalchemy import select
    with SessionLocal() as db:
        u = db.scalar(select(User).where(User.email == "u@example.com"))
        u.is_admin = True
        db.commit()

    return token


def _create_client(client, token, name="rp"):
    r = client.post(
        "/graphql/",
        json={"query": f'''
            mutation {{
              createClient(
                name: "{name}",
                isConfidential: false,
                scopes: ["openid","profile","email"],
                grantTypes: ["authorization_code","refresh_token"],
                redirectUris: ["http://localhost/cb"]
              ) {{ clientId }}
            }}
        '''},
        headers={"Authorization": f"Bearer {token}"}
    )
    return r.json()["data"]["createClient"]["clientId"]


def test_code_single_use(client):
    admin_token = _make_user_and_client(client)
    client_id = _create_client(client, admin_token)

    # Получить код через /oauth/authorize
    verifier = secrets.token_urlsafe(64)
    r = client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": "http://localhost/cb",
            "scope": "openid",
            "state": "xyz",
            "code_challenge": _challenge(verifier),
            "code_challenge_method": "S256",
        },
        headers={"Authorization": f"Bearer {admin_token}"},
        follow_redirects=False,
    )
    assert r.status_code == 302
    loc = r.headers["location"]
    code = loc.split("code=")[1].split("&")[0]

    # Первый обмен — успех
    r = client.post("/oauth/token", data={
        "grant_type": "authorization_code",
        "client_id": client_id,
        "code": code,
        "redirect_uri": "http://localhost/cb",
        "code_verifier": verifier,
    })
    assert r.status_code == 200
    assert "access_token" in r.json()

    # Повторный обмен — invalid_grant + аудит
    r = client.post("/oauth/token", data={
        "grant_type": "authorization_code",
        "client_id": client_id,
        "code": code,
        "redirect_uri": "http://localhost/cb",
        "code_verifier": verifier,
    })
    assert r.status_code == 400
    assert r.json()["detail"]["error"] == "invalid_grant"

    with SessionLocal() as db:
        ev = db.scalar(
            select(AuditEvent).where(
                AuditEvent.event_type == "auth_code.reuse_detected"
            )
        )
        assert ev is not None