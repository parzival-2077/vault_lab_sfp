from sqlalchemy import select

from app.db.session import SessionLocal
from app.models.models import AuditEvent, RefreshToken


def _setup(client):
    client.post("/auth/register", json={
        "email": "u@example.com", "password": "M7!vQ2#rL9@xT4"
    })
    login = client.post("/auth/login", json={
        "email": "u@example.com", "password": "M7!vQ2#rL9@xT4"
    }).json()
    token = login["access_token"]

    with SessionLocal() as db:
        from app.models.models import User
        u = db.scalar(select(User).where(User.email == "u@example.com"))
        u.is_admin = True
        db.commit()

    r = client.post(
        "/graphql/",
        json={"query": '''
            mutation {
              createClient(
                name: "rp", isConfidential: false,
                scopes: ["openid"],
                grantTypes: ["password","refresh_token"],
                redirectUris: []
              ) { clientId }
            }
        '''},
        headers={"Authorization": f"Bearer {token}"}
    )
    return token, r.json()["data"]["createClient"]["clientId"]


def test_refresh_rotation_and_reuse(client):
    admin_token, client_id = _setup(client)

    r = client.post("/oauth/token", data={
        "grant_type": "password",
        "client_id": client_id,
        "username": "u@example.com",
        "password": "M7!vQ2#rL9@xT4",
        "scope": "openid",
    })
    assert r.status_code == 200
    rt1 = r.json()["refresh_token"]

    r2 = client.post("/oauth/token", data={
        "grant_type": "refresh_token",
        "client_id": client_id,
        "refresh_token": rt1,
    })
    assert r2.status_code == 200
    rt2 = r2.json()["refresh_token"]
    assert rt2 != rt1

    # Повторное использование rt1 → reuse
    r3 = client.post("/oauth/token", data={
        "grant_type": "refresh_token",
        "client_id": client_id,
        "refresh_token": rt1,
    })
    assert r3.status_code == 400
    assert r3.json()["detail"]["error"] == "invalid_grant"

    # Всё семейство отозвано
    with SessionLocal() as db:
        family = db.scalar(
            select(RefreshToken).where(
                RefreshToken.token_hash == __import__("hashlib").sha256(
                    rt2.encode()
                ).hexdigest()
            )
        ).family_id
        tokens = db.scalars(
            select(RefreshToken).where(RefreshToken.family_id == family)
        ).all()
        assert all(t.revoked_at is not None for t in tokens)

        ev = db.scalar(
            select(AuditEvent).where(
                AuditEvent.event_type == "token.reuse_detected"
            )
        )
        assert ev is not None