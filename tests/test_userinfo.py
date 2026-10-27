from sqlalchemy import select

from app.db.session import SessionLocal
from app.models.models import User


def _setup(client):
    client.post("/auth/register", json={
        "email": "u@example.com", "password": "M7!vQ2#rL9@xT4"
    })
    with SessionLocal() as db:
        u = db.scalar(select(User).where(User.email == "u@example.com"))
        u.is_admin = True
        db.commit()
    tok = client.post("/auth/login", json={
        "email": "u@example.com", "password": "M7!vQ2#rL9@xT4"
    }).json()["access_token"]
    r = client.post(
        "/graphql/",
        json={"query": '''
            mutation {
              createClient(
                name: "u", isConfidential: false,
                scopes: ["openid","profile","email"],
                grantTypes: ["password"]
              ) { clientId }
            }
        '''},
        headers={"Authorization": f"Bearer {tok}"}
    )
    return r.json()["data"]["createClient"]["clientId"]


def _get_access(client, cid, scope):
    return client.post("/oauth/token", data={
        "grant_type": "password", "client_id": cid,
        "username": "u@example.com", "password": "M7!vQ2#rL9@xT4",
        "scope": scope,
    }).json()["access_token"]


def test_userinfo_email(client):
    cid = _setup(client)
    access = _get_access(client, cid, "openid email")

    r = client.get("/oauth/userinfo",
                   headers={"Authorization": f"Bearer {access}"})
    assert r.status_code == 200
    body = r.json()
    assert body["sub"]
    assert "email" in body


def test_userinfo_no_extra_without_scope(client):
    cid = _setup(client)
    access = _get_access(client, cid, "openid")

    r = client.get("/oauth/userinfo",
                   headers={"Authorization": f"Bearer {access}"})
    body = r.json()
    assert "email" not in body
    assert "name" not in body