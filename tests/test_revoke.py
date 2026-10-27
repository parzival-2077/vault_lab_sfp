from sqlalchemy import select

from app.db.session import SessionLocal
from app.models.models import User


def _setup(client):
    client.post("/auth/register", json={
        "email": "r@example.com", "password": "M7!vQ2#rL9@xT4"
    })
    with SessionLocal() as db:
        u = db.scalar(select(User).where(User.email == "r@example.com"))
        u.is_admin = True
        db.commit()
    tok = client.post("/auth/login", json={
        "email": "r@example.com", "password": "M7!vQ2#rL9@xT4"
    }).json()["access_token"]
    r = client.post(
        "/graphql/",
        json={"query": '''
            mutation {
              createClient(
                name: "r", isConfidential: true,
                scopes: ["openid","profile"],
                grantTypes: ["password","refresh_token"]
              ) { clientId clientSecret }
            }
        '''},
        headers={"Authorization": f"Bearer {tok}"}
    )
    return r.json()["data"]["createClient"]


def test_revoke_access(client):
    data = _setup(client)
    cid, csec = data["clientId"], data["clientSecret"]

    r = client.post("/oauth/token", data={
        "grant_type": "password", "client_id": cid,
        "client_secret": csec,
        "username": "r@example.com", "password": "M7!vQ2#rL9@xT4",
        "scope": "openid",
    })
    access = r.json()["access_token"]

    client.post("/oauth/revoke", data={"token": access,
                                       "token_type_hint": "access_token"})

    r = client.post("/oauth/introspect", data={
        "token": access, "client_id": cid, "client_secret": csec,
    })
    assert r.json() == {"active": False}