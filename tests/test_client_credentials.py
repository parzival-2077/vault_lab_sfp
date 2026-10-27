from sqlalchemy import select

from app.db.session import SessionLocal
from app.models.models import User


def _admin_token(client):
    client.post("/auth/register", json={
        "email": "a@example.com", "password": "M7!vQ2#rL9@xT4"
    })
    with SessionLocal() as db:
        u = db.scalar(select(User).where(User.email == "a@example.com"))
        u.is_admin = True
        db.commit()
    return client.post("/auth/login", json={
        "email": "a@example.com", "password": "M7!vQ2#rL9@xT4"
    }).json()["access_token"]


def test_confidential_cc(client):
    admin = _admin_token(client)

    r = client.post(
        "/graphql/",
        json={"query": '''
            mutation {
              createClient(
                name: "svc", isConfidential: true,
                scopes: ["openid"],
                grantTypes: ["client_credentials"]
              ) { clientId clientSecret }
            }
        '''},
        headers={"Authorization": f"Bearer {admin}"}
    )
    data = r.json()["data"]["createClient"]
    cid, csec = data["clientId"], data["clientSecret"]

    r = client.post("/oauth/token", data={
        "grant_type": "client_credentials",
        "client_id": cid,
        "client_secret": csec,
        "scope": "openid",
    })
    assert r.status_code == 200
    assert "refresh_token" not in r.json()

    # sub должен быть == client_id
    from app.core.security.jwt_rsa import verify_token
    payload = verify_token(r.json()["access_token"])
    assert payload["sub"] == cid


def test_public_cc_forbidden(client):
    admin = _admin_token(client)
    r = client.post(
        "/graphql/",
        json={"query": '''
            mutation {
              createClient(
                name: "pub", isConfidential: false,
                scopes: ["openid"],
                grantTypes: ["client_credentials"]
              ) { clientId }
            }
        '''},
        headers={"Authorization": f"Bearer {admin}"}
    )
    cid = r.json()["data"]["createClient"]["clientId"]

    r = client.post("/oauth/token", data={
        "grant_type": "client_credentials",
        "client_id": cid,
    })
    assert r.status_code == 400
    assert r.json()["detail"]["error"] == "unauthorized_client"