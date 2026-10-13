from sqlalchemy import select

from app.db.session import SessionLocal
from app.models.models import AuditEvent


EMAIL = "student@example.com"
PASSWORD = "M7!vQ2#rL9@xT4"


def test_register_login_me(client):
    response = client.post("/auth/register", json={
        "email": EMAIL,
        "password": PASSWORD
    })

    assert response.status_code == 200

    response = client.post("/auth/login", json={
        "email": EMAIL,
        "password": PASSWORD
    })

    assert response.status_code == 200

    token = response.json()["access_token"]

    response = client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 200
    assert response.json()["email"] == EMAIL

    with SessionLocal() as db:
        event = db.scalar(
            select(AuditEvent).where(
                AuditEvent.event_type == "user.login.success"
            )
        )
        assert event is not None


def test_wrong_password(client):
    client.post("/auth/register", json={
        "email": EMAIL,
        "password": PASSWORD
    })

    response = client.post("/auth/login", json={
        "email": EMAIL,
        "password": "wrong"
    })

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials"


def test_me_without_token(client):
    response = client.get("/auth/me")

    assert response.status_code == 401


def test_weak_registration(client):
    response = client.post("/auth/register", json={
        "email": EMAIL,
        "password": "123456"
    })

    assert response.status_code == 400