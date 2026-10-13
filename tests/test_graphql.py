from sqlalchemy import select

from app.db.session import SessionLocal
from app.models.models import User


EMAIL = "student@example.com"
PASSWORD = "M7!vQ2#rL9@xT4"


def test_users_without_token(client):
    response = client.post("/graphql/", json={
        "query": "{ users { id email } }"
    })

    assert "Authentication required" in str(response.json())


def test_users_without_admin(client):
    client.post("/auth/register", json={
        "email": EMAIL,
        "password": PASSWORD
    })

    response = client.post("/auth/login", json={
        "email": EMAIL,
        "password": PASSWORD
    })

    token = response.json()["access_token"]

    response = client.post(
        "/graphql/",
        json={"query": "{ users { id email } }"},
        headers={"Authorization": f"Bearer {token}"}
    )

    assert "Admin only" in str(response.json())


def test_users_with_admin(client):
    client.post("/auth/register", json={
        "email": EMAIL,
        "password": PASSWORD
    })

    with SessionLocal() as db:
        user = db.scalar(
            select(User).where(User.email == EMAIL)
        )
        user.is_admin = True
        db.commit()

    response = client.post("/auth/login", json={
        "email": EMAIL,
        "password": PASSWORD
    })

    token = response.json()["access_token"]

    response = client.post(
        "/graphql/",
        json={"query": "{ users { id email } }"},
        headers={"Authorization": f"Bearer {token}"}
    )

    assert response.json()["data"]["users"][0]["email"] == EMAIL