import os

os.environ["DATABASE_URL"] = "sqlite:///./test_vault.db"
os.environ.setdefault("JWT_SECRET", "test_secret_for_local_tests_only")
os.environ.setdefault("PASSWORD_PEPPER", "test_pepper_for_local_tests_only")

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.db.base import Base
from app.db.session import engine


@pytest.fixture(autouse=True)
def clean_database():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    yield

    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client