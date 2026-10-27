import os

os.environ["DATABASE_URL"] = "sqlite:///./test_vault.db"
os.environ.setdefault("PASSWORD_PEPPER", "test_pepper_for_local_tests_only")

import fakeredis
import pytest
from fastapi.testclient import TestClient

# Подменяем Redis ДО импорта приложения
import app.redis_client as redis_module
redis_module.redis_client = fakeredis.FakeRedis(decode_responses=True)

from app.main import app
from app.db.base import Base
from app.db.session import engine


@pytest.fixture(autouse=True)
def clean_database():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    redis_module.redis_client.flushall()
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client