from fastapi.testclient import TestClient
from app.main import app

def test_jwks():
    c = TestClient(app)
    r = c.get("/.well-known/jwks.json")
    assert r.status_code == 200
    keys = r.json()["keys"]
    assert keys and keys[0]["kty"] == "RSA"
    assert keys[0]["alg"] == "RS256"
    assert keys[0]["use"] == "sig"
    assert "kid" in keys[0]