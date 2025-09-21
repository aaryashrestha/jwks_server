#aarya shrestha
import sys, os
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from main import app, keystore
import pytest
from fastapi.testclient import TestClient
from main import app, keystore
from datetime import datetime, timezone

client = TestClient(app)


def test_jwks_contains_only_unexpired_keys():
    """Ensure JWKS endpoint only returns unexpired keys."""
    response = client.get("/jwks")
    assert response.status_code == 200
    data = response.json()
    assert "keys" in data

    now = datetime.now(timezone.utc)
    for jwk in data["keys"]:
        kid = jwk["kid"]
        matching = [k for k in keystore._keys if k.kid == kid]
        assert matching, f"Key {kid} not found in keystore"
        assert matching[0].expiry > now


def test_auth_returns_valid_jwt_by_default():
    """Test normal JWT issuance with unexpired key."""
    response = client.post("/auth", json={"sub": "alice"})
    assert response.status_code == 200
    body = response.json()

    token_exp = datetime.fromisoformat(body["token_exp_utc"])
    key_exp = datetime.fromisoformat(body["key_expiry_utc"])
    assert token_exp <= key_exp


def test_auth_with_expired_true_uses_expired_key():
    """Test issuing a token with an expired key."""
    response = client.post("/auth?expired=true", json={"sub": "bob"})
    assert response.status_code == 200
    body = response.json()

    token_exp = datetime.fromisoformat(body["token_exp_utc"])
    key_exp = datetime.fromisoformat(body["key_expiry_utc"])

    # Compare timestamps (ignore microseconds difference)
    assert int(token_exp.timestamp()) == int(key_exp.timestamp())


def test_auth_without_body_uses_defaults():
    """Test POST /auth with empty JSON (defaults applied)."""
    response = client.post("/auth", json={})
    assert response.status_code == 200
    body = response.json()
    assert "token" in body
    assert body["signed_with_kid"]


def test_auth_no_signing_key(monkeypatch):
    """Force keystore to return None -> should raise 404."""
    monkeypatch.setattr(keystore, "get_signing_key", lambda expired=False: None)

    response = client.post("/auth", json={})
    assert response.status_code == 404
    assert response.json()["detail"].startswith("No matching signing key")
