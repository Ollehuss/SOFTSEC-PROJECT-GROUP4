import re
import secrets
from urllib import response
import pytest
from server import app
import os
from itsdangerous import URLSafeTimedSerializer

def test_healthz_route():
    client = app.test_client()
    resp = client.get("/healthz")

    assert resp.status_code == 200
    assert resp.is_json
    

def test_delete_document_rejects_sql_injection():
    client = app.test_client()

    serializer = URLSafeTimedSerializer(
        os.environ["SECRET_KEY"],
        salt="tatou-auth",
    )
    token = serializer.dumps({
        "uid": 1,
        "login": "test-user",
        "email": "test@example.com",
    })

    resp = client.post(
        "/api/delete-document?id=1%20OR%201=1",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert resp.status_code == 400


def test_download_token_is_unpredictable():
    token1 = secrets.token_hex(32)
    token2 = secrets.token_hex(32)

    assert len(token1) == 64
    assert len(token2) == 64

    assert re.fullmatch(r"[0-9a-f]{64}", token1)
    assert re.fullmatch(r"[0-9a-f]{64}", token2)

    assert token1 != token2


def test_delete_document_requires_authentication():
    client = app.test_client()
    resp = client.post("/api/delete-document?id=1")
    assert resp.status_code == 401


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("post", "/api/upload-document"),
        ("get", "/api/list-documents"),
        ("get", "/api/get-document?id=1"),
        ("get", "/api/list-versions/1"),
        ("post", "/api/create-watermark/1"),
        ("post", "/api/read-watermark/1"),
    ],
)
def test_protected_endpoints_require_authentication(method, path):
    client = app.test_client()

    response = getattr(client, method)(path)

    assert response.status_code == 401, (
        f"{method.upper()} {path} returned "
        f"{response.status_code}; expected 401"
    )


import uuid


def unique_user():
    """Generate unique credentials so tests do not conflict."""
    suffix = uuid.uuid4().hex
    return {
        "email": f"test-{suffix}@example.com",
        "login": f"test-{suffix}",
        "password": "TestPassword123!",
    }



def test_create_user_success():
    client = app.test_client()
    user = unique_user()

    response = client.post("/api/create-user", json=user)

    print("Registration response:", response.status_code, response.get_json())

    assert response.status_code == 201
    data = response.get_json()
    assert data["email"] == user["email"]
    assert data["login"] == user["login"]
    assert "password" not in data
    assert "hpassword" not in data



def test_create_user_duplicate():
    client = app.test_client()
    user = unique_user()

    first_response = client.post("/api/create-user", json=user)
    assert first_response.status_code == 201

    second_response = client.post("/api/create-user", json=user)
    assert second_response.status_code == 409


def test_login_success():
    client = app.test_client()
    user = unique_user()

    registration = client.post("/api/create-user", json=user)
    assert registration.status_code == 201

    response = client.post(
        "/api/login",
        json={
            "email": user["email"],
            "password": user["password"],
        },
    )

    assert response.status_code == 200
    data = response.get_json()
    assert data["token"]
    assert data["token_type"] == "bearer"
    assert data["expires_in"] > 0


def test_login_wrong_password():
    client = app.test_client()
    user = unique_user()

    registration = client.post("/api/create-user", json=user)
    assert registration.status_code == 201

    response = client.post(
        "/api/login",
        json={
            "email": user["email"],
            "password": "WrongPassword123!",
        },
    )

    assert response.status_code == 401
    assert response.get_json()["error"] == "invalid credentials"
