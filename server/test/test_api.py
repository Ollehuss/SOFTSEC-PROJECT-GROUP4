import re
import secrets
from urllib import response
import pytest
from server import app
import os
from itsdangerous import URLSafeTimedSerializer
from types import SimpleNamespace
from unittest.mock import MagicMock

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


def test_delete_document_success(tmp_path, monkeypatch):
    pdf_file = tmp_path / "test.pdf"
    pdf_file.write_bytes(b"%PDF-1.4 test document")

    assert pdf_file.exists()

    document = SimpleNamespace(
        id=1,
        path=str(pdf_file),
    )

    mock_conn = MagicMock()
    mock_conn.execute.return_value.first.return_value = document

    mock_engine = MagicMock()
    mock_engine.connect.return_value.__enter__.return_value = mock_conn
    mock_engine.begin.return_value.__enter__.return_value = mock_conn

    monkeypatch.setitem(app.config, "_ENGINE", mock_engine)

    monkeypatch.setitem(app.config, "STORAGE_DIR", tmp_path)

    serializer = URLSafeTimedSerializer(
        app.config["SECRET_KEY"],
        salt="tatou-auth",
    )

    token = serializer.dumps({
        "uid": 1,
        "login": "test-user",
        "email": "test@example.com",
    })

    client = app.test_client()
    response = client.delete(
        "/api/delete-document/1",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200

    data = response.get_json()
    assert data["deleted"] is True
    assert data["id"] == 1
    assert data["file_deleted"] is True
    assert data["file_missing"] is False

    assert not pdf_file.exists()

    queries = [
        str(call.args[0])
        for call in mock_conn.execute.call_args_list
    ]

    assert any(
        "DELETE FROM Documents" in query
        for query in queries
    )


def test_delete_document_other_user(monkeypatch, tmp_path):

    pdf_file = tmp_path / "other_user.pdf"
    pdf_file.write_bytes(b"%PDF-1.4 private document")

    mock_conn = MagicMock()
    mock_conn.execute.return_value.first.return_value = None

    mock_engine = MagicMock()
    mock_engine.connect.return_value.__enter__.return_value = mock_conn
    mock_engine.begin.return_value.__enter__.return_value = mock_conn

    monkeypatch.setitem(app.config, "_ENGINE", mock_engine)
    monkeypatch.setitem(app.config, "STORAGE_DIR", tmp_path)

    serializer = URLSafeTimedSerializer(
        app.config["SECRET_KEY"],
        salt="tatou-auth",
    )

    token = serializer.dumps({
        "uid": 1,
        "login": "test-user",
        "email": "test@example.com",
    })

    client = app.test_client()

    response = client.delete(
        "/api/delete-document/2",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 404
    assert response.get_json()["error"] == "document not found"

    assert pdf_file.exists()

    query_call = mock_conn.execute.call_args_list[0]
    query = str(query_call.args[0])
    params = query_call.args[1]

    assert "ownerid = :uid" in query
    assert params["id"] == 2
    assert params["uid"] == 1

    mock_engine.begin.assert_not_called()

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
