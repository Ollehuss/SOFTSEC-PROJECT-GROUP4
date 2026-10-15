import io
import os
import server
from sqlalchemy import create_engine, text

import pytest
from itsdangerous import URLSafeTimedSerializer
from server import app


@pytest.fixture
def client(monkeypatch, tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'test.db'}")

    with engine.begin() as conn:
        conn.execute(text("""
            CREATE TABLE Users (
                id INTEGER PRIMARY KEY,
                login TEXT NOT NULL,
                email TEXT
            )
        """))

        conn.execute(text("""
            CREATE TABLE Documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                path TEXT,
                creation TEXT DEFAULT CURRENT_TIMESTAMP,
                sha256 BLOB,
                size INTEGER,
                ownerid INTEGER
            )
        """))

        conn.execute(text("""
            CREATE TABLE Versions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                documentid INTEGER,
                link TEXT,
                intended_for TEXT,
                secret TEXT,
                method TEXT
            )
        """))

        conn.execute(text("""
            INSERT INTO Users (id, login, email)
            VALUES (1, 'test-user', 'test@example.com')
        """))

    monkeypatch.setitem(app.config, "_ENGINE", engine)

    yield app.test_client()

    engine.dispose()

@pytest.fixture
def auth_headers():
    serializer = URLSafeTimedSerializer(
        os.environ["SECRET_KEY"],
        salt="tatou-auth",
    )
    token = serializer.dumps({
        "uid": 1,
        "login": "test-user",
        "email": "test@example.com",
    })
    return {"Authorization": f"Bearer {token}"}


# --------------------------------------------------
# POST /api/upload-document
# --------------------------------------------------

def test_upload_document_without_file(client, auth_headers):
    response = client.post(
        "/api/upload-document",
        headers=auth_headers,
    )
    assert response.status_code in (400, 415)


def test_upload_document_without_authentication(client):
    response = client.post(
        "/api/upload-document",
        data={"file": (io.BytesIO(b"test content"), "test.pdf")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 401


# --------------------------------------------------
# GET /api/list-documents
# --------------------------------------------------

def test_list_documents_without_authentication(client):
    response = client.get("/api/list-documents")
    assert response.status_code == 401


def test_list_documents_with_authentication(client, auth_headers):
    response = client.get(
        "/api/list-documents",
        headers=auth_headers,
    )
    assert response.status_code == 200


# --------------------------------------------------
# GET /api/list-versions
# --------------------------------------------------

def test_list_versions_without_authentication(client):
    response = client.get("/api/list-versions")
    assert response.status_code == 401


def test_list_versions_with_authentication(client, auth_headers):
    response = client.get(
        "/api/list-versions/1",
        headers=auth_headers,
    )
    assert response.status_code == 200


# --------------------------------------------------
# GET /api/list-versions/<document_id>
# --------------------------------------------------

def test_list_versions_nonexistent_document(client, auth_headers):
    response = client.get(
        "/api/list-versions/999999999",
        headers=auth_headers,
    )
    assert response.status_code in (200, 400, 404)


# --------------------------------------------------
# GET /api/list-all-versions
# --------------------------------------------------

def test_list_all_versions_without_authentication(client):
    response = client.get("/api/list-all-versions")
    assert response.status_code == 401


def test_list_all_versions_with_authentication(client, auth_headers):
    response = client.get(
        "/api/list-all-versions",
        headers=auth_headers,
    )
    assert response.status_code == 200


# --------------------------------------------------
# GET /api/get-document
# --------------------------------------------------

def test_get_document_without_authentication(client):
    response = client.get("/api/get-document")
    assert response.status_code == 401


# --------------------------------------------------
# GET /api/get-document/<document_id>
# --------------------------------------------------

def test_get_document_path_with_authentication(client, auth_headers):
    response = client.get(
        "/api/get-document/999999999",
        headers=auth_headers,
    )
    assert response.status_code in (400, 404)


# --------------------------------------------------
# GET /api/get-version/<link>
# --------------------------------------------------

def test_get_version_invalid_link(client):
    response = client.get("/api/get-version/invalid-test-link")
    assert response.status_code in (400, 403, 404, 410)

# --------------------------------------------------
# GET /api/get-watermarking-methods
# --------------------------------------------------

def test_get_watermarking_methods(client):
    response = client.get("/api/get-watermarking-methods")

    assert response.status_code == 200

    data = response.get_json()
    assert "methods" in data
    assert "count" in data
    assert isinstance(data["methods"], list)
    assert data["count"] == len(data["methods"])

    for method in data["methods"]:
        assert isinstance(method["name"], str)
        assert method["name"]
        assert isinstance(method["description"], str)

def test_upload_document_rejects_non_pdf(client, auth_headers):
    response = client.post(
        "/api/upload-document",
        headers=auth_headers,
        data={"file": (io.BytesIO(b"not a PDF"), "document.txt")},
        content_type="multipart/form-data",
    )

    assert response.status_code in (400, 415)