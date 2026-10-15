import re
import secrets
from urllib import response
import pytest
from server import app
import os
from itsdangerous import URLSafeTimedSerializer
from types import SimpleNamespace
import os
from itsdangerous import URLSafeTimedSerializer
from types import SimpleNamespace
from unittest.mock import MagicMock
from sqlalchemy.exc import IntegrityError


class FakeUserResult:
    def __init__(self, row=None, lastrowid=None):
        self.row = row
        self.lastrowid = lastrowid

    def first(self):
        return self.row

    def one(self):
        if self.row is None:
            raise RuntimeError("Expected one user")
        return self.row


class FakeUserConnection:
    def __init__(self, engine):
        self.engine = engine

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def execute(self, query, parameters=None):
        sql = str(query).lower()
        parameters = parameters or {}

        if "insert into users" in sql:
            email = parameters["email"]
            login = parameters["login"]

            for user in self.engine.users.values():
                if user.email == email or user.login == login:
                    raise IntegrityError(
                        str(query), parameters, Exception("duplicate user")
                    )

            user_id = self.engine.next_id
            self.engine.next_id += 1

            user = SimpleNamespace(
                id=user_id,
                email=email,
                login=login,
                hpassword=parameters["hpw"],
            )
            self.engine.users[user_id] = user

            return FakeUserResult(lastrowid=user_id)

        if "where id = :id" in sql:
            user = self.engine.users.get(parameters["id"])

            if user is None:
                return FakeUserResult()

            return FakeUserResult(
                SimpleNamespace(
                    id=user.id,
                    email=user.email,
                    login=user.login,
                )
            )

        if "where email = :email" in sql:
            for user in self.engine.users.values():
                if user.email == parameters["email"]:
                    return FakeUserResult(user)

            return FakeUserResult()

        raise RuntimeError(f"Unexpected SQL query: {query}")


class FakeUserEngine:
    def __init__(self):
        self.users = {}
        self.next_id = 1

    def connect(self):
        return FakeUserConnection(self)

    def begin(self):
        return FakeUserConnection(self)


@pytest.fixture
def fake_user_db(monkeypatch):
    engine = FakeUserEngine()
    monkeypatch.setitem(app.config, "_ENGINE", engine)
    return engine


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



def test_create_user_success(fake_user_db):
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



def test_create_user_duplicate(fake_user_db):
    client = app.test_client()
    user = unique_user()

    first_response = client.post("/api/create-user", json=user)
    assert first_response.status_code == 201

    second_response = client.post("/api/create-user", json=user)
    assert second_response.status_code == 409


def test_login_success(fake_user_db):
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


def test_login_wrong_password(fake_user_db):
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


def test_create_user_rejects_missing_required_fields(fake_user_db):
    with app.test_client() as client:
        response = client.post(
            "/api/create-user",
            json={"email": "test@example.com"},
        )

    assert response.status_code == 400
    assert "error" in response.get_json()


def test_login_rejects_missing_required_fields(fake_user_db):
    with app.test_client() as client:
        response = client.post(
            "/api/login",
            json={"email": "test@example.com"},
        )

    assert response.status_code == 400
    assert "error" in response.get_json()


def test_login_rejects_unknown_email(fake_user_db):
    with app.test_client() as client:
        response = client.post(
            "/api/login",
            json={
                "email": "unknown@example.com",
                "password": "SomePassword123!",
            },
        )

    assert response.status_code == 401
    assert response.get_json()["error"] == "invalid credentials"


def test_delete_document_returns_503_when_database_lookup_fails(monkeypatch):
    from types import SimpleNamespace

    class FailingConnection:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

        def execute(self, query, parameters=None):
            raise RuntimeError("Simulated database failure")

    class FailingEngine:
        def connect(self):
            return FailingConnection()

    # Make the endpoint use our mock database.
    monkeypatch.setitem(app.config, "_ENGINE", FailingEngine())

    # Create a valid authentication token.
    serializer = URLSafeTimedSerializer(
        os.environ["SECRET_KEY"],
        salt="tatou-auth",
    )
    token = serializer.dumps({
        "uid": 1,
        "login": "test-user",
        "email": "test@example.com",
    })

    client = app.test_client()
    response = client.post(
        "/api/delete-document?id=1",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 503
    assert response.get_json()["error"] == "database error"


def test_delete_document_returns_503_when_delete_fails(monkeypatch, tmp_path):
    class FakeResult:
        def first(self):
            return SimpleNamespace(
                id=1,
                ownerid=1,
                path="test-document.pdf",
            )

    class FakeConnection:
        def __init__(self, fail_on_delete=False):
            self.fail_on_delete = fail_on_delete

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

        def execute(self, query, parameters=None):
            sql = str(query).lower()

            if "select" in sql:
                return FakeResult()

            if "delete from documents" in sql:
                raise RuntimeError("Simulated delete failure")

            raise RuntimeError(f"Unexpected SQL: {query}")

    class FakeEngine:
        def connect(self):
            return FakeConnection()

        def begin(self):
            return FakeConnection(fail_on_delete=True)

    monkeypatch.setitem(app.config, "_ENGINE", FakeEngine())
    monkeypatch.setitem(app.config, "STORAGE_DIR", str(tmp_path))

    serializer = URLSafeTimedSerializer(
        os.environ["SECRET_KEY"],
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

    assert response.status_code == 503
    assert response.get_json()["error"].startswith(
        "database error during delete:"
    )
