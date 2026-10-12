
from hypothesis import given, settings, strategies as st

from server import app

import os
from itsdangerous import URLSafeTimedSerializer


client = app.test_client()


# Generate JSON values that are not JSON objects.
non_object_json = st.one_of(
    st.lists(st.integers(), min_size=1),
    st.text(min_size=1),
    st.integers(),
    st.booleans(),
)


@settings(max_examples=100, deadline=None)
@given(payload=non_object_json)
def test_create_user_rejects_non_object_json(payload):
    response = client.post("/api/create-user", json=payload)

    assert response.status_code == 400


@settings(max_examples=100, deadline=None)
@given(payload=non_object_json)
def test_login_rejects_non_object_json(payload):
    response = client.post("/api/login", json=payload)

    assert response.status_code == 400


def make_test_auth_headers():
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


@settings(max_examples=100, deadline=None)
@given(document_id=st.text(
    alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    min_size=1,
))
def test_get_document_rejects_non_numeric_ids(document_id):
    response = client.get(
        "/api/get-document",
        query_string={"id": document_id},
        headers=make_test_auth_headers(),
    )

    assert response.status_code == 400




class FakeResult:
    def __init__(self, rows=None):
        self.rows = rows if rows is not None else []

    def first(self):
        return None

    def all(self):
        return self.rows


class FakeConnection:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def execute(self, query, parameters=None):
        return FakeResult()


class FakeEngine:
    def connect(self):
        return FakeConnection()



class RecordingConnection(FakeConnection):
    def __init__(self):
        self.query = None
        self.parameters = None

    def execute(self, query, parameters=None):
        self.query = str(query)
        self.parameters = parameters
        return FakeResult()




    
@settings(max_examples=100, deadline=None)
@given(document_id=st.integers(
    min_value=-(10**100),
    max_value=10**100,
))
def test_get_document_handles_numeric_ids(document_id):
    had_engine = "_ENGINE" in app.config
    old_engine = app.config.get("_ENGINE")

    app.config["_ENGINE"] = FakeEngine()

    try:
        response = client.get(
            "/api/get-document",
            query_string={"id": str(document_id)},
            headers=make_test_auth_headers(),
        )

        assert response.status_code == 404
    finally:
        if had_engine:
            app.config["_ENGINE"] = old_engine
        else:
            app.config.pop("_ENGINE", None)


def test_list_documents_requires_authentication():
    response = client.get("/api/list-documents")

    assert response.status_code == 401



@settings(max_examples=100, deadline=None)
@given(token=st.text(
    alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.",
    max_size=200,
))
def test_list_documents_rejects_arbitrary_tokens(token):
    response = client.get(
        "/api/list-documents",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401


def test_list_documents_returns_empty_list_when_no_documents(monkeypatch):
    monkeypatch.setitem(app.config, "_ENGINE", FakeEngine())

    response = client.get(
        "/api/list-documents",
        headers=make_test_auth_headers(),
    )

    assert response.status_code == 200
    assert response.get_json() == {"documents": []}


def test_list_documents_filters_by_authenticated_user(monkeypatch):
    connection = RecordingConnection()

    class RecordingEngine:
        def connect(self):
            return connection

    monkeypatch.setitem(app.config, "_ENGINE", RecordingEngine())

    response = client.get(
        "/api/list-documents",
        headers=make_test_auth_headers(),
    )

    assert response.status_code == 200
    assert connection.parameters == {"uid": 1}
    assert "WHERE ownerid = :uid" in connection.query


def test_list_documents_does_not_expose_database_errors(monkeypatch):
    class BrokenConnection(FakeConnection):
        def execute(self, query, parameters=None):
            raise RuntimeError("internal_database_secret_123")

    class BrokenEngine:
        def connect(self):
            return BrokenConnection()

    monkeypatch.setitem(app.config, "_ENGINE", BrokenEngine())

    response = client.get(
        "/api/list-documents",
        headers=make_test_auth_headers(),
    )

    assert response.status_code == 503
    assert "internal_database_secret_123" not in response.get_data(as_text=True)

