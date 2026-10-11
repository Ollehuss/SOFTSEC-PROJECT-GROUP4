
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


class FakeConnection:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def execute(self, query, parameters=None):
        return self

    def first(self):
        return None


class FakeEngine:
    def connect(self):
        return FakeConnection()


    
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

