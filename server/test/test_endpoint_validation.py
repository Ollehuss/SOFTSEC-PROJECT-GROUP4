
import pytest
from server import app


import os

import pytest
from itsdangerous import URLSafeTimedSerializer
from server import app


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


@pytest.mark.parametrize(
    ("path", "payload", "expected_status"),
    [
        ("/api/create-watermark", {}, 400),
        ("/api/create-watermark/not-an-id", {
            "method": "metadata-hmac",
            "intended_for": "test-user",
            "secret": "test-secret",
            "key": "test-key",
        }, 405),
        ("/api/read-watermark", {}, 400),
        ("/api/read-watermark/not-an-id", {
            "method": "metadata-hmac",
            "key": "test-key",
        }, 405),
    ],
)
def test_watermark_validation(
    auth_headers, path, payload, expected_status
):
    response = app.test_client().post(
        path,
        json=payload,
        headers=auth_headers,
    )

    assert response.status_code == expected_status, (
        f"{path} returned {response.status_code}: "
        f"{response.get_data(as_text=True)}"
    )


@pytest.mark.parametrize(
    "path",
    [
        "/api/rmap-initiate",
        "/api/rmap-get-link",
    ],
)
def test_rmap_rejects_non_object_json(path):
    response = app.test_client().post(
        path,
        json=["not", "an", "object"],
    )

    assert response.status_code == 400
    assert response.get_json()["error"] == "JSON object required"



@pytest.mark.parametrize(
    ("method", "path", "expected_status"),
    [
        ("post", "/api/rmap-initiate", 400),
        ("post", "/api/rmap-get-link", 400),
        ("post", "/api/upload-document", 401),
        ("delete", "/api/delete-document", 401),
        ("get", "/api/get-document", 401),
        ("post", "/api/create-watermark/1", 401),
        ("post", "/api/read-watermark/1", 401),
    ],
)
def test_endpoint_validation_without_authentication(
    method, path, expected_status
):
    client = app.test_client()

    if path in ("/api/rmap-initiate", "/api/rmap-get-link"):
        response = getattr(client, method)(
            path,
            json={},
        )
    else:
        response = getattr(client, method)(path)

    assert response.status_code == expected_status, (
        f"{method.upper()} {path} returned "
        f"{response.status_code}; expected {expected_status}. "
        f"Response: {response.get_data(as_text=True)}"
    )
