
from hypothesis import given, settings, strategies as st

from server import app


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
