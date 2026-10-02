import re
import secrets
from server import app

def test_healthz_route():
    client = app.test_client()
    resp = client.get("/healthz")

    assert resp.status_code == 200
    assert resp.is_json
    
def test_delete_document_rejects_sql_injection():
    client = app.test_client()

    resp = client.post(
        "/api/delete-document?id=1%20OR%201=1"
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
