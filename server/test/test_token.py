import secrets


def test_download_token():
    token = secrets.token_hex(32)

    # 32 bytes = 64 hexadecimal characters
    assert len(token) == 64

    # Token should contain only hexadecimal characters
    assert all(c in "0123456789abcdef" for c in token)

    # Generate another token and make sure they are different
    another_token = secrets.token_hex(32)
    assert token != another_token