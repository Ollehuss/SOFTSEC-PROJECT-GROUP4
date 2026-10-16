import pytest
import argparse
import io
import sys

from watermarking_cli import main
from watermarking_cli import (
    _read_text_from_file,
    _read_text_from_stdin,
    _resolve_secret,
    _resolve_key,
)

def test_cli_methods(capsys):
    """Check that the CLI lists our watermarking methods."""
    result = main(["methods"])

    output = capsys.readouterr().out

    assert result == 0
    assert "metadata-hmac" in output
    assert "visible-repeat" in output
    assert "hidden-object" in output

def test_cli_version(capsys):
    """Check that the CLI displays its version."""
    with pytest.raises(SystemExit) as error:
        main(["--version"])

    output = capsys.readouterr().out

    assert error.value.code == 0
    assert "pdfwm" in output

def test_cli_no_command():
    """Check that the CLI requires a command."""
    with pytest.raises(SystemExit) as error:
        main([])

    assert error.value.code == 2

def test_cli_invalid_command():
    """Check that the CLI rejects unknown commands."""
    with pytest.raises(SystemExit) as error:
        main(["not-a-command"])

    assert error.value.code == 2

def test_read_text_from_file(tmp_path):
    """Check that the CLI reads text from a file."""
    file = tmp_path / "secret.txt"
    file.write_text("my-secret", encoding="utf-8")

    result = _read_text_from_file(str(file))

    assert result == "my-secret"


def test_read_text_from_stdin(monkeypatch):
    """Check that the CLI reads text from stdin."""
    monkeypatch.setattr(sys, "stdin", io.StringIO("hello"))

    result = _read_text_from_stdin()

    assert result == "hello"


def test_resolve_secret():
    """Check that a directly provided secret is returned."""
    args = argparse.Namespace(
        secret="my-secret",
        secret_file=None,
        secret_stdin=False,
    )

    result = _resolve_secret(args)

    assert result == "my-secret"


def test_resolve_key():
    """Check that a directly provided key is returned."""
    args = argparse.Namespace(
        key="my-key",
        key_file=None,
        key_stdin=False,
        key_prompt=False,
    )

    result = _resolve_key(args)

    assert result == "my-key"