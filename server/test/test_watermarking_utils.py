import pytest

from watermarking_utils import METHODS, get_method, register_method
from watermarking_utils import explore_pdf
from watermarking_utils import apply_watermark, is_watermarking_applicable, read_watermark

from unittest.mock import MagicMock, patch

def test_get_existing_method():
    """Check that we can find our metadata watermark method."""
    method = get_method("metadata-hmac")

    assert method is METHODS["metadata-hmac"]

def test_get_unknown_method():
    """Check that an unknown watermark method raises an error."""
    with pytest.raises(KeyError):
        get_method("this-method-does-not-exist")

def test_get_method_instance():
    """Check that passing a method object returns the same object."""
    method = METHODS["metadata-hmac"]

    result = get_method(method)

    assert result is method

def test_register_method():
    """Check that we can register an existing watermark method."""
    method = METHODS["visible-repeat"]

    register_method(method)

    assert get_method("visible-repeat") is method

def test_explore_pdf_returns_dictionary():
    """Check that PDF exploration returns a dictionary."""
    pdf = b"%PDF-1.4\n"

    result = explore_pdf(pdf)

    assert isinstance(result, dict)

def test_explore_pdf_contains_size():
    """Check that the reported size matches the input."""
    pdf = b"%PDF-1.4\n"

    result = explore_pdf(pdf)

    assert result["size"] == len(pdf)

def test_explore_pdf_contains_children():
    """Check that the result contains a list of PDF objects."""
    pdf = b"%PDF-1.4\n"

    result = explore_pdf(pdf)

    assert "children" in result
    assert isinstance(result["children"], list)

@pytest.mark.parametrize(
    "function_name, expected_result",
    [
        ("apply", b"watermarked PDF"),
        ("applicable", True),
        ("read", "test secret"),
    ],
)
def test_watermarking_utils_delegate_to_method(function_name, expected_result):
    """Check that utility functions call the correct watermark method."""
    fake_method = MagicMock()
    fake_method.add_watermark.return_value = b"watermarked PDF"
    fake_method.is_watermark_applicable.return_value = True
    fake_method.read_secret.return_value = "test secret"

    with patch("watermarking_utils.get_method", return_value=fake_method):
        if function_name == "apply":
            result = apply_watermark(
                method="metadata-hmac",
                pdf=b"test PDF",
                secret="test secret",
                key="test key",
            )
            fake_method.add_watermark.assert_called_once_with(
                pdf=b"test PDF",
                secret="test secret",
                key="test key",
                position=None,
            )

        elif function_name == "applicable":
            result = is_watermarking_applicable(
                method="metadata-hmac",
                pdf=b"test PDF",
            )
            fake_method.is_watermark_applicable.assert_called_once_with(
                pdf=b"test PDF",
                position=None,
            )

        else:
            result = read_watermark(
                method="metadata-hmac",
                pdf=b"test PDF",
                key="test key",
            )
            fake_method.read_secret.assert_called_once_with(
                pdf=b"test PDF",
                key="test key",
            )

    assert result == expected_result