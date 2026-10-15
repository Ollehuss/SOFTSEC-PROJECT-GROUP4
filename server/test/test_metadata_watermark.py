import io

import fitz
import pytest

from olles_metadata_watermark import MetadataWatermark
from watermarking_method import InvalidKeyError, SecretNotFoundError


@pytest.fixture
def watermark():
    return MetadataWatermark()


@pytest.fixture
def sample_pdf():
    """Create a minimal PDF in memory."""
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((72, 72), "Metadata watermark test")
    pdf_bytes = doc.tobytes()
    doc.close()
    return pdf_bytes


def test_metadata_hmac_round_trip(watermark, sample_pdf):
    secret = "test-secret-123"
    key = "test-key-456"

    watermarked_pdf = watermark.add_watermark(
        sample_pdf,
        secret=secret,
        key=key,
    )

    recovered_secret = watermark.read_secret(
        watermarked_pdf,
        key=key,
    )

    assert recovered_secret == secret


def test_metadata_hmac_rejects_wrong_key(watermark, sample_pdf):
    watermarked_pdf = watermark.add_watermark(
        sample_pdf,
        secret="test-secret",
        key="correct-key",
    )

    with pytest.raises(InvalidKeyError):
        watermark.read_secret(
            watermarked_pdf,
            key="wrong-key",
        )


def test_metadata_hmac_rejects_pdf_without_watermark(watermark, sample_pdf):
    with pytest.raises(SecretNotFoundError):
        watermark.read_secret(
            sample_pdf,
            key="test-key",
        )


def test_metadata_hmac_preserves_pdf_content(watermark, sample_pdf):
    watermarked_pdf = watermark.add_watermark(
        sample_pdf,
        secret="test-secret",
        key="test-key",
    )

    doc = fitz.open(stream=watermarked_pdf, filetype="pdf")
    try:
        assert doc.page_count == 1
        assert "Metadata watermark test" in doc[0].get_text()
    finally:
        doc.close()


def test_metadata_hmac_metadata_contains_expected_fields(
    watermark, sample_pdf
):
    watermarked_pdf = watermark.add_watermark(
        sample_pdf,
        secret="test-secret",
        key="test-key",
    )

    doc = fitz.open(stream=watermarked_pdf, filetype="pdf")
    try:
        metadata_value = doc.metadata["keywords"]
    finally:
        doc.close()

    assert metadata_value.startswith("WM-METADATA:v1:")
    assert '"alg":"HMAC-SHA256"' in metadata_value
    assert '"secret":"test-secret"' in metadata_value
    assert '"mac":' in metadata_value