import pymupdf
import pytest

from visible_repeat_watermark import VisibleRepeatWatermark
from watermarking_method import InvalidKeyError


def test_visible_repeat_roundtrip(tmp_path):
    original_pdf = tmp_path / "original.pdf"

    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_text((100, 100), "This is the original document.")
    doc.save(original_pdf)
    doc.close()

    method = VisibleRepeatWatermark()

    secret = "test-secret-123"
    key = "test-key"

    watermarked_bytes = method.add_watermark(
        original_pdf,
        secret=secret,
        key=key,
        position=None,
    )

    watermarked_pdf = tmp_path / "watermarked.pdf"
    watermarked_pdf.write_bytes(watermarked_bytes)

    recovered_secret = method.read_secret(
        watermarked_pdf,
        key=key,
    )

    assert recovered_secret == secret

def test_visible_repeat_rejects_wrong_key(tmp_path):
    original_pdf = tmp_path / "original.pdf"

    doc = pymupdf.open()
    doc.new_page()
    doc.save(original_pdf)
    doc.close()

    method = VisibleRepeatWatermark()

    watermarked_bytes = method.add_watermark(
        original_pdf,
        secret="test-secret-123",
        key="correct-key",
        position=None,
    )

    watermarked_pdf = tmp_path / "watermarked.pdf"
    watermarked_pdf.write_bytes(watermarked_bytes)

    with pytest.raises(InvalidKeyError):
        method.read_secret(
            watermarked_pdf,
            key="wrong-key",
        )

