import pymupdf
import pytest

from watermarking_joshua import HiddenObjectWatermark

@pytest.fixture
def one_page_pdf() -> bytes:
    with pymupdf.open() as document:
        document.new_page()
        return document.tobytes()


def test_normal_pdf_is_applicable(one_page_pdf):
    watermarker = HiddenObjectWatermark()
    result = watermarker.is_watermark_applicable(one_page_pdf)
    assert result == True

def test_secret_is_unchanged_after_watermarking(one_page_pdf):
    watermarker = HiddenObjectWatermark()
    secret = "test_secret"
    key = "test_key"
    watermarked_pdf = watermarker.add_watermark(one_page_pdf, secret, key)
    result = watermarker.read_secret(watermarked_pdf, key)
    assert result == secret


def test_add_watermark_is_deterministic(one_page_pdf):
    watermarker = HiddenObjectWatermark()
    secret = "test_secret"
    key = "test_key"
    watermarked_pdf_one = watermarker.add_watermark(one_page_pdf, secret, key)
    watermarked_pdf_two = watermarker.add_watermark(one_page_pdf, secret, key)
    assert watermarked_pdf_one == watermarked_pdf_two