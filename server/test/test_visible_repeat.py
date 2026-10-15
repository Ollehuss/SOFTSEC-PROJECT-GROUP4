import pymupdf
import pytest
import hashlib
import hmac

from visible_repeat_watermark import VisibleRepeatWatermark
from watermarking_method import InvalidKeyError, SecretNotFoundError


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

def test_visible_repeat_secret_with_colons(tmp_path):
    original_pdf = tmp_path / "original.pdf"
    watermarked_pdf = tmp_path / "watermarked.pdf"

    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_text((100, 100), "Test document")
    doc.save(original_pdf)
    doc.close()

    method = VisibleRepeatWatermark()
    secret = "project:confidential:2026"
    key = "test-key"

    watermarked_bytes = method.add_watermark(
        original_pdf,
        secret=secret,
        key=key,
        position=None,
    )

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


def test_visible_repeat_recovers_from_damaged_copy(tmp_path):
    original_pdf = tmp_path / "original.pdf"
    doc =pymupdf.open()
    doc.new_page()
    doc.save(original_pdf)
    doc.close()

    method = VisibleRepeatWatermark()

    secret = "test-secret-123"
    key = "test-key"

    watermarked_bytes = method.add_watermark(original_pdf,
                                             secret=secret,
                                             key=key,
                                             position=None,)

    watermarked_pdf = tmp_path / "watermarked.pdf"
    watermarked_pdf.write_bytes(watermarked_bytes)
    doc = pymupdf.open(watermarked_pdf)
    page = doc[0]

    first_watermark = page.search_for("TATOU-watermark:")[0]
    page.add_redact_annot(first_watermark)
    page.apply_redactions()

    damaged_pdf = tmp_path / "damaged.pdf"
    doc.save(damaged_pdf)
    doc.close()

    recovered_secret = method.read_secret(
        damaged_pdf,
        key=key,
    )

    assert recovered_secret == secret

def test_visible_repeat_rejects_empty_secret(tmp_path):
    original_pdf = tmp_path / "original.pdf"

    doc = pymupdf.open()
    doc.new_page()
    doc.save(original_pdf)
    doc.close()

    method = VisibleRepeatWatermark()

    with pytest.raises(ValueError):
        method.add_watermark(original_pdf,
                             secret="",
                             key="test-key",
                             position=None,
        )


def test_visible_repeat_rejects_empty_key(tmp_path):
    original_pdf = tmp_path / "original.pdf"

    doc = pymupdf.open()
    doc.new_page()
    doc.save(original_pdf)
    doc.close()

    method = VisibleRepeatWatermark()

    with pytest.raises(ValueError):
        method.add_watermark(original_pdf,
                             secret="test-secret",
                             key="",
                             position=None,
        )

def test_visible_repeat_rejects_unwatermarked_pdf(tmp_path):
    original_pdf = tmp_path / "unwatermarked.pdf"

    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_text((100, 100), "This PDF has no watermark.")
    doc.save(original_pdf)
    doc.close()
    method = VisibleRepeatWatermark()

    with pytest.raises(
        SecretNotFoundError,
        match="Visible watermark not found",
    ):
        method.read_secret(original_pdf, key="test-key")


def test_visible_repeat_watermark_positions(tmp_path):
    original_pdf = tmp_path / "original.pdf"

    doc = pymupdf.open()
    doc.new_page()
    doc.save(original_pdf)
    doc.close()

    method = VisibleRepeatWatermark()

    watermarked_bytes = method.add_watermark(
        original_pdf,
        secret="position-test",
        key="test-key",
    )

    result = pymupdf.open(
        stream=watermarked_bytes,
        filetype="pdf",
    )

    try:
        page = result[0]
        width = page.rect.width
        height = page.rect.height

        expected_positions = [
            (0.15, 0.15),
            (0.50, 0.35),
            (0.15, 0.60),
            (0.40, 0.80),
        ]

        watermark_blocks = [
            block
            for block in page.get_text("blocks")
            if "TATOU-watermark:" in block[4]
        ]

        assert len(watermark_blocks) == 4

        for block, (relative_x, relative_y) in zip(
            watermark_blocks,
            expected_positions,
        ):
            actual_x = block[0]
            actual_y = block[1]
            expected_x = width * relative_x
            expected_y = height * relative_y - 17.2

            assert abs(actual_x - expected_x) < 2
            assert abs(actual_y - expected_y) < 2

    finally:
        result.close()

def test_read_secret_skips_missing_separator(tmp_path):
    pdf_path = tmp_path / "malformed_separator.pdf"
    secret = "recover-me"
    key = "test-key"

    valid_tag = hmac.new(
        key.encode("utf-8"),
        secret.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:8]

    doc = pymupdf.open()
    page = doc.new_page()

    page.insert_text(
        (50, 100),
        "TATOU-watermark:malformed",
    )

    page.insert_text(
        (50, 150),
        f"TATOU-watermark:{secret}:{valid_tag}",
    )

    doc.save(pdf_path)
    doc.close()

    method = VisibleRepeatWatermark()
    assert method.read_secret(pdf_path, key) == secret


def test_read_secret_skips_invalid_hex_tag(tmp_path):
    pdf_path = tmp_path / "invalid_hex.pdf"
    secret = "recover-me"
    key = "test-key"

    valid_tag = hmac.new(
        key.encode("utf-8"),
        secret.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:8]

    doc = pymupdf.open()
    page = doc.new_page()

    page.insert_text(
        (50, 100),
        "TATOU-watermark:damaged:zzzzzzzz",
    )

    page.insert_text(
        (50, 150),
        f"TATOU-watermark:{secret}:{valid_tag}",
    )

    doc.save(pdf_path)
    doc.close()

    method = VisibleRepeatWatermark()

    assert method.read_secret(pdf_path, key) == secret