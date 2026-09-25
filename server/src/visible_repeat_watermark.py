import pymupdf
import hashlib
import hmac
from watermarking_method import (WatermarkingMethod, PdfSource, load_pdf_bytes, SecretNotFoundError, InvalidKeyError,)

class VisibleRepeatWatermark(WatermarkingMethod):
    name = "visible-repeat"

    @staticmethod
    def get_usage() -> str:
        return "Repeats a visible watermark across every page of the PDF."

    def is_watermark_applicable(
            self,
            pdf: PdfSource,
            position: str | None = None,
    ) -> bool:
        pdf_bytes = load_pdf_bytes(pdf)
        doc = pymupdf.open(stream=pdf_bytes, filetype="pdf")
        applicable = doc.page_count > 0

        doc.close()
        return applicable

    def add_watermark(
            self,
            pdf: PdfSource,
            secret: str,
            key: str,
            position: str | None = None,
    ) -> bytes:

        if not secret:
            raise ValueError("Secret can not be empty")
       
        if not key:
            raise ValueError("Key can not be empty")

        pdf_bytes = load_pdf_bytes(pdf)
        doc = pymupdf.open(stream=pdf_bytes, filetype="pdf")

        tag = hmac.new(
            key.encode("utf-8"),
            secret.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()[:16]

        watermark_text = f"TATOU-watermark:{secret}:{tag}"

        for page in doc:
            width = page.rect.width
            height = page.rect.height

            positions = [
                (width * 0.15, height * 0.15),
                (width * 0.50, height * 0.35),
                (width * 0.15, height * 0.60),
                (width * 0.40, height * 0.80),]

            for position in positions:
                page.insert_text(
                    position, watermark_text, 
                    fontsize=16, 
                    color=(0.5, 0.5, 0.5), 
                    fill_opacity=0.3)

        result = doc.tobytes()
        doc.close()

        return result

    def read_secret(self, pdf:PdfSource, key:str) -> str:
        if not key:
            raise InvalidKeyError("Key can not be empty")

        pdf_bytes = load_pdf_bytes(pdf)
        doc = pymupdf.open(stream=pdf_bytes, filetype="pdf")

        marker = "TATOU-watermark:"
        watermark_found = False

        try:
            for page in doc:
                text = page.get_text()

                for line in text.splitlines():
                    if marker not in line:
                        continue

                    watermark_found = True
                    watermark_data = line.split(marker, 1)[1].strip()

                    if ":" not in watermark_data:
                        continue

                    secret, tag = watermark_data.rsplit(":", 1)

                    expected_tag = hmac.new(key.encode ("utf-8"),
                                            secret.encode("utf-8"),
                                            hashlib.sha256
                                            ).hexdigest()[:16]

                    if hmac.compare_digest(tag, expected_tag):
                        return secret

        finally:
            doc.close()

        if watermark_found:
            raise InvalidKeyError("Invalid key or modified watermark")

        raise SecretNotFoundError("Visible watermark not found")