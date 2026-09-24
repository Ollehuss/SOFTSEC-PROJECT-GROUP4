from __future__ import annotations
from typing import Final

import pymupdf


from watermarking_method import WatermarkingMethod, load_pdf_bytes, PdfSource, SecretNotFoundError, InvalidKeyError



class HiddenObjectWatermark(WatermarkingMethod):
    name: Final[str] = "hidden-object"

    @staticmethod
    def get_usage() -> str:
        return "Method that hides secret objects inside the PDF, position is ignored"


    def is_watermark_applicable(self, pdf:PdfSource, position:str |None = None) -> bool:
        data = load_pdf_bytes(pdf)
        with pymupdf.open(stream=data, filetype="pdf") as document:
            return document.page_count > 0 and not document.needs_pass


    def add_watermark(
            self,
            pdf: PdfSource,
            secret: str,
            key: str,
            position: str | None = None,
    ) -> bytes:
        data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not key:
            raise ValueError("Key must be a non-empty string")
        return data

    def read_secret(self, pdf: PdfSource, key: str) -> str:
        data = load_pdf_bytes(pdf)
        if not key:
            raise ValueError("Key must be a non-empty string")
        raise SecretNotFoundError("No hidden-object watermark found")



