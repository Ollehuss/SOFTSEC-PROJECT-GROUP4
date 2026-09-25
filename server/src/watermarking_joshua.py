from __future__ import annotations
from typing import Final

import pymupdf
import hmac
import hashlib

from watermarking_method import WatermarkingMethod, load_pdf_bytes, PdfSource, SecretNotFoundError, InvalidKeyError



class HiddenObjectWatermark(WatermarkingMethod):
    name: Final[str] = "hidden-object"
    _catalog_key: Final[str] = "ObjectReference"

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

        with pymupdf.open(stream=data, filetype="pdf") as document:
            secret_xref = document.get_new_xref()
            document.update_object(secret_xref, "<<>>")
            secret_seal = hmac.new(key.encode(), secret.encode(), hashlib.sha256).hexdigest()
            watermark_payload = f"{secret_seal}:{secret}"
            document.update_stream(secret_xref, watermark_payload.encode())
            catalog_xref = document.pdf_catalog()
            document.xref_set_key(catalog_xref, self._catalog_key, f"{secret_xref} 0 R")
            return document.tobytes(no_new_id=True)


    def read_secret(self, pdf: PdfSource, key: str) -> str:
        data = load_pdf_bytes(pdf)
        if not key:
            raise ValueError("Key must be a non-empty string")
        with pymupdf.open(stream=data, filetype="pdf") as document:
            catalog_xref = document.pdf_catalog()
            catalog_entry_type, reference_to_secret_object = document.xref_get_key(catalog_xref, self._catalog_key)
            if catalog_entry_type != "xref":
                raise SecretNotFoundError("No hidden-object watermark found")
            try:
                secret_xref = int(reference_to_secret_object.split()[0])
                secret_bytes = document.xref_stream(secret_xref)
                watermark_payload = secret_bytes.decode()
                stored_seal, stored_secret = watermark_payload.split(":", 1)
            except (ValueError, IndexError, AttributeError) as exc:
                raise SecretNotFoundError("Malformed watermark payload") from exc
        expected_seal = hmac.new(key.encode(), stored_secret.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_seal, stored_seal):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")
        return stored_secret



