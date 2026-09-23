from __future__ import annotations

import hashlib
import hmac
import json
from typing import Final

import fitz

from watermarking_method import (
    InvalidKeyError,
    PdfSource,
    SecretNotFoundError,
    WatermarkingError,
    WatermarkingMethod,
    is_pdf_bytes,
    load_pdf_bytes,
)


class MetadataWatermark(WatermarkingMethod):
    """
    Watermarking method that stores an authenticated watermark
    in the PDF document metadata.

    The secret is stored in the metadata together with an HMAC-SHA256
    value calculated using the supplied key.
    """

    name: Final[str] = "metadata-hmac"

    _FIELD: Final[str] = "keywords"
    _PREFIX: Final[str] = "WM-METADATA:v1:"
    _CONTEXT: Final[bytes] = b"wm:metadata-hmac:v1:"

    @staticmethod
    def get_usage() -> str:
        return (
            "Stores an authenticated watermark in the PDF metadata. "
            "Position is ignored."
        )

    def add_watermark(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:

        data = load_pdf_bytes(pdf)

        if not secret:
            raise ValueError("Secret must be a non-empty string")

        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        try:
            doc = fitz.open(stream=data, filetype="pdf")

            payload = self._build_payload(secret, key)

            metadata = doc.metadata or {}
            metadata[self._FIELD] = self._PREFIX + payload

            doc.set_metadata(metadata)

            output = doc.tobytes()
            doc.close()

            return output

        except Exception as exc:
            raise WatermarkingError(
                f"Failed to add metadata watermark: {exc}"
            ) from exc

    def is_watermark_applicable(
        self,
        pdf,
        position: str | None = None,
    ) -> bool:

        load_pdf_bytes(pdf)

        try:
            data = load_pdf_bytes(pdf)
            doc = fitz.open(stream=data, filetype="pdf")

            # Metadata is available on normal PDF documents.
            metadata = doc.metadata
            doc.close()

            return metadata is not None

        except Exception:
            return False


    def is_watermark_applicable(
        self,
        pdf: PdfSource,
        position: str | None = None,
    ) -> bool:
        
        try:
            pdf_bytes = load_pdf_bytes(pdf)

            if not is_pdf_bytes(pdf_bytes):
                return False

            doc = fitz.open(stream=pdf_bytes, filetype="pdf")
            try:
                return doc.page_count > 0
            finally:
                doc.close()

        except Exception:
            return False

    def read_secret(self, pdf, key: str) -> str:

        data = load_pdf_bytes(pdf)

        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        try:
            doc = fitz.open(stream=data, filetype="pdf")
            metadata = doc.metadata or {}
            doc.close()
        except Exception as exc:
            raise WatermarkingError(
                f"Failed to read PDF metadata: {exc}"
            ) from exc

        value = metadata.get(self._FIELD, "")

        if not value.startswith(self._PREFIX):
            raise SecretNotFoundError(
                "No metadata-hmac watermark found"
            )

        encoded_payload = value[len(self._PREFIX):]

        try:
            payload = json.loads(encoded_payload)
        except Exception as exc:
            raise SecretNotFoundError(
                "Malformed metadata watermark"
            ) from exc

        if payload.get("v") != 1:
            raise SecretNotFoundError(
                "Unsupported watermark version"
            )

        try:
            secret = payload["secret"]
            mac = payload["mac"]
        except KeyError as exc:
            raise SecretNotFoundError(
                "Invalid watermark payload"
            ) from exc

        expected_mac = self._calculate_mac(secret, key)

        if not hmac.compare_digest(mac, expected_mac):
            raise InvalidKeyError(
                "Provided key failed to authenticate the watermark"
            )

        return secret

    def _build_payload(self, secret: str, key: str) -> str:

        mac = self._calculate_mac(secret, key)

        payload = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "secret": secret,
            "mac": mac,
        }

        return json.dumps(
            payload,
            separators=(",", ":"),
            ensure_ascii=True,
        )

    def _calculate_mac(self, secret: str, key: str) -> str:

        message = self._CONTEXT + secret.encode("utf-8")

        return hmac.new(
            key.encode("utf-8"),
            message,
            hashlib.sha256,
        ).hexdigest()


__all__ = ["MetadataWatermark"]