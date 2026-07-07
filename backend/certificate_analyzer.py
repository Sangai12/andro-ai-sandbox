"""
AndroAI Sandbox - Certificate Analyzer

This module extracts APK signing certificate information.
"""

from typing import Any

from androguard.core.apk import APK


def _safe_getattr(obj: Any, primary: str, fallback: str | None = None) -> str:
    value = getattr(obj, primary, None)

    if value is None and fallback is not None:
        value = getattr(obj, fallback, None)

    if value is None:
        return "unknown"

    return str(value)


def extract_certificate_metadata(
    apk: APK,
) -> list[dict[str, Any]]:
    """
    Extract signing certificate metadata from an APK.
    """

    certificates: list[dict[str, Any]] = []

    for certificate in apk.get_certificates():
        certificates.append(
            {
                "subject": str(certificate.subject),
                "issuer": str(certificate.issuer),
                "serial_number": str(certificate.serial_number),
                "signature_algorithm": _safe_getattr(
                    certificate,
                    "signature_hash_algorithm",
                ),
                "valid_from": _safe_getattr(
                    certificate,
                    "not_valid_before_utc",
                    "not_valid_before",
                ),
                "valid_until": _safe_getattr(
                    certificate,
                    "not_valid_after_utc",
                    "not_valid_after",
                ),
            }
        )

    return certificates