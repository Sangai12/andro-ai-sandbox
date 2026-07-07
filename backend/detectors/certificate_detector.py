"""
AndroAI Sandbox - Certificate Detector

This module evaluates APK signing certificate metadata and returns
evidence-based findings.

Phase 16 scope:
- Detect self-signed certificates
- Detect unknown signature algorithm
- Detect debug/test/platform signing indicators
"""

from typing import Any


def detect_certificate_findings(
    certificates: list[dict[str, Any]],
) -> list[dict[str, str]]:
    """
    Analyze APK signing certificate metadata.
    """

    findings: list[dict[str, str]] = []

    suspicious_certificate_keywords = [
        "android debug",
        "debug",
        "testkey",
        "test key",
        "platform",
        "shared",
        "media",
        "aosp",
    ]

    for certificate in certificates:
        subject = certificate.get("subject", "")
        issuer = certificate.get("issuer", "")
        signature_algorithm = certificate.get("signature_algorithm", "")

        subject_lower = subject.lower()
        issuer_lower = issuer.lower()

        if subject and issuer and subject == issuer:
            findings.append(
                {
                    "id": "CERT_SELF_SIGNED",
                    "title": "Self-Signed Certificate Detected",
                    "severity": "low",
                    "evidence_type": "certificate",
                    "evidence": f"subject={subject}; issuer={issuer}",
                }
            )

        if signature_algorithm.lower() == "unknown":
            findings.append(
                {
                    "id": "CERT_UNKNOWN_SIGNATURE_ALGORITHM",
                    "title": "Unknown Certificate Signature Algorithm",
                    "severity": "low",
                    "evidence_type": "certificate",
                    "evidence": f"signature_algorithm={signature_algorithm}",
                }
            )

        for keyword in suspicious_certificate_keywords:
            if keyword in subject_lower or keyword in issuer_lower:
                findings.append(
                    {
                        "id": "CERT_SUSPICIOUS_SIGNING_KEYWORD",
                        "title": "Suspicious Certificate Signing Keyword Detected",
                        "severity": "medium",
                        "evidence_type": "certificate",
                        "evidence": f"keyword={keyword}",
                    }
                )
                break

    return findings