"""
AndroAI Sandbox - Network Intelligence

This module analyzes runtime network evidence collected during
dynamic analysis.

Milestone 2 scope:
- Analyze runtime network indicators
- Classify network protocols
- Detect encrypted communication indicators
- Summarize observed network behavior
- Produce analyst-friendly network intelligence
"""

from typing import Any


def analyze_network_intelligence(
    runtime_analysis: dict[str, Any],
) -> dict[str, Any]:
    """
    Analyze runtime network indicators.
    """

    indicators = runtime_analysis.get(
        "network_indicators",
        [],
    )

    http = []
    https = []
    dns = []
    sockets = []
    ssl_tls = []
    other = []

    for indicator in indicators:
        text = str(indicator).lower()

        if "https://" in text:
            https.append(indicator)

        elif "http://" in text:
            http.append(indicator)

        elif "dns" in text:
            dns.append(indicator)

        elif "socket" in text:
            sockets.append(indicator)

        elif any(
            keyword in text
            for keyword in (
                "ssl",
                "tls",
                "certificate",
                "x509",
            )
        ):
            ssl_tls.append(indicator)

        else:
            other.append(indicator)

    return {
        "success": True,
        "total_network_indicators": len(indicators),
        "http_count": len(http),
        "https_count": len(https),
        "dns_count": len(dns),
        "socket_count": len(sockets),
        "ssl_tls_count": len(ssl_tls),
        "other_count": len(other),
        "http": http[:20],
        "https": https[:20],
        "dns": dns[:20],
        "sockets": sockets[:20],
        "ssl_tls": ssl_tls[:20],
        "other": other[:20],
        "network_flags": {
            "network_activity_detected": len(indicators) > 0,
            "encrypted_traffic_detected": (
                len(https) > 0
                or len(ssl_tls) > 0
            ),
            "dns_activity_detected": len(dns) > 0,
            "socket_activity_detected": len(sockets) > 0,
        },
        "message": "Network intelligence analyzed successfully.",
    }