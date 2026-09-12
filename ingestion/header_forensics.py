"""
header_forensics.py

Looks at the parsed email's headers and flags sender-identity anomalies:
  - From / Reply-To / Return-Path mismatches
  - Display-name spoofing (e.g. "PayPal Support" <random@gmail.com>)
  - SPF / DKIM / DMARC authentication results (parsed from the
    Authentication-Results header, which is what receiving mail
    servers stamp onto the message)
  - Received-chain hop count sanity check

This module takes a ParsedEmail (from eml_parser.py) and returns a
list of Finding objects, each with a severity and human-readable reason,
so the UI / report generator can show *why* something looks suspicious
rather than just a score.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import List
import re

from ingestion.eml_parser import ParsedEmail


@dataclass
class Finding:
    severity: str      # "info" | "warning" | "high"
    check: str          # short machine-readable name
    message: str         # human-readable explanation


KNOWN_BRAND_WORDS = [
    "paypal", "amazon", "microsoft", "google", "apple", "bank", "netflix",
    "facebook", "instagram", "hdfc", "sbi", "icici", "axis", "irs", "irctc",
]


def analyze_headers(parsed: ParsedEmail) -> List[Finding]:
    findings: List[Finding] = []

    findings.extend(_check_from_reply_to_mismatch(parsed))
    findings.extend(_check_display_name_spoofing(parsed))
    findings.extend(_check_authentication_results(parsed))
    findings.extend(_check_received_chain(parsed))

    return findings


def _check_from_reply_to_mismatch(parsed: ParsedEmail) -> List[Finding]:
    findings = []
    from_domain = _domain_of(parsed.from_address)

    if parsed.reply_to:
        reply_domain = _domain_of(parsed.reply_to)
        if reply_domain and from_domain and reply_domain != from_domain:
            findings.append(Finding(
                severity="high",
                check="reply_to_mismatch",
                message=(
                    f"Reply-To domain ('{reply_domain}') does not match "
                    f"From domain ('{from_domain}') — replies would be "
                    f"routed somewhere other than the apparent sender."
                ),
            ))

    if parsed.return_path:
        return_domain = _domain_of(parsed.return_path)
        if return_domain and from_domain and return_domain != from_domain:
            findings.append(Finding(
                severity="warning",
                check="return_path_mismatch",
                message=(
                    f"Return-Path domain ('{return_domain}') differs from "
                    f"From domain ('{from_domain}') — bounce handling is "
                    f"routed away from the apparent sender's domain."
                ),
            ))

    return findings


def _check_display_name_spoofing(parsed: ParsedEmail) -> List[Finding]:
    findings = []
    display = (parsed.from_display_name or "").lower()
    from_domain = (_domain_of(parsed.from_address) or "").lower()

    for brand in KNOWN_BRAND_WORDS:
        if brand in display and brand not in from_domain:
            findings.append(Finding(
                severity="high",
                check="display_name_spoofing",
                message=(
                    f"Display name references '{brand}' but the actual "
                    f"sending domain ('{from_domain}') has no relation to "
                    f"it — classic display-name impersonation."
                ),
            ))
            break  # one flag is enough, avoid duplicate noise

    return findings


def _check_authentication_results(parsed: ParsedEmail) -> List[Finding]:
    """
    Parses the Authentication-Results header if present. This header is
    added by the RECEIVING mail server, not the sender, so its presence
    and content is a reasonably trustworthy signal (can't be forged by
    the phisher without controlling the recipient's mail server).
    """
    findings = []
    auth_header = parsed.raw_headers.get("Authentication-Results", "")

    if not auth_header:
        findings.append(Finding(
            severity="warning",
            check="no_auth_results",
            message=(
                "No Authentication-Results header found — SPF/DKIM/DMARC "
                "outcome cannot be verified from this message."
            ),
        ))
        return findings

    for mechanism in ("spf", "dkim", "dmarc"):
        match = re.search(rf"{mechanism}=(\w+)", auth_header, re.IGNORECASE)
        if not match:
            continue
        result = match.group(1).lower()
        if result in ("fail", "softfail", "permerror"):
            findings.append(Finding(
                severity="high",
                check=f"{mechanism}_fail",
                message=f"{mechanism.upper()} check result: {result.upper()} — "
                        f"sending server failed to authenticate as this domain.",
            ))
        elif result == "none":
            findings.append(Finding(
                severity="warning",
                check=f"{mechanism}_none",
                message=f"{mechanism.upper()} not evaluated (no policy published or checked).",
            ))
        elif result == "pass":
            findings.append(Finding(
                severity="info",
                check=f"{mechanism}_pass",
                message=f"{mechanism.upper()} check passed.",
            ))

    return findings


def _check_received_chain(parsed: ParsedEmail) -> List[Finding]:
    findings = []
    hop_count = len(parsed.received_chain)

    if hop_count == 0:
        findings.append(Finding(
            severity="warning",
            check="no_received_headers",
            message="No Received headers present — routing history cannot be reconstructed.",
        ))
    elif hop_count == 1:
        findings.append(Finding(
            severity="info",
            check="single_hop",
            message="Only one Received hop — message may be locally injected or headers stripped.",
        ))

    return findings


def _domain_of(address: str) -> str:
    if not address or "@" not in address:
        return ""
    # strip display-name wrapper like "Name <addr@domain>" if present
    m = re.search(r"[\w\.\+\-]+@([\w\.\-]+)", address)
    return m.group(1).lower() if m else ""


if __name__ == "__main__":
    import sys
    import json
    from ingestion.eml_parser import parse_eml_file

    if len(sys.argv) != 2:
        print("Usage: python header_forensics.py <path_to.eml>")
        sys.exit(1)

    parsed = parse_eml_file(sys.argv[1])
    findings = analyze_headers(parsed)
    for f in findings:
        print(f"[{f.severity.upper():7}] {f.check}: {f.message}")
