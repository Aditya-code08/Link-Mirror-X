"""IOC extraction from text, headers, and decoded QR destinations."""
from __future__ import annotations
from dataclasses import dataclass, field
import re
import urllib.parse
from ingestion.eml_parser import ParsedEmail
from ingestion.qr_detector import QRFinding

URL_REGEX = re.compile(r'https?://[^\s<>"\'\)\]]+', re.IGNORECASE)
IP_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
EMAIL_REGEX = re.compile(r'[\w.\+\-]+@[\w\-]+(?:\.[\w\-]+)+')

@dataclass
class IndicatorSet:
    urls: List[str] = field(default_factory=list)
    qr_urls: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)
    email_addresses: List[str] = field(default_factory=list)
    attachment_hashes: List[str] = field(default_factory=list)


def extract_indicators(parsed: ParsedEmail, qr_findings: List[QRFinding] | None = None) -> IndicatorSet:
    combined = "\n".join([parsed.body_text, parsed.body_html, *(str(v) for v in parsed.raw_headers.values())])
    text_urls = {u.rstrip(".,;:") for u in URL_REGEX.findall(combined)}
    qr_urls = {q.decoded for q in (qr_findings or []) if q.success and q.decoded.startswith(("http://", "https://"))}
    all_urls = sorted(text_urls | qr_urls)
    domains = sorted({_domain_from_url(u) for u in all_urls if _domain_from_url(u)})
    ips = sorted(set(IP_REGEX.findall(combined)))
    emails = set(EMAIL_REGEX.findall(combined))
    if parsed.from_address:
        emails.add(parsed.from_address)
    return IndicatorSet(
        urls=all_urls,
        qr_urls=sorted(qr_urls),
        domains=domains,
        ips=ips,
        email_addresses=sorted(emails),
        attachment_hashes=[a.sha256 for a in parsed.attachments],
    )


def _domain_from_url(url: str) -> str:
    try:
        return urllib.parse.urlparse(url).hostname.lower() if urllib.parse.urlparse(url).hostname else ""
    except Exception:
        return ""
