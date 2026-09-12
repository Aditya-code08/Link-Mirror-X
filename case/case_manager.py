"""End-to-end case orchestration with automatic and standalone LinkMirror modes."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import List
from pathlib import Path
import uuid

from ingestion.eml_parser import parse_eml_file, ParsedEmail
from ingestion.header_forensics import analyze_headers, Finding
from ingestion.indicator_extractor import extract_indicators, IndicatorSet
from ingestion.qr_detector import decode_qr_images, QRFinding
from ingestion.attachment_triage import analyze_attachments, AttachmentFinding
from engine.capture import get_webpage_screenshot
from engine.linkmirror_engine import analyze_url_and_screenshot, EngineResult
from core.risk_engine import assess_case_risk, RiskAssessment
from provenance.origin_trace import analyze_origin, OriginTraceResult

@dataclass
class UrlAnalysis:
    url: str
    source: str
    had_screenshot: bool
    result: EngineResult

@dataclass
class Case:
    case_id: str
    source_filename: str
    parsed: ParsedEmail
    header_findings: List[Finding]
    qr_findings: List[QRFinding]
    indicators: IndicatorSet
    attachment_findings: dict[str, List[AttachmentFinding]]
    url_analyses: List[UrlAnalysis] = field(default_factory=list)
    risk: RiskAssessment | None = None
    shared_relationships: int = 0
    origin_trace: OriginTraceResult | None = None

    @property
    def highest_severity(self) -> str:
        if self.risk:
            return self.risk.level
        levels = [f.severity for f in self.header_findings]
        return "high" if "high" in levels else "warning" if "warning" in levels else "info"

    @property
    def summary_line(self) -> str:
        risk = f"risk {self.risk.score:.0f}/100" if self.risk else "risk pending"
        return f"[{self.highest_severity.upper()}] {self.parsed.subject!r} — {risk}, {len(self.indicators.urls)} URL(s), {len(self.parsed.attachments)} attachment(s)"


def process_email(eml_path: str, reference_dir: str = "reference_images", capture_dir: str | None = None) -> Case:
    parsed = parse_eml_file(eml_path)
    headers = analyze_headers(parsed)
    qr_findings = decode_qr_images([*parsed.embedded_images, *parsed.attachments])
    indicators = extract_indicators(parsed, qr_findings)
    attachment_findings = analyze_attachments(parsed.attachments)

    url_analyses: List[UrlAnalysis] = []
    for url in indicators.urls:
        screenshot = get_webpage_screenshot(url, capture_dir) if capture_dir else get_webpage_screenshot(url)
        result = analyze_url_and_screenshot(url, screenshot, ref_dir=reference_dir)
        source = "QR" if url in indicators.qr_urls else "Email body/header"
        url_analyses.append(UrlAnalysis(url, source, screenshot is not None, result))

    case = Case(
        case_id=str(uuid.uuid4())[:8],
        source_filename=eml_path,
        parsed=parsed,
        header_findings=headers,
        qr_findings=qr_findings,
        indicators=indicators,
        attachment_findings=attachment_findings,
        url_analyses=url_analyses,
    )
    case.risk = assess_case_risk(headers, url_analyses, attachment_findings, len(qr_findings), 0)
    case.origin_trace = analyze_origin(parsed, headers, url_analyses)
    return case


def analyze_standalone_url(url: str, screenshot=None, reference_dir: str = "reference_images") -> EngineResult:
    return analyze_url_and_screenshot(url, screenshot, ref_dir=reference_dir)
