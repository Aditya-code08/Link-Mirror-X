"""Unified, explainable case-level risk scoring."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import List

@dataclass
class RiskEvidence:
    category: str
    severity: str
    weight: int
    message: str

@dataclass
class RiskAssessment:
    score: float
    level: str
    evidence: List[RiskEvidence] = field(default_factory=list)
    explanation: str = ""

SEVERITY_WEIGHT = {"high": 15, "warning": 8, "info": 1}


def assess_case_risk(header_findings, url_analyses, attachment_findings, qr_count: int, shared_indicator_count: int = 0) -> RiskAssessment:
    evidence: List[RiskEvidence] = []
    score = 0.0
    for f in header_findings:
        w = SEVERITY_WEIGHT.get(f.severity, 1)
        if f.severity != "info":
            evidence.append(RiskEvidence("identity/header", f.severity, w, f.message))
            score += w
    for ua in url_analyses:
        risk = max(0.0, 100.0 - float(ua.result.fused))
        if risk >= 60:
            evidence.append(RiskEvidence("URL/visual", "high", int(round(min(15, risk / 5))), f"URL/visual analysis is high risk ({ua.result.fused:.1f}/100 trust)."))
        elif risk >= 30:
            evidence.append(RiskEvidence("URL/visual", "warning", int(round(min(8, risk / 10))), f"URL/visual analysis is moderately suspicious ({ua.result.fused:.1f}/100 trust)."))
        score += min(15, risk / 5)
    for _, findings in attachment_findings.items():
        for f in findings:
            if f.severity != "info":
                evidence.append(RiskEvidence("attachment", f.severity, SEVERITY_WEIGHT.get(f.severity, 1), f.message))
                score += SEVERITY_WEIGHT.get(f.severity, 1)
    if qr_count:
        w = min(10, qr_count * 4)
        evidence.append(RiskEvidence("quishing", "warning", w, f"{qr_count} QR code destination(s) decoded from the email."))
        score += w
    if shared_indicator_count:
        w = min(20, shared_indicator_count * 8)
        evidence.append(RiskEvidence("correlation", "high", w, f"Shared infrastructure detected across {shared_indicator_count} other case relationship(s)."))
        score += w
    score = round(min(100.0, score), 1)
    level = "critical" if score >= 75 else "high" if score >= 50 else "medium" if score >= 25 else "low"
    ranked = sorted(evidence, key=lambda x: x.weight, reverse=True)
    reasons = "; ".join(e.message for e in ranked[:4])
    explanation = reasons or "No significant suspicious evidence was identified by the current rule set."
    return RiskAssessment(score, level, ranked, explanation)
