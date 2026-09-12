"""Evidence-backed forensic Markdown report generation."""
from __future__ import annotations
from datetime import datetime, timezone
from typing import List, Optional
from case.case_manager import Case
from intelligence.domain_intel import lookup_ip
from correlation.correlation_engine import build_attack_path
from provenance.origin_trace import explain_result


def generate_case_report(case: Case, shared_with: Optional[List[str]] = None) -> str:
    lines = [f"# LinkMirror X Forensic Report — {case.case_id}", f"_Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}_", ""]
    lines += [f"**Subject:** {case.parsed.subject}", f"**From:** {case.parsed.from_display_name} <{case.parsed.from_address}>", f"**Reply-To:** {case.parsed.reply_to or '(none)'}", f"**Case risk:** {case.risk.score if case.risk else 0}/100 ({case.risk.level.upper() if case.risk else 'PENDING'})", ""]
    lines += ["## 1. Evidence integrity", f"- Original email SHA-256: `{case.parsed.raw_bytes_sha256}`", f"- Source file: `{case.source_filename}`", ""]
    lines.append("## 2. Header forensics")
    lines += [f"- **{f.severity.upper()}** {f.message}" for f in case.header_findings] or ["No header anomalies detected by the current rules."]
    lines += ["", "## 3. Indicators", f"- URLs: {', '.join(case.indicators.urls) or 'none'}", f"- QR URLs: {', '.join(case.indicators.qr_urls) or 'none'}", f"- Domains: {', '.join(case.indicators.domains) or 'none'}", f"- IPs: {', '.join(case.indicators.ips) or 'none'}", ""]
    lines.append("## 4. Attachment triage")
    for att in case.parsed.attachments:
        lines.append(f"### {att.filename}")
        lines.append(f"- SHA-256: `{att.sha256}`")
        lines.append(f"- Type: {att.content_type}; Size: {att.size_bytes} bytes")
        for f in case.attachment_findings.get(att.sha256, []): lines.append(f"- **{f.severity.upper()}** {f.message}")
    if not case.parsed.attachments: lines.append("No attachments present.")
    lines += ["", "## 5. LinkMirror analysis"]
    for ua in case.url_analyses:
        lines += [f"### {ua.url}", f"- Source: {ua.source}", f"- URL trust: {ua.result.url_score}/100", f"- Visual similarity: {ua.result.screenshot_score:.1f}%" if ua.result.screenshot_score >= 0 else "- Visual similarity: unavailable", f"- **Verdict:** {ua.result.verdict}", f"- Fused trust: {ua.result.fused}/100"]
        lines += [f"  - {r}" for r in ua.result.verdict_reasons]
    lines += ["", "## 6. Infrastructure intelligence"]
    for ip in case.indicators.ips:
        intel = lookup_ip(ip); note = " (synthetic demo data)" if intel.is_demo else ""
        lines.append(f"- **{ip}** — {intel.org}, {intel.country}{note}")
    if not case.indicators.ips: lines.append("No IP addresses extracted.")
    lines += ["", "## 7. Attack path"]
    for i, step in enumerate(build_attack_path(case), 1): lines.append(f"{i}. **{step['stage']}** → {step['label']} — {step['evidence']}")
    lines += ["", "## 8. Correlation", "- Related cases: " + (", ".join(shared_with) if shared_with else "none currently known."), ""]
    lines += ["## 9. Explainable risk assessment", f"- Score: **{case.risk.score if case.risk else 0}/100**", f"- Level: **{case.risk.level.upper() if case.risk else 'PENDING'}**", f"- Explanation: {case.risk.explanation if case.risk else 'pending'}", ""]

    ot = case.origin_trace
    lines.append("## 10. OriginTrace forensic summary")
    if not ot:
        lines.append("OriginTrace analysis not available for this case.")
    else:
        top = ot.hypotheses[0]
        alt = ot.hypotheses[1:]
        lines += [
            f"- **Threat risk:** {ot.threat_risk}/100",
            f"- **Probable origin:** {top.label} (confidence {top.confidence}/100)",
            f"- **Origin confidence:** {ot.origin_confidence}/100",
        ]
        if ot.earliest_reliable_node.hop:
            h = ot.earliest_reliable_node.hop
            lines.append(f"- **Earliest reliable node:** Hop {h.index} — {h.from_host or 'unknown host'} ({h.from_ip or 'no IP'}), confidence {ot.earliest_reliable_node.confidence}/100")
        else:
            lines.append("- **Earliest reliable node:** none (no relay hops available)")
        if ot.breakpoint.detected:
            lines.append(f"- **Provenance breakpoint:** trust {ot.breakpoint.trust_before} → {ot.breakpoint.trust_after} between hop {ot.breakpoint.hop_before.index} and hop {ot.breakpoint.hop_after.index} (confidence {ot.breakpoint.confidence}/100)")
        else:
            lines.append("- **Provenance breakpoint:** none detected (no sharp trust drop)")
        lines.append(f"- **Most likely scenario:** {explain_result(ot)}")
        if alt:
            lines.append("- **Alternative hypotheses:**")
            for h in alt:
                lines.append(f"  - {h.label} ({h.confidence}/100)")
        lines.append("- **Evidence chain:**")
        for e in ot.evidence_chain:
            lines.append(f"  - {e}")
        lines.append("- **Limitations:**")
        for lim in ot.limitations:
            lines.append(f"  - {lim}")
    lines.append("")
    return "\n".join(lines)
