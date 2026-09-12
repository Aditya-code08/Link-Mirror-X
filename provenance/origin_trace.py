"""
origin_trace.py — OriginTrace AI intelligence module.

LinkMirror X (the rest of this platform) answers "is this a threat?".
OriginTrace answers a different question: "where did this message
actually come from, and at what point can we no longer trust the
evidence?"

It works entirely from data LinkMirror X already has -- the parsed
email's Received chain, the header-forensics findings (SPF/DKIM/DMARC,
display-name/reply-to checks), the IP/domain intelligence lookups, and
(optionally) the URL/visual verdicts already computed for this case. It
does not call out to any external service and does not invent facts:
every conclusion is traceable to a specific parsed header or an existing
finding, and gaps in the evidence are reported as gaps, not guessed at.

Pipeline:
    reconstruct_relay_path()   -- parse Received headers into ordered hops
    score_hop()                -- 0-100 trust score per hop, with reasons
    find_provenance_breakpoint() -- where trust drops hardest along the chain
    find_earliest_reliable_node() -- earliest hop still worth trusting
    rank_origin_hypotheses()   -- score 4 candidate explanations
    analyze_origin()           -- runs the whole pipeline, returns OriginTraceResult
    explain_result()           -- deterministic natural-language summary of the
                                   above (this is the "AI/LLM layer" hook -- see
                                   note in that function)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from email.utils import parsedate_to_datetime
from typing import List, Optional

from ingestion.header_forensics import Finding
from ingestion.eml_parser import ParsedEmail
from intelligence.domain_intel import lookup_ip, IpIntel

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

IP_RE = re.compile(r"\[?((?:\d{1,3}\.){3}\d{1,3})\]?")
FROM_HOST_RE = re.compile(r"\bfrom\s+([^\s;]+)", re.IGNORECASE)
BY_HOST_RE = re.compile(r"\bby\s+([^\s;]+)", re.IGNORECASE)
PROTOCOL_RE = re.compile(r"\bwith\s+([A-Za-z0-9/.\-]+)", re.IGNORECASE)

VPS_HOSTNAME_HINTS = ["vps", "cloud", "compute", "linode", "digitalocean", "ovh", "vultr", "hetzner", "amazonaws", "azure"]
RESIDENTIAL_HINTS = ["dyn", "dsl", "cable", "pool", "dhcp", "res.", "broadband"]
WEBMAIL_HINTS = ["outlook.com", "gmail.com", "yahoo.com", "office365", "google.com", "protonmail"]


@dataclass
class RelayHop:
    index: int                     # 1 = earliest observed hop, increasing toward recipient
    raw_header: str
    from_host: Optional[str]
    from_ip: Optional[str]
    by_host: Optional[str]
    protocol: Optional[str]
    timestamp: Optional[datetime]
    timestamp_raw: Optional[str]
    ip_intel: Optional[IpIntel] = None
    trust_score: int = 50
    trust_reasons: List[str] = field(default_factory=list)
    parse_issues: List[str] = field(default_factory=list)


@dataclass
class ProvenanceBreakpoint:
    hop_before: Optional[RelayHop]
    hop_after: Optional[RelayHop]
    trust_before: int
    trust_after: int
    confidence: int                # 0-100, confidence that THIS is the real breakpoint
    evidence: List[str]

    @property
    def detected(self) -> bool:
        return self.hop_after is not None and (self.trust_before - self.trust_after) >= 20


@dataclass
class EarliestReliableNode:
    hop: Optional[RelayHop]
    confidence: int
    note: str


@dataclass
class OriginHypothesis:
    label: str
    confidence: int                # 0-100
    supporting_evidence: List[str] = field(default_factory=list)
    contradicting_evidence: List[str] = field(default_factory=list)


@dataclass
class OriginTraceResult:
    hops: List[RelayHop]
    breakpoint: ProvenanceBreakpoint
    earliest_reliable_node: EarliestReliableNode
    hypotheses: List[OriginHypothesis]     # sorted, highest confidence first
    threat_risk: int                        # 0-100
    origin_confidence: int                  # 0-100 -- confidence in the TOP hypothesis
    evidence_chain: List[str]               # every conclusion traced to its source
    limitations: List[str]                  # explicit gaps / things we could NOT determine


# ---------------------------------------------------------------------------
# 1. Relay path reconstruction
# ---------------------------------------------------------------------------

def _parse_hop(raw: str, index: int) -> RelayHop:
    issues: List[str] = []
    ip_match = IP_RE.search(raw)
    from_match = FROM_HOST_RE.search(raw)
    by_match = BY_HOST_RE.search(raw)
    proto_match = PROTOCOL_RE.search(raw)

    from_host = from_match.group(1).rstrip(",;") if from_match else None
    by_host = by_match.group(1).rstrip(",;") if by_match else None
    protocol = proto_match.group(1) if proto_match else None
    from_ip = ip_match.group(1) if ip_match else None

    if not from_host:
        issues.append("could not identify a 'from' host in this hop")
    if not from_ip:
        issues.append("no IPv4 address found in this hop (IPv6-only, or stripped)")
    if not by_host:
        issues.append("could not identify a 'by' (receiving) host in this hop")

    timestamp = None
    timestamp_raw = None
    if ";" in raw:
        timestamp_raw = raw.rsplit(";", 1)[-1].strip()
        try:
            timestamp = parsedate_to_datetime(timestamp_raw)
        except Exception:
            issues.append(f"timestamp '{timestamp_raw}' could not be parsed")
    else:
        issues.append("no ';' timestamp section found in this hop")

    return RelayHop(
        index=index,
        raw_header=raw,
        from_host=from_host,
        from_ip=from_ip,
        by_host=by_host,
        protocol=protocol,
        timestamp=timestamp,
        timestamp_raw=timestamp_raw,
        parse_issues=issues,
    )


def reconstruct_relay_path(parsed: ParsedEmail) -> List[RelayHop]:
    """
    parsed.received_chain is in header order: index 0 is the hop closest to
    the recipient (added last), the final entry is the hop closest to the
    origin (added first). We reverse it so hop 1 = earliest observed = the
    starting point of the journey, matching how an investigator reads it.
    """
    raw_hops = list(reversed(parsed.received_chain or []))
    return [_parse_hop(raw, i + 1) for i, raw in enumerate(raw_hops)]


# ---------------------------------------------------------------------------
# 2. Per-hop trust scoring
# ---------------------------------------------------------------------------

def score_hop(hop: RelayHop, prev_hop: Optional[RelayHop], auth_findings: List[Finding]) -> None:
    """Mutates hop.trust_score and hop.trust_reasons in place."""
    score = 70  # neutral starting point; hop.parse_issues and checks below adjust it
    reasons: List[str] = []

    # -- Parse completeness --
    if hop.parse_issues:
        penalty = min(25, 8 * len(hop.parse_issues))
        score -= penalty
        reasons.append(f"{len(hop.parse_issues)} field(s) missing/malformed in this hop ({'; '.join(hop.parse_issues)})")

    # -- IP/hostname/reverse-DNS consistency & infrastructure reputation --
    if hop.from_ip:
        hop.ip_intel = lookup_ip(hop.from_ip)
        if hop.ip_intel.lookup_succeeded:
            org = (hop.ip_intel.org or "").lower()
            if any(h in org for h in VPS_HOSTNAME_HINTS):
                score -= 15
                reasons.append(f"originating IP is hosted by a VPS/cloud provider ({hop.ip_intel.org}) rather than an ISP/mail provider — common for disposable sending infrastructure")
            elif hop.ip_intel.is_demo:
                reasons.append("synthetic demo IP range — infrastructure reputation unavailable (not a real lookup)")
        else:
            score -= 4
            reasons.append("IP intelligence lookup unavailable for this hop's IP (no network reachability at analysis time) — cannot verify hosting/ASN reputation; treated as a soft signal, not a hard anomaly")
    else:
        score -= 5

    if hop.from_host:
        host_l = hop.from_host.lower()
        if any(h in host_l for h in RESIDENTIAL_HINTS):
            score -= 10
            reasons.append(f"hostname pattern ('{hop.from_host}') looks like a dynamic/residential address, not a mail server")
        if any(h in host_l for h in VPS_HOSTNAME_HINTS):
            score -= 10
            reasons.append(f"hostname pattern ('{hop.from_host}') matches known VPS/cloud naming conventions")
        if any(h in host_l for h in WEBMAIL_HINTS):
            score += 5
            reasons.append(f"hostname ('{hop.from_host}') matches a known webmail/legitimate provider pattern")

    # -- Timestamp anomalies (monotonicity moving toward the recipient) --
    if prev_hop and hop.timestamp and prev_hop.timestamp:
        if hop.timestamp < prev_hop.timestamp:
            score -= 20
            reasons.append(
                f"timestamp ({hop.timestamp_raw}) is EARLIER than the previous hop's timestamp "
                f"({prev_hop.timestamp_raw}) — relay chain is not chronologically consistent"
            )
    elif prev_hop and (not hop.timestamp or not prev_hop.timestamp):
        reasons.append("cannot verify chronological consistency with the previous hop — one or both timestamps missing/unparseable")

    # -- From/by host consistency with the next declared hop (chain continuity) --
    if prev_hop and prev_hop.by_host and hop.from_host:
        if prev_hop.by_host.lower() not in (hop.from_host or "").lower() and hop.from_host.lower() not in (prev_hop.by_host or "").lower():
            # Not necessarily wrong (real chains often show slightly different names for the same box),
            # so this is a soft signal, not a hard penalty.
            reasons.append(f"receiving host of the earlier hop ('{prev_hop.by_host}') does not textually match the sending host of this hop ('{hop.from_host}') — could be normal MTA renaming or could indicate a gap")

    # -- SPF/DKIM/DMARC (applies to the message as a whole; weighted onto the
    #    origin-most hop, since that's the identity the auth check is about) --
    if hop.index == 1:
        for f in auth_findings:
            if f.check.endswith("_fail"):
                score -= 15
                reasons.append(f"{f.check.split('_')[0].upper()} authentication FAILED for this message — undermines trust in the claimed origin identity")
            elif f.check == "no_auth_results":
                score -= 8
                reasons.append("no Authentication-Results header at all — origin identity cannot be authenticated")
            elif f.check.endswith("_pass"):
                score += 5
                reasons.append(f"{f.check.split('_')[0].upper()} authentication PASSED — receiving server verified this hop's claimed identity")

    hop.trust_score = max(0, min(100, score))
    hop.trust_reasons = reasons


def score_all_hops(hops: List[RelayHop], auth_findings: List[Finding]) -> None:
    prev = None
    for hop in hops:
        score_hop(hop, prev, auth_findings)
        prev = hop


# ---------------------------------------------------------------------------
# 3. Provenance breakpoint
# ---------------------------------------------------------------------------

def find_provenance_breakpoint(hops: List[RelayHop]) -> ProvenanceBreakpoint:
    if len(hops) < 2:
        return ProvenanceBreakpoint(
            hop_before=hops[0] if hops else None, hop_after=None,
            trust_before=hops[0].trust_score if hops else 0, trust_after=0,
            confidence=0,
            evidence=["Fewer than 2 relay hops available — no chain to find a breakpoint within."],
        )

    biggest_drop = float("-inf")
    biggest_idx = 1
    for i in range(1, len(hops)):
        drop = hops[i - 1].trust_score - hops[i].trust_score
        if drop > biggest_drop:
            biggest_drop = drop
            biggest_idx = i

    before = hops[biggest_idx - 1]
    after = hops[biggest_idx]
    confidence = max(0, min(100, biggest_drop * 2)) if biggest_drop > 0 else 0
    evidence = [
        f"Hop {before.index} (trust {before.trust_score}/100) → Hop {after.index} (trust {after.trust_score}/100): drop of {max(0, biggest_drop)} points.",
    ]
    evidence.extend(f"Hop {after.index} reasons: {r}" for r in after.trust_reasons[:3])

    return ProvenanceBreakpoint(
        hop_before=before, hop_after=after,
        trust_before=before.trust_score, trust_after=after.trust_score,
        confidence=confidence, evidence=evidence,
    )


# ---------------------------------------------------------------------------
# 4. Earliest reliable node
# ---------------------------------------------------------------------------

def find_earliest_reliable_node(hops: List[RelayHop], trust_threshold: int = 55) -> EarliestReliableNode:
    if not hops:
        return EarliestReliableNode(hop=None, confidence=0, note="No relay hops were present to examine.")

    for hop in hops:  # earliest first
        if hop.trust_score >= trust_threshold:
            confidence = min(95, hop.trust_score)  # never claim full certainty
            return EarliestReliableNode(
                hop=hop, confidence=confidence,
                note=(
                    f"Earliest hop we could observe evidence for that still meets the trust threshold "
                    f"({trust_threshold}/100). This is the earliest OBSERVED trustworthy point in the chain — "
                    f"it is NOT necessarily the attacker, and any earlier hops in the true delivery path may not "
                    f"appear in this message's headers at all."
                ),
            )

    # nothing met the threshold
    weakest_but_earliest = hops[0]
    return EarliestReliableNode(
        hop=weakest_but_earliest, confidence=max(10, weakest_but_earliest.trust_score // 2),
        note=(
            "No hop in this chain reached the trust threshold — every observed hop shows some anomaly. "
            "The earliest hop is shown anyway for reference, but confidence in it as a genuine origin point is low."
        ),
    )


# ---------------------------------------------------------------------------
# 5. Origin hypothesis engine
# ---------------------------------------------------------------------------

def rank_origin_hypotheses(hops: List[RelayHop], auth_findings: List[Finding],
                            header_findings: List[Finding], url_high_risk: bool) -> List[OriginHypothesis]:
    spf_dkim_fail = any(f.check.endswith("_fail") for f in auth_findings)
    spf_dkim_pass = any(f.check.endswith("_pass") for f in auth_findings)
    display_spoof = any(f.check == "display_name_spoofing" for f in header_findings)
    reply_mismatch = any(f.check == "reply_to_mismatch" for f in header_findings)

    origin_hop = hops[0] if hops else None
    origin_is_vps = bool(origin_hop and origin_hop.ip_intel and origin_hop.ip_intel.lookup_succeeded
                          and any(h in (origin_hop.ip_intel.org or "").lower() for h in VPS_HOSTNAME_HINTS))
    origin_lookup_failed = bool(origin_hop and origin_hop.ip_intel and not origin_hop.ip_intel.lookup_succeeded)
    origin_is_webmail = bool(origin_hop and origin_hop.from_host and any(h in origin_hop.from_host.lower() for h in WEBMAIL_HINTS))

    hypotheses = []

    # -- Spoofed Identity --
    support, contra = [], []
    score = 20
    if spf_dkim_fail:
        score += 30; support.append("SPF/DKIM/DMARC authentication failed for the claimed sending domain.")
    if display_spoof:
        score += 20; support.append("Display name impersonates a known brand not matching the sending domain.")
    if reply_mismatch:
        score += 10; support.append("Reply-To domain differs from the From domain.")
    if spf_dkim_pass:
        score -= 25; contra.append("SPF/DKIM/DMARC PASSED — the sending server successfully authenticated as the claimed domain, which is hard to fake without infrastructure control.")
    hypotheses.append(OriginHypothesis("Spoofed Identity", max(0, min(100, score)), support, contra))

    # -- Compromised Account --
    support, contra = [], []
    score = 15
    if spf_dkim_pass and origin_is_webmail:
        score += 35; support.append("Message authenticated successfully AND originated from a recognizable webmail/legitimate-provider hostname — consistent with a real account sending through its normal provider.")
    elif spf_dkim_pass:
        score += 15; support.append("Message authenticated successfully via the legitimate provider's infrastructure.")
    if origin_is_vps:
        score -= 15; contra.append("Origin hop is VPS/cloud infrastructure, not a typical webmail client path.")
    if spf_dkim_fail:
        score -= 20; contra.append("Authentication failed — a compromised legitimate account would normally still pass SPF/DKIM via its real provider.")
    hypotheses.append(OriginHypothesis("Compromised Account", max(0, min(100, score)), support, contra))

    # -- Anonymized Infrastructure --
    support, contra = [], []
    score = 15
    if origin_lookup_failed:
        score += 10; support.append("Origin IP could not be resolved to any organization/ASN at analysis time — a soft signal consistent with (but not proof of) anonymization; could also just mean no network reachability during this analysis run.")
    if origin_hop and len(origin_hop.parse_issues) >= 2:
        score += 15; support.append("Origin hop's header fields were largely missing or malformed, consistent with deliberately sparse relay information.")
    if origin_is_webmail:
        score -= 20; contra.append("Origin hostname matches a known legitimate provider, which is inconsistent with anonymized infrastructure.")
    hypotheses.append(OriginHypothesis("Anonymized Infrastructure", max(0, min(100, score)), support, contra))

    # -- Direct Malicious Infrastructure --
    support, contra = [], []
    score = 15
    if origin_is_vps:
        score += 20; support.append("Origin IP is hosted on VPS/cloud infrastructure commonly rented for short-lived sending operations.")
    if spf_dkim_fail:
        score += 15; support.append("Authentication failure is consistent with infrastructure the attacker fully controls (no need to pass legitimate auth).")
    if url_high_risk:
        score += 25; support.append("This case's URL/visual analysis already returned a high-risk verdict, consistent with attacker-owned infrastructure being used end-to-end.")
    if spf_dkim_pass:
        score -= 20; contra.append("Authentication passed, which is unusual (though not impossible) for infrastructure entirely outside any legitimate provider's control.")
    hypotheses.append(OriginHypothesis("Direct Malicious Infrastructure", max(0, min(100, score)), support, contra))

    hypotheses.sort(key=lambda h: h.confidence, reverse=True)
    return hypotheses


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def analyze_origin(parsed: ParsedEmail, header_findings: List[Finding],
                    url_analyses: Optional[list] = None) -> OriginTraceResult:
    hops = reconstruct_relay_path(parsed)
    auth_findings = [f for f in header_findings if f.check.endswith(("_fail", "_pass", "_none")) or f.check == "no_auth_results"]
    score_all_hops(hops, auth_findings)

    breakpoint = find_provenance_breakpoint(hops)
    earliest = find_earliest_reliable_node(hops)

    url_high_risk = bool(url_analyses) and any(getattr(u.result, "fused", 100) < 40 for u in url_analyses)
    hypotheses = rank_origin_hypotheses(hops, auth_findings, header_findings, url_high_risk)

    limitations = []
    if not hops:
        limitations.append("No Received headers were present at all — no relay journey could be reconstructed. All conclusions below are based solely on message-level identity/authentication headers.")
    else:
        total_issues = sum(len(h.parse_issues) for h in hops)
        if total_issues:
            limitations.append(f"{total_issues} parsing issue(s) across {len(hops)} hop(s) — some fields could not be extracted from the raw headers (see per-hop notes).")
    if len(hops) <= 1:
        limitations.append("Fewer than 2 hops means the provenance breakpoint and earliest-reliable-node findings have very limited signal.")
    limitations.append("Received headers can themselves be forged by anyone who controls a hop before the FIRST hop your own trusted infrastructure added — OriginTrace can only reason about what is present in the message, not about hops that were stripped or never existed.")

    top = hypotheses[0]
    second = hypotheses[1] if len(hypotheses) > 1 else None
    gap = (top.confidence - second.confidence) if second else top.confidence
    origin_confidence = max(5, min(95, top.confidence - max(0, 20 - gap)))

    weakest_hop_score = min((h.trust_score for h in hops), default=50)
    threat_risk = max(0, min(100, round(
        0.6 * (100 - weakest_hop_score) + 0.4 * top.confidence * (1 if top.label != "Compromised Account" else 0.7)
    )))
    # Legitimate-looking chains (all high trust, top hypothesis isn't malicious-leaning) pull threat_risk down further.
    if weakest_hop_score >= 70 and top.label in ("Compromised Account",):
        threat_risk = min(threat_risk, 35)

    evidence_chain = []
    evidence_chain.append(f"Relay path: {len(hops)} hop(s) reconstructed from Received headers.")
    for h in hops:
        evidence_chain.append(f"Hop {h.index}: from={h.from_host or '?'} ip={h.from_ip or '?'} by={h.by_host or '?'} @ {h.timestamp_raw or '?'} → trust {h.trust_score}/100.")
    if breakpoint.detected:
        evidence_chain.append(f"Provenance breakpoint: trust fell from {breakpoint.trust_before} to {breakpoint.trust_after} between hop {breakpoint.hop_before.index} and hop {breakpoint.hop_after.index}.")
    else:
        evidence_chain.append("No sharp provenance breakpoint detected — trust degrades gradually or stays flat across the chain.")
    evidence_chain.append(f"Earliest reliable node: hop {earliest.hop.index if earliest.hop else 'none'} (confidence {earliest.confidence}/100).")
    evidence_chain.append(f"Top origin hypothesis: {top.label} ({top.confidence}/100 confidence).")

    return OriginTraceResult(
        hops=hops, breakpoint=breakpoint, earliest_reliable_node=earliest,
        hypotheses=hypotheses, threat_risk=threat_risk, origin_confidence=origin_confidence,
        evidence_chain=evidence_chain, limitations=limitations,
    )


# ---------------------------------------------------------------------------
# 9. AI explanation layer
# ---------------------------------------------------------------------------

def explain_result(result: OriginTraceResult) -> str:
    """
    Deterministic natural-language summary of the analysis above.

    NOTE ON THE "AI/LLM LAYER": this codebase does not currently wire up a
    live LLM API call anywhere (no OpenAI/Anthropic/etc. client exists in
    the project). Rather than fabricate an integration, this function
    produces the explanation directly from the deterministic findings using
    templated language -- it summarizes and never introduces a fact that
    isn't already in `result`. If/when a real LLM call is added elsewhere
    in the project, swap the return statement here for a call that passes
    this same templated summary (or the evidence_chain list) as the prompt
    context, so the model is strictly summarizing/explaining rather than
    inventing forensic facts.
    """
    top = result.hypotheses[0]
    lines = []
    lines.append(
        f"Most likely explanation: **{top.label}** (confidence {top.confidence}/100)."
    )
    if top.supporting_evidence:
        lines.append("Supporting evidence: " + " ".join(top.supporting_evidence))
    if top.contradicting_evidence:
        lines.append("Contradicting evidence: " + " ".join(top.contradicting_evidence))
    if result.breakpoint.detected:
        lines.append(
            f"Trust in the evidence trail drops sharply between hop {result.breakpoint.hop_before.index} "
            f"and hop {result.breakpoint.hop_after.index} (from {result.breakpoint.trust_before} to "
            f"{result.breakpoint.trust_after}/100) — this is the point past which the relay evidence "
            f"becomes unreliable."
        )
    else:
        lines.append("No single sharp trust drop was found; reliability degrades gradually or stays consistent across the observed hops.")
    if result.earliest_reliable_node.hop:
        h = result.earliest_reliable_node.hop
        lines.append(
            f"The earliest hop still worth trusting is hop {h.index} ({h.from_host or h.from_ip or 'unknown host'}), "
            f"at {result.earliest_reliable_node.confidence}/100 confidence — this is an observed data point, not a "
            f"claim about who the attacker is."
        )
    if result.limitations:
        lines.append("Limitations: " + " ".join(result.limitations))
    return " ".join(lines)


if __name__ == "__main__":
    import sys
    from ingestion.eml_parser import parse_eml_file
    from ingestion.header_forensics import analyze_headers

    if len(sys.argv) != 2:
        print("Usage: python origin_trace.py <path_to.eml>")
        sys.exit(1)

    parsed = parse_eml_file(sys.argv[1])
    headers = analyze_headers(parsed)
    result = analyze_origin(parsed, headers)

    print(f"Hops reconstructed: {len(result.hops)}")
    for h in result.hops:
        print(f"  [{h.index}] trust={h.trust_score:3d}  from={h.from_host}  ip={h.from_ip}  by={h.by_host}  @ {h.timestamp_raw}")
        for r in h.trust_reasons:
            print(f"        - {r}")
    print(f"\nBreakpoint detected: {result.breakpoint.detected}")
    if result.breakpoint.detected:
        print(f"  hop {result.breakpoint.hop_before.index} ({result.breakpoint.trust_before}) -> hop {result.breakpoint.hop_after.index} ({result.breakpoint.trust_after})")
    print(f"\nEarliest reliable node: hop {result.earliest_reliable_node.hop.index if result.earliest_reliable_node.hop else None} (confidence {result.earliest_reliable_node.confidence})")
    print("\nHypotheses:")
    for h in result.hypotheses:
        print(f"  {h.confidence:3d}  {h.label}")
    print(f"\nThreat risk: {result.threat_risk}/100")
    print(f"Origin confidence: {result.origin_confidence}/100")
    print("\nExplanation:")
    print(explain_result(result))
