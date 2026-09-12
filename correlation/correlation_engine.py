"""Cross-case correlation, campaign DNA, and attack-path reconstruction."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Dict, Set
from collections import defaultdict
from ingestion.indicator_extractor import IndicatorSet

@dataclass
class CaseIndicators:
    case_id: str
    label: str
    indicators: IndicatorSet

@dataclass
class GraphNode:
    id: str
    type: str
    label: str

@dataclass
class GraphEdge:
    source: str
    target: str
    relation: str

@dataclass
class ThreatGraph:
    nodes: List[GraphNode] = field(default_factory=list)
    edges: List[GraphEdge] = field(default_factory=list)

@dataclass
class CampaignDNA:
    case_ids: List[str]
    shared_indicators: Dict[str, List[str]]
    target_domains: List[str]
    campaign_score: int
    summary: str


def build_threat_graph(cases: List[CaseIndicators]) -> ThreatGraph:
    graph, seen = ThreatGraph(), set()
    def add(nid, typ, label):
        if nid not in seen:
            graph.nodes.append(GraphNode(nid, typ, label)); seen.add(nid)
    for case in cases:
        cnode = f"case:{case.case_id}"; add(cnode, "case", case.label)
        for domain in case.indicators.domains:
            d = f"domain:{domain}"; add(d, "domain", domain); graph.edges.append(GraphEdge(cnode, d, "contains_link"))
        for ip in case.indicators.ips:
            i = f"ip:{ip}"; add(i, "ip", ip); graph.edges.append(GraphEdge(cnode, i, "infrastructure"))
            for domain in case.indicators.domains:
                graph.edges.append(GraphEdge(f"domain:{domain}", i, "resolves_to"))
        for addr in case.indicators.email_addresses:
            e = f"email:{addr}"; add(e, "email", addr); graph.edges.append(GraphEdge(cnode, e, "sender_or_recipient"))
    return graph


def find_shared_infrastructure(cases: List[CaseIndicators]) -> Dict[str, List[str]]:
    mapping = defaultdict(set)
    for c in cases:
        for ip in c.indicators.ips: mapping[f"ip:{ip}"].add(c.case_id)
        for d in c.indicators.domains: mapping[f"domain:{d}"].add(c.case_id)
        for h in c.indicators.attachment_hashes: mapping[f"sha256:{h}"].add(c.case_id)
    return {k: sorted(v) for k, v in mapping.items() if len(v) >= 2}


def build_campaign_dna(cases: List[CaseIndicators]) -> CampaignDNA:
    shared = find_shared_infrastructure(cases)
    case_ids = sorted({cid for ids in shared.values() for cid in ids})
    targets = sorted({d for c in cases if c.case_id in case_ids for d in c.indicators.domains})
    shared_count = len(shared)
    score = min(100, 50 + shared_count * 12 + max(0, len(case_ids) - 2) * 8) if shared else 0
    summary = (f"{len(case_ids)} case(s) form a potential campaign cluster through {shared_count} shared indicator(s)." if shared else "No cross-case campaign cluster identified.")
    return CampaignDNA(case_ids, shared, targets, score, summary)


def build_attack_path(case) -> List[dict]:
    steps = [{"stage":"Email", "label":case.parsed.subject, "evidence":"Original .eml evidence"}]
    steps.append({"stage":"Identity", "label":case.parsed.from_address or "Unknown sender", "evidence":f"{len(case.header_findings)} header finding(s)"})
    if case.indicators.qr_urls:
        steps.append({"stage":"QR / Quishing", "label":case.indicators.qr_urls[0], "evidence":f"{len(case.indicators.qr_urls)} QR destination(s) decoded"})
    elif case.indicators.urls:
        steps.append({"stage":"URL", "label":case.indicators.urls[0], "evidence":f"{len(case.indicators.urls)} URL(s) extracted"})
    if case.url_analyses:
        ua = max(case.url_analyses, key=lambda x: x.result.fused)
        steps.append({"stage":"Visual / URL analysis", "label":ua.result.verdict, "evidence":f"Trust {ua.result.fused:.1f}/100"})
    if case.indicators.domains:
        steps.append({"stage":"Domain", "label":case.indicators.domains[0], "evidence":"Extracted infrastructure indicator"})
    if case.indicators.ips:
        steps.append({"stage":"IP", "label":case.indicators.ips[0], "evidence":"Infrastructure pivot"})
    return steps
