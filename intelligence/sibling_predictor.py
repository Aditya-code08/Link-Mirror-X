"""
sibling_predictor.py

Proactive typosquat / sibling-domain prediction.

Everything else in this pipeline is REACTIVE: it judges a domain/URL you
already fed it (from an email, a QR code, an attachment). This module is
PROACTIVE: given ONE confirmed-malicious domain, it predicts the *other*
domains the same attacker probably also registered for the same campaign
-- before any of those siblings show up in an inbox or get reported.

Why this matters for an investigator: phishing kits are cheap to redeploy.
An attacker who registers "hdfc-secure-verify.com" very often *also*
registers "hdfc-secure-verify.com", "hdfc-secure-verify.net",
"secure-hdfc-verify.com", etc. in the same sitting, and rotates between
them as each gets blocklisted. Waiting for each one to be individually
reported means the investigator is always a step behind. This module
generates that sibling set and ranks candidates by how likely each is to
be part of the same campaign, so an analyst can pre-emptively check /
block them.

This is intentionally self-contained (no external API calls) so it works
offline in a demo: everything here is string-structure analysis, not a
live registrar/WHOIS lookup. Feed its output into domain_intel.lookup_ip
or a registrar API for real-world confirmation.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Set
import itertools
import re

# Characters commonly swapped in homoglyph / visual typosquats.
HOMOGLYPH_SUBS = {
    "o": ["0"], "0": ["o"],
    "i": ["1", "l"], "l": ["1", "i"], "1": ["i", "l"],
    "e": ["3"], "3": ["e"],
    "a": ["4", "@"],
    "s": ["5", "$"],
    "g": ["9"],
}

# TLDs frequently abused in phishing campaigns because they're cheap /
# loosely policed. This is a heuristic weight, not a blacklist.
RISKY_TLDS = {"xyz", "top", "click", "site", "online", "info", "tk", "cc"}

SUSPICIOUS_KEYWORDS = ["secure", "verify", "login", "update", "account", "confirm", "support", "signin"]


@dataclass
class SiblingCandidate:
    domain: str
    similarity: float          # 0-100, structural closeness to the seed domain
    reasons: List[str] = field(default_factory=list)


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cur[j] = min(
                prev[j] + 1,        # deletion
                cur[j - 1] + 1,     # insertion
                prev[j - 1] + (ca != cb),  # substitution
            )
        prev = cur
    return prev[-1]


def _strip_tld(domain: str) -> tuple[str, str]:
    parts = domain.lower().strip().split(".")
    if len(parts) < 2:
        return domain.lower(), ""
    return ".".join(parts[:-1]), parts[-1]


def generate_candidates(seed_domain: str, brand_keyword: str | None = None) -> List[str]:
    """
    Generate plausible sibling domains an attacker might register alongside
    seed_domain for the same campaign: homoglyph swaps, hyphen shuffles,
    keyword reordering, and TLD variants.
    """
    name, tld = _strip_tld(seed_domain)
    candidates: Set[str] = set()

    # 1. Homoglyph character substitution (one swap at a time).
    for i, ch in enumerate(name):
        for sub in HOMOGLYPH_SUBS.get(ch, []):
            candidates.add(name[:i] + sub + name[i + 1:] + "." + tld)

    # 2. Hyphen insertion / removal around suspicious keywords.
    tokens = re.split(r"[-]", name)
    if len(tokens) > 1:
        candidates.add("".join(tokens) + "." + tld)          # remove hyphens
        candidates.add("-".join(reversed(tokens)) + "." + tld)  # reorder
    else:
        for kw in SUSPICIOUS_KEYWORDS:
            if kw in name and kw != name:
                candidates.add(name.replace(kw, f"{kw}-") + "." + tld)

    # 3. Brand-keyword recombination, if a brand is known.
    if brand_keyword:
        brand = brand_keyword.lower()
        for kw in SUSPICIOUS_KEYWORDS:
            candidates.add(f"{brand}-{kw}.{tld}")
            candidates.add(f"{kw}-{brand}.{tld}")

    # 4. Same name, other commonly-abused TLDs.
    for alt_tld in RISKY_TLDS | {"com", "net", "org"}:
        if alt_tld != tld:
            candidates.add(f"{name}.{alt_tld}")

    candidates.discard(seed_domain.lower())
    return sorted(candidates)


def score_candidate(seed_domain: str, candidate: str) -> SiblingCandidate:
    """
    Score how likely `candidate` is a sibling of `seed_domain` in the same
    campaign. Pure structural heuristic -- combine with a real registrar
    lookup (creation date, registrant, nameservers) for a real verdict.
    """
    seed_name, seed_tld = _strip_tld(seed_domain)
    cand_name, cand_tld = _strip_tld(candidate)

    reasons = []
    dist = _levenshtein(seed_name, cand_name)
    max_len = max(len(seed_name), len(cand_name), 1)
    name_similarity = max(0.0, 100.0 * (1 - dist / max_len))

    score = name_similarity
    if dist == 0:
        reasons.append("Identical name to the confirmed domain (TLD/keyword variant only)")
    elif dist == 1:
        reasons.append("Only 1 character different from the confirmed domain (likely homoglyph/typo)")
    elif dist <= 3:
        reasons.append(f"{dist}-character edit distance from the confirmed domain")

    if cand_tld != seed_tld:
        if cand_tld in RISKY_TLDS:
            score += 5
            reasons.append(f".{cand_tld} is a commonly-abused TLD for disposable phishing sites")
        else:
            reasons.append(f"Same name, different TLD (.{cand_tld} vs .{seed_tld})")

    if any(kw in cand_name for kw in SUSPICIOUS_KEYWORDS):
        score += 5
        reasons.append("Contains a credential-harvesting keyword (verify/secure/login/etc.)")

    score = min(100.0, round(score, 1))
    return SiblingCandidate(domain=candidate, similarity=score, reasons=reasons)


def predict_siblings(seed_domain: str, brand_keyword: str | None = None,
                      known_domains: List[str] | None = None, top_n: int = 10) -> List[SiblingCandidate]:
    """
    Main entry point. Returns the top_n most likely sibling domains for a
    confirmed-malicious seed_domain, ranked highest-risk first.

    known_domains: optionally pass in domains already seen across other
    cases (e.g. from correlation_engine.find_shared_infrastructure) so
    they get flagged as CONFIRMED overlaps rather than just predicted.
    """
    candidates = generate_candidates(seed_domain, brand_keyword)
    known_set = {d.lower() for d in (known_domains or [])}

    scored = []
    for c in candidates:
        result = score_candidate(seed_domain, c)
        if c.lower() in known_set:
            result.similarity = 100.0
            result.reasons.insert(0, "Already observed in another case in this investigation")
        scored.append(result)

    scored.sort(key=lambda x: x.similarity, reverse=True)
    return scored[:top_n]


if __name__ == "__main__":
    import sys
    seed = sys.argv[1] if len(sys.argv) > 1 else "hdfc-secure-verify.com"
    brand = sys.argv[2] if len(sys.argv) > 2 else "hdfc"
    print(f"Predicting siblings for: {seed}\n")
    for cand in predict_siblings(seed, brand_keyword=brand):
        print(f"  {cand.similarity:5.1f}  {cand.domain:35s}  {'; '.join(cand.reasons)}")
