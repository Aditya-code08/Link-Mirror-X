"""LinkMirror X analysis engine.

Supports two entry points:
  1) independent URL / screenshot investigation
  2) automatic invocation from the email-forensics pipeline

The visual engine preserves the original ORB + ResNet comparison approach,
while the URL analyzer now uses a substantially stricter, explainable set of
structural, lexical, domain, encoding and authentication-context heuristics.
"""
from __future__ import annotations

import datetime
import ipaddress
import math
import os
import re
import tempfile
import urllib.parse
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

import cv2
import numpy as np
from PIL import Image
from sklearn.metrics.pairwise import cosine_similarity

tempfile.tempdir = tempfile.gettempdir()

try:
    import torch
    from torchvision import models, transforms
    TORCH_AVAILABLE = True
except Exception:
    TORCH_AVAILABLE = False

_resnet_model = None
_resnet_transform = None

SUSPICIOUS_TLDS = {
    "xyz", "top", "club", "click", "work", "party", "zip", "gq", "ml",
    "cf", "tk", "icu", "cam", "rest", "fit", "buzz", "live", "support",
}
SUSPICIOUS_TOKENS = {
    "login", "log-in", "signin", "sign-in", "verify", "verification", "secure",
    "security", "account", "update", "confirm", "confirmation", "bank", "billing",
    "payment", "invoice", "password", "credential", "wallet", "bonus", "reward",
    "refund", "suspended", "unlock", "authentication", "mfa", "otp", "free",
}
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "shorturl.at", "rebrand.ly", "rb.gy", "s.id", "lnkd.in",
}
BRAND_TERMS = {
    "paypal", "microsoft", "office", "outlook", "apple", "icloud", "amazon",
    "hdfc", "sbi", "icici", "axis", "google", "facebook", "instagram", "netflix",
    "linkedin", "dropbox", "adobe", "docusign", "dhl", "fedex", "upi", "paytm",
}


def _load_resnet_torch():
    global _resnet_model, _resnet_transform
    if _resnet_model is not None:
        return _resnet_model, _resnet_transform
    if not TORCH_AVAILABLE:
        return None, None
    try:
        weights = models.ResNet50_Weights.DEFAULT
        model = models.resnet50(weights=weights)
        model.eval()
        model = torch.nn.Sequential(*(list(model.children())[:-1]))
        transform = transforms.Compose([
            transforms.Resize((224, 224)),
            transforms.ToTensor(),
            transforms.Normalize(mean=[0.485, 0.456, 0.406],
                                 std=[0.229, 0.224, 0.225]),
        ])
        _resnet_model, _resnet_transform = model, transform
    except Exception:
        _resnet_model, _resnet_transform = None, None
    return _resnet_model, _resnet_transform


def compute_orb_similarity_cv(img_cv_q, img_cv_ref, nfeatures=1200) -> float:
    orb = cv2.ORB_create(nfeatures=nfeatures)
    kp1, des1 = orb.detectAndCompute(img_cv_q, None)
    kp2, des2 = orb.detectAndCompute(img_cv_ref, None)
    if des1 is None or des2 is None or not kp1 or not kp2:
        return 0.0
    bf = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=True)
    matches = bf.match(des1, des2)
    if not matches:
        return 0.0
    matches = sorted(matches, key=lambda m: m.distance)
    # Only retain reasonably strong keypoint matches. This makes the visual
    # score less optimistic when two images merely share generic UI texture.
    good = [m for m in matches if m.distance <= 55]
    denom = min(len(kp1), len(kp2))
    return len(good) / denom if denom else 0.0


def compute_resnet_similarity_pil(pil_q, pil_ref) -> float:
    model, transform = _load_resnet_torch()
    if model is None:
        return 0.0
    try:
        tq = transform(pil_q).unsqueeze(0)
        tr = transform(pil_ref).unsqueeze(0)
        with torch.no_grad():
            f_q = model(tq).cpu().numpy().reshape(1, -1)
            f_r = model(tr).cpu().numpy().reshape(1, -1)
        # Clamp because tiny floating point overshoots should never create
        # an impossible visual score.
        return float(max(-1.0, min(1.0, cosine_similarity(f_q, f_r)[0][0])))
    except Exception:
        return 0.0


@dataclass
class ScreenshotMatch:
    reference_name: str
    score_pct: float
    orb_similarity: float
    resnet_similarity: float
    fallback_similarity: float = 0.0


def _fallback_visual_similarity(pil_q: Image.Image, pil_ref: Image.Image) -> float:
    """Lightweight structural fallback when ResNet weights are unavailable."""
    q = np.array(pil_q.convert("RGB").resize((256, 256))).astype(np.float32) / 255.0
    r = np.array(pil_ref.convert("RGB").resize((256, 256))).astype(np.float32) / 255.0
    diff = np.mean(np.abs(q - r))
    return float(max(0.0, min(1.0, 1.0 - diff * 2.5)))


def analyze_screenshot_against_refs(
    pil_query: Image.Image, ref_dir: str = "reference_images"
) -> Tuple[Optional[str], float, List[ScreenshotMatch]]:
    if not os.path.isdir(ref_dir):
        raise FileNotFoundError(f"Reference directory not found: {ref_dir}")

    query_cv = np.array(pil_query.convert("RGB"))[:, :, ::-1]
    best_name = None
    best_score = -1.0
    results: List[ScreenshotMatch] = []

    for fname in os.listdir(ref_dir):
        if not fname.lower().endswith((".png", ".jpg", ".jpeg")):
            continue
        path = os.path.join(ref_dir, fname)
        try:
            ref_pil = Image.open(path).convert("RGB")
        except Exception:
            continue
        ref_cv = np.array(ref_pil)[:, :, ::-1]
        try:
            orb_sim = compute_orb_similarity_cv(query_cv, ref_cv)
        except Exception:
            orb_sim = 0.0
        try:
            resnet_sim = compute_resnet_similarity_pil(pil_query, ref_pil)
        except Exception:
            resnet_sim = 0.0

        orb_sim = max(0.0, min(1.0, orb_sim))
        resnet_sim = max(0.0, min(1.0, resnet_sim))
        fallback_sim = 0.0
        if resnet_sim <= 0.0:
            fallback_sim = _fallback_visual_similarity(pil_query, ref_pil)
            combined = 0.4 * orb_sim + 0.6 * fallback_sim
        else:
            combined = 0.4 * orb_sim + 0.6 * resnet_sim
        score_pct = combined * 100
        results.append(ScreenshotMatch(fname, round(score_pct, 2), orb_sim, resnet_sim, fallback_sim))
        if score_pct > best_score:
            best_score = score_pct
            best_name = fname

    results.sort(key=lambda r: r.score_pct, reverse=True)
    return best_name, round(max(best_score, 0.0), 2), results


def _normalize_url(url: str) -> str:
    raw = (url or "").strip()
    if not raw:
        return ""
    if not re.match(r"^[a-z][a-z0-9+.-]*://", raw, re.I):
        raw = "http://" + raw
    return raw


def _registrable_domain(hostname: str) -> str:
    try:
        import tldextract
        ext = tldextract.extract(hostname)
        return ".".join([p for p in (ext.domain, ext.suffix) if p])
    except Exception:
        parts = hostname.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else hostname


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {c: value.count(c) for c in set(value)}
    total = len(value)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def _domain_age_days(hostname: str) -> Optional[int]:
    try:
        import whois
        w = whois.whois(hostname)
        cd = w.creation_date
        if isinstance(cd, list):
            cd = next((x for x in cd if x), None)
        if not cd:
            return None
        if getattr(cd, "tzinfo", None):
            now = datetime.datetime.now(cd.tzinfo)
        else:
            now = datetime.datetime.now()
        return max(0, (now - cd).days)
    except Exception:
        return None


def analyze_url_heuristic(url: str) -> Tuple[int, List[str]]:
    """Strict URL trust scoring. Higher = safer.

    The scoring intentionally penalizes structural red flags more strongly than
    the legacy implementation. It is heuristic evidence, not a definitive claim
    that a URL is malicious.
    """
    reasons: List[str] = []
    score = 100
    raw = (url or "").strip()
    if not raw:
        return 0, ["No URL provided."]

    normalized = _normalize_url(raw)
    try:
        parsed = urllib.parse.urlsplit(normalized)
        host = (parsed.hostname or "").lower().rstrip(".")
    except Exception:
        return 0, ["URL could not be parsed safely."]

    if parsed.scheme not in {"http", "https"} or not host:
        return 10, ["Invalid or unsupported URL structure."]

    # HTTPS is necessary but absolutely not sufficient.
    if parsed.scheme == "https":
        reasons.append("HTTPS present (+ context, not a trust guarantee)")
    else:
        score -= 18
        reasons.append("No HTTPS: traffic is not protected by TLS (-18)")

    # Host is an IPv4/IPv6 literal instead of a normal domain.
    try:
        ipaddress.ip_address(host)
        score -= 20
        reasons.append(f"IP-literal host detected ({host}) (-20)")
    except ValueError:
        pass

    # Userinfo / @ is a classic deception pattern.
    if parsed.username or parsed.password or "@" in parsed.netloc:
        score -= 25
        reasons.append("Embedded userinfo/@ symbol can disguise the real destination (-25)")

    # Punycode / IDN signal.
    if "xn--" in host:
        score -= 20
        reasons.append("Punycode/IDN hostname detected; visually deceptive domains are possible (-20)")

    registered = _registrable_domain(host)
    labels = [x for x in host.split(".") if x]
    subdomain_depth = max(0, len(labels) - 2)
    if subdomain_depth >= 3:
        score -= 14
        reasons.append(f"Deep subdomain structure ({subdomain_depth} subdomain levels) (-14)")
    elif subdomain_depth == 2:
        score -= 7
        reasons.append("Multiple subdomain levels detected (-7)")

    hyphens = host.count("-")
    if hyphens >= 3:
        score -= 10
        reasons.append(f"Host contains {hyphens} hyphens, common in generated/lookalike domains (-10)")
    elif hyphens == 2:
        score -= 5
        reasons.append("Host contains multiple hyphens (-5)")

    try:
        import tldextract
        ext = tldextract.extract(host)
        suffix = (ext.suffix or "").lower()
        if suffix in SUSPICIOUS_TLDS:
            score -= 18
            reasons.append(f"Higher-risk/suspicious TLD .{suffix} (-18)")
        elif suffix:
            reasons.append(f"TLD: .{suffix}")
        else:
            score -= 6
            reasons.append("No recognizable public suffix (-6)")
    except Exception:
        reasons.append("TLD intelligence unavailable")

    # Brand term + domain mismatch. Example: paypal.example.net.
    low_host = host.replace("-", "")
    claimed_brands = [b for b in BRAND_TERMS if b in low_host]
    if claimed_brands and registered:
        brand_like = claimed_brands[0]
        if not registered.startswith(brand_like + ".") and registered != brand_like:
            score -= 25
            reasons.append(f"Brand-like token '{brand_like}' appears in a non-official-looking registered domain (-25)")

    # Lexical red flags across hostname, path and query.
    combined = f"{host}{parsed.path.lower()}?{parsed.query.lower()}"
    found_tokens = sorted({t for t in SUSPICIOUS_TOKENS if t in combined})
    if found_tokens:
        penalty = min(24, 5 * len(found_tokens))
        score -= penalty
        reasons.append(f"Suspicious security/credential token(s): {', '.join(found_tokens[:6])} (-{penalty})")

    # URL complexity and obfuscation.
    if len(normalized) > 120:
        score -= 12
        reasons.append("Very long URL (>120 chars), increasing obfuscation risk (-12)")
    elif len(normalized) > 80:
        score -= 6
        reasons.append("Long URL (>80 chars) (-6)")

    path_segments = [p for p in parsed.path.split("/") if p]
    if len(path_segments) >= 5:
        score -= 8
        reasons.append(f"Deep URL path ({len(path_segments)} segments) (-8)")

    if parsed.port is not None and parsed.port not in {80, 443}:
        score -= 10
        reasons.append(f"Non-standard port {parsed.port} (-10)")

    if parsed.query:
        pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        if len(pairs) >= 6:
            score -= 8
            reasons.append(f"Many query parameters ({len(pairs)}) (-8)")
        elif len(pairs) >= 3:
            score -= 4
            reasons.append(f"Multiple query parameters ({len(pairs)}) (-4)")

    if "%" in normalized:
        encoded = re.findall(r"%[0-9a-fA-F]{2}", normalized)
        if len(encoded) >= 4:
            score -= 10
            reasons.append(f"Heavy percent-encoding ({len(encoded)} encoded bytes) (-10)")
        else:
            score -= 3
            reasons.append("Percent-encoded characters present (-3)")

    if re.search(r"(?:0x[0-9a-f]{4,}|\\x[0-9a-f]{2})", normalized, re.I):
        score -= 12
        reasons.append("Hex-style obfuscation pattern detected (-12)")

    host_entropy = _entropy(host)
    if len(host) >= 20 and host_entropy >= 3.7:
        score -= 7
        reasons.append(f"High hostname entropy ({host_entropy:.2f}), possible generated label (-7)")

    # URL shortener context: not malicious by itself, but reduces transparency.
    if registered in SHORTENERS or host in SHORTENERS:
        score -= 12
        reasons.append("URL shortener detected; final destination is obscured (-12)")

    # Newly created domain: strong contextual warning.
    age_days = _domain_age_days(host)
    if age_days is not None:
        if age_days < 30:
            score -= 22
            reasons.append(f"Domain age is {age_days} days (<30), unusually new for a trusted service (-22)")
        elif age_days < 90:
            score -= 16
            reasons.append(f"Domain age is {age_days} days (<90) (-16)")
        elif age_days < 180:
            score -= 10
            reasons.append(f"Domain age is {age_days} days (<180) (-10)")
        else:
            reasons.append(f"Domain age is {age_days} days")
    else:
        reasons.append("Domain registration age unavailable")

    # Compound evidence floor: multiple strong red flags should not remain
    # artificially high merely because HTTPS exists.
    strong_markers = sum([
        "Embedded userinfo/@" in " ".join(reasons),
        "Punycode/IDN" in " ".join(reasons),
        "IP-literal host" in " ".join(reasons),
        "Higher-risk/suspicious TLD" in " ".join(reasons),
        "unusually new" in " ".join(reasons).lower(),
        bool(found_tokens),
        "Brand-like token" in " ".join(reasons),
    ])
    joined = " ".join(reasons)
    if "Brand-like token" in joined:
        score = min(score, 70)
        reasons.append("Brand-impersonation guardrail applied: non-official brand-like domain capped at 70 trust")
    if strong_markers >= 3:
        score = min(score, 45)
        reasons.append("Compound-risk guardrail applied: multiple strong red flags cap trust at 45")
    elif strong_markers >= 2:
        score = min(score, 60)
        reasons.append("Compound-risk guardrail applied: multiple strong red flags cap trust at 60")

    score = max(0, min(100, int(round(score))))
    if score >= 90:
        reasons.append("Overall URL trust: high")
    elif score >= 75:
        reasons.append("Overall URL trust: moderate")
    elif score >= 50:
        reasons.append("Overall URL trust: low")
    else:
        reasons.append("Overall URL trust: very low / high-risk")
    return score, reasons


def fused_score(url_score: float, img_score: float) -> float:
    if img_score is None or img_score < 0:
        return round(max(0.0, min(100.0, url_score)), 2)
    # Make high visual similarity matter more, but do not let visual evidence
    # erase strong URL red flags.
    if img_score >= 90:
        w_img = 0.55
    elif img_score >= 75:
        w_img = 0.45
    elif img_score >= 60:
        w_img = 0.30
    else:
        w_img = 0.15
    w_url = 1.0 - w_img
    final = w_url * url_score + w_img * max(img_score, 0)
    return round(max(0.0, min(100.0, final)), 2)


def decide_trust(url_score, img_score, best_ref_name=None, v_high=88, v_mid=65):
    reasons: List[str] = []
    if url_score is None:
        url_score = 0
        reasons.append("URL score unavailable — treated as high-risk/unknown.")
    if img_score is None:
        img_score = -1

    if img_score >= v_high:
        reasons.append(f"Strong visual similarity to reference {best_ref_name}: {img_score:.1f}%")
    elif img_score >= v_mid:
        reasons.append(f"Moderate visual similarity to references: {img_score:.1f}%")
    elif img_score >= 0:
        reasons.append(f"Low visual similarity to known references: {img_score:.1f}%")
    else:
        reasons.append("No screenshot supplied; visual impersonation evidence unavailable.")

    if url_score >= 90:
        reasons.append("URL structure shows few high-risk indicators.")
    elif url_score >= 75:
        reasons.append("URL has some cautionary indicators; do not treat as verified safe.")
    elif url_score >= 50:
        reasons.append("URL contains multiple risk indicators.")
    else:
        reasons.append("URL contains strong/high-risk indicators.")

    # Stricter verdict gates: high visual similarity to a known legitimate
    # reference no longer overrides a genuinely risky URL.
    if url_score < 50 and img_score >= v_high:
        verdict = "Critical risk — strong visual impersonation + high-risk URL"
        color = "red"
    elif url_score < 65 and img_score >= v_high:
        verdict = "High risk — visual impersonation + suspicious URL"
        color = "red"
    elif url_score < 65 and img_score >= v_mid:
        verdict = "High risk — suspicious URL with meaningful visual similarity"
        color = "red"
    elif url_score < 50:
        verdict = "High risk — URL heuristics strongly suspicious"
        color = "red"
    elif img_score >= v_high and url_score >= 85:
        verdict = "Caution — strong visual similarity; verify domain ownership"
        color = "orange"
    elif url_score >= 90 and (img_score < 0 or img_score < v_mid):
        verdict = "Likely low risk — no strong phishing signals detected"
        color = "green"
    elif url_score >= 75:
        verdict = "Moderate risk — manual verification recommended"
        color = "orange"
    else:
        verdict = "Unknown / review required"
        color = "blue"
    return verdict, color, reasons


@dataclass
class EngineResult:
    url: str
    url_score: int
    url_reasons: List[str]
    screenshot_best_match: Optional[str]
    screenshot_score: float
    screenshot_matches: List[ScreenshotMatch] = field(default_factory=list)
    verdict: str = ""
    verdict_color: str = "blue"
    verdict_reasons: List[str] = field(default_factory=list)
    fused: float = 0.0


def analyze_url_and_screenshot(
    url: str,
    screenshot: Optional[Image.Image],
    ref_dir: str = "reference_images",
) -> EngineResult:
    url_score, url_reasons = analyze_url_heuristic(url)
    img_score = -1.0
    best_name = None
    matches: List[ScreenshotMatch] = []
    if screenshot is not None:
        try:
            best_name, img_score, matches = analyze_screenshot_against_refs(screenshot, ref_dir)
        except FileNotFoundError:
            url_reasons.append("Reference image directory unavailable; visual analysis skipped.")
            img_score = -1.0
    verdict, color, verdict_reasons = decide_trust(url_score, img_score, best_ref_name=best_name)
    fused = fused_score(url_score, img_score)
    return EngineResult(
        url=url,
        url_score=url_score,
        url_reasons=url_reasons,
        screenshot_best_match=best_name,
        screenshot_score=img_score,
        screenshot_matches=matches,
        verdict=verdict,
        verdict_color=color,
        verdict_reasons=verdict_reasons,
        fused=fused,
    )


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python linkmirror_engine.py <url> [screenshot_path]")
        raise SystemExit(1)
    shot = Image.open(sys.argv[2]).convert("RGB") if len(sys.argv) > 2 else None
    result = analyze_url_and_screenshot(sys.argv[1], shot)
    print(f"URL trust: {result.url_score}/100")
    print(f"Visual match: {result.screenshot_score:.2f}%")
    print(f"Fused trust: {result.fused:.2f}/100")
    print(result.verdict)
    for r in result.url_reasons:
        print(" -", r)
