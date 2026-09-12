"""
domain_intel.py

Lightweight infrastructure intelligence: domain age (via WHOIS, reused
from the engine's URL heuristic path) and a hosting/ASN label for an
IP address.

For REAL public IPs, this calls ip-api.com's free JSON endpoint (no
key required) — good enough for a demo, not a production-grade OSINT
source. For the synthetic demo IPs (RFC 5737 reserved test ranges,
which will NEVER resolve on the real internet), a small hardcoded
lookup table returns a fictional-but-labeled "demo hosting" result so
the app doesn't just show blank/error data.

If the network call fails for any reason (no internet, rate limit),
this degrades gracefully to "unavailable" rather than crashing.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Optional
import json
import urllib.request

# RFC 5737 / RFC 2606 reserved ranges used in our synthetic demo dataset —
# these will never resolve on the real internet, so we label them clearly
# as demo data instead of pretending to look them up live.
DEMO_IP_LABELS = {
    "203.0.113.44": {
        "org": "AS-EXAMPLE-HOSTING (fictional, demo only)",
        "country": "N/A (RFC 5737 reserved test range)",
        "is_demo": True,
    },
    "198.51.100.77": {
        "org": "AS-OTHERHOST-DEMO (fictional, demo only)",
        "country": "N/A (RFC 5737 reserved test range)",
        "is_demo": True,
    },
}


@dataclass
class IpIntel:
    ip: str
    org: str
    country: str
    is_demo: bool
    lookup_succeeded: bool


def lookup_ip(ip: str) -> IpIntel:
    if ip in DEMO_IP_LABELS:
        info = DEMO_IP_LABELS[ip]
        return IpIntel(ip=ip, org=info["org"], country=info["country"],
                        is_demo=True, lookup_succeeded=True)

    try:
        with urllib.request.urlopen(f"http://ip-api.com/json/{ip}?fields=org,country,isp", timeout=3) as resp:
            data = json.loads(resp.read().decode())
        org = data.get("org") or data.get("isp") or "Unknown"
        country = data.get("country", "Unknown")
        return IpIntel(ip=ip, org=org, country=country, is_demo=False, lookup_succeeded=True)
    except Exception:
        return IpIntel(ip=ip, org="Lookup unavailable", country="Unknown",
                        is_demo=False, lookup_succeeded=False)


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python domain_intel.py <ip>")
        sys.exit(1)
    result = lookup_ip(sys.argv[1])
    print(f"IP: {result.ip}")
    print(f"Org/ISP: {result.org}")
    print(f"Country: {result.country}")
    print(f"Demo data: {result.is_demo}")
    print(f"Lookup succeeded: {result.lookup_succeeded}")
