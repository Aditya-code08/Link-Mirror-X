"""
capture.py

Stands in for "visit this URL and take a screenshot." For the demo,
we deliberately do NOT do live browsing (Selenium) — see project notes
for why. Instead this maps a URL to a pre-captured screenshot file by
naming convention, so the rest of the pipeline (which expects "a
screenshot for this URL") doesn't need to know the difference.

Naming convention: for a URL like
    http://secure-verify.test/hdfc/login?ref=8827
we look for a screenshot file whose name matches the domain:
    captured_screenshots/secure-verify.test.png

To add support for a new demo URL, just drop a screenshot into
captured_screenshots/ named after its domain.
"""

from __future__ import annotations
import os
import urllib.parse
from typing import Optional
from PIL import Image

CAPTURED_DIR = os.path.join(os.path.dirname(__file__), "..", "captured_screenshots")


def get_webpage_screenshot(url: str, captured_dir: str = CAPTURED_DIR) -> Optional[Image.Image]:
    """
    Returns a PIL Image for the given URL if a matching pre-captured
    screenshot exists, else None. This is intentionally NOT live
    browsing — see module docstring.
    """
    domain = urllib.parse.urlparse(url if "//" in url else f"//{url}").netloc.lower()
    if not domain:
        return None

    for ext in (".png", ".jpg", ".jpeg"):
        candidate = os.path.join(captured_dir, f"{domain}{ext}")
        if os.path.exists(candidate):
            return Image.open(candidate).convert("RGB")

    return None


def has_screenshot(url: str, captured_dir: str = CAPTURED_DIR) -> bool:
    return get_webpage_screenshot(url, captured_dir) is not None


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python capture.py <url>")
        sys.exit(1)
    img = get_webpage_screenshot(sys.argv[1])
    if img:
        print(f"Found screenshot: size={img.size}")
    else:
        print("No pre-captured screenshot found for this URL's domain.")
