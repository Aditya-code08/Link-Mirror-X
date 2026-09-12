"""
capture_legit_screenshots.py

Visit a curated list of 20 legitimate sites and save full-page screenshots into `reference_images/`.

Usage:
    python capture_legit_screenshots.py

Notes:
 - This captures legitimate webpages only (no phishing). Safe to run on your main machine.
 - If a site blocks headless chrome, try removing the headless flag (see code comments).
"""

import os
import time
import csv
import random
import urllib.parse
import datetime
from pathlib import Path
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.common.exceptions import TimeoutException, WebDriverException
from webdriver_manager.chrome import ChromeDriverManager
from PIL import Image

# -------- CONFIG --------
OUT_DIR = Path("reference_images")
LOG_CSV = "legit_screenshots.csv"
WINDOW_WIDTH = 1366
MAX_HEIGHT = 4000
PAGE_LOAD_TIMEOUT = 30
SLEEP_AFTER_LOAD = 4
HEADLESS = True      # set False if a site blocks headless (or to debug)
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36"
MIN_DELAY = 1.0
MAX_DELAY = 2.5

SITES = [
    "https://www.youtube.com",
    "https://www.facebook.com",
    "https://www.twitter.com",
    "https://www.reddit.com",
    "https://www.microsoft.com",
    "https://www.apple.com",
    "https://stackoverflow.com",
    "https://www.ebay.com",
    "https://www.walmart.com",
    "https://www.bing.com",
    "https://www.office.com",
    "https://www.dropbox.com",
    "https://medium.com",
    "https://www.quora.com",
    "https://www.pinterest.com",
    "https://imgur.com",
    "https://www.cnn.com",
    "https://www.bbc.com",
    "https://www.craigslist.org",
    "https://www.adobe.com",
]

# -------- Helpers --------
def safe_filename_from_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    netloc = parsed.netloc.replace(":", "_")
    path = parsed.path.strip("/").replace("/", "_")[:60]
    if path == "":
        path = "home"
    name = f"{netloc}__{path}"
    name = "".join(ch for ch in name if ch.isalnum() or ch in ("_", "-"))
    if len(name) > 150:
        name = name[:150]
    return name + ".png"

def ensure_outdir():
    OUT_DIR.mkdir(parents=True, exist_ok=True)

def init_driver():
    options = Options()
    if HEADLESS:
        # latest chrome headless flag; if it causes issues on your system, set HEADLESS=False above
        options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.add_argument(f"--window-size={WINDOW_WIDTH},800")
    options.add_argument(f"user-agent={USER_AGENT}")
    options.add_argument("--ignore-certificate-errors")
    options.add_argument("--log-level=3")
    # instantiate driver via webdriver-manager
    service = Service(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=service, options=options)
    driver.set_page_load_timeout(PAGE_LOAD_TIMEOUT)
    return driver

def capture_fullpage_screenshot(driver, out_path: Path):
    """
    Capture full page screenshot by resizing window to page height.
    Caps height to MAX_HEIGHT. Saves PNG to out_path.
    """
    try:
        total_height = driver.execute_script(
            "return Math.max(document.body.scrollHeight, document.documentElement.scrollHeight, "
            "document.body.offsetHeight, document.documentElement.offsetHeight, "
            "document.body.clientHeight, document.documentElement.clientHeight);"
        )
        total_width = driver.execute_script(
            "return Math.max(document.body.scrollWidth, document.documentElement.scrollWidth);"
        )

        total_height = min(int(total_height or 1000), MAX_HEIGHT)
        total_width = max(int(total_width or WINDOW_WIDTH), WINDOW_WIDTH)

        driver.set_window_size(total_width, total_height)
        time.sleep(0.3)  # allow reflow
        tmp_png = out_path.with_suffix(".tmp.png")
        driver.save_screenshot(str(tmp_png))

        im = Image.open(tmp_png).convert("RGB")
        if im.height > MAX_HEIGHT:
            im = im.crop((0, 0, im.width, MAX_HEIGHT))
        im.save(out_path, optimize=True)
        try:
            tmp_png.unlink(missing_ok=True)
        except Exception:
            pass
        return True, f"saved ({im.width}x{im.height})"
    except Exception as e:
        # fallback: viewport screenshot
        try:
            driver.save_screenshot(str(out_path))
            return True, "saved (viewport fallback)"
        except Exception as e2:
            return False, f"failed: {e} // {e2}"

def load_urls():
    # returns SITES (keeps code flexible if you want to load from file later)
    return SITES

# -------- Main --------
def main():
    print("=== Legitimate website screenshot capture ===")
    ensure_outdir()
    urls = load_urls()
    if not urls:
        print("No sites to process.")
        return

    csv_path = LOG_CSV
    write_header = not os.path.exists(csv_path)
    csv_file = open(csv_path, "a", newline="", encoding="utf-8")
    import csv as _csv
    csv_writer = _csv.writer(csv_file)
    if write_header:
        csv_writer.writerow(["url", "filename", "status", "notes", "timestamp"])

    driver = None
    try:
        driver = init_driver()
    except Exception as e:
        print(f"[ERROR] Could not start WebDriver: {e}")
        return

    for idx, url in enumerate(urls, 1):
        safe_name = safe_filename_from_url(url)
        out_path = OUT_DIR / safe_name
        timestamp = datetime.datetime.utcnow().isoformat()

        print(f"[{idx}/{len(urls)}] Visiting: {url}")
        try:
            driver.get(url)
            time.sleep(SLEEP_AFTER_LOAD)  # wait for JS & assets (adjust if needed)
            success, note = capture_fullpage_screenshot(driver, out_path)
            status = "ok" if success else "error"
            print(f"  => {status}: {note} -> {out_path}")
            csv_writer.writerow([url, str(out_path), status, note, timestamp])
            csv_file.flush()
        except TimeoutException as te:
            print(f"  => timeout: {te}")
            csv_writer.writerow([url, "", "timeout", str(te), timestamp])
            csv_file.flush()
        except WebDriverException as we:
            print(f"  => webdriver error: {we}")
            csv_writer.writerow([url, "", "webdriver_error", str(we), timestamp])
            csv_file.flush()
            # try to re-init driver
            try:
                driver.quit()
            except Exception:
                pass
            try:
                driver = init_driver()
            except Exception as e:
                print(f"[ERROR] failed to restart driver: {e}")
                break
        except Exception as e:
            print(f"  => unexpected error: {e}")
            csv_writer.writerow([url, "", "error", str(e), timestamp])
            csv_file.flush()

        time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))

    try:
        driver.quit()
    except Exception:
        pass
    csv_file.close()
    print("Done. Screenshots saved to:", OUT_DIR)
    print("Log written to:", csv_path)

if __name__ == "__main__":
    main()
