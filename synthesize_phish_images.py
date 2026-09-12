#!/usr/bin/env python3
"""
synthesize_phish_images.py (fixed)
Safe synthetic phishing-like image generator.
Compatibility fix: robust text measurement across Pillow versions.
"""

import os
import random
import argparse
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont, ImageFilter, ImageOps

# -----------------------
# Helpers
# -----------------------
def get_font(size=24):
    # Try common fonts, fallback to default
    candidates = ["arial.ttf", "DejaVuSans.ttf"]
    for f in candidates:
        try:
            return ImageFont.truetype(f, size)
        except Exception:
            continue
    return ImageFont.load_default()

def measure_text(draw, text, font):
    """
    Return (width, height) for text using whichever method is available.
    Supports Pillow versions that have textbbox, textsize, or fall back to font.getsize.
    """
    try:
        # Pillow >= 8.x/9.x: textbbox exists and is precise
        if hasattr(draw, "textbbox"):
            bbox = draw.textbbox((0, 0), text, font=font)
            w = bbox[2] - bbox[0]
            h = bbox[3] - bbox[1]
            return w, h
        # older versions might have textsize
        if hasattr(draw, "textsize"):
            return draw.textsize(text, font=font)
    except Exception:
        pass
    # final fallback
    try:
        return font.getsize(text)
    except Exception:
        # last resort approximate
        return (len(text) * font.size // 2, font.size)

def add_translucent_banner(img, text, color=(220,40,40), height_ratio=0.12):
    w, h = img.size
    banner_h = int(h * height_ratio)
    banner = Image.new("RGBA", (w, banner_h), color + (220,))
    draw = ImageDraw.Draw(banner)
    font = get_font(max(16, banner_h//3))
    text_w, text_h = measure_text(draw, text, font)
    draw.text(((w - text_w) // 2, (banner_h - text_h) // 2), text, font=font, fill=(255,255,255,255))
    img.paste(banner, (0,0), banner)
    return img

def add_fake_login_box(img, width_ratio=0.36, height_ratio=0.28):
    w, h = img.size
    box_w = int(w * width_ratio)
    box_h = int(h * height_ratio)
    x = int((w - box_w) / 2 + random.randint(-int(w*0.05), int(w*0.05)))
    y = int((h - box_h) / 2 + random.randint(-int(h*0.08), int(h*0.08)))
    box = Image.new("RGBA", (box_w, box_h), (20, 20, 24, 230))
    draw = ImageDraw.Draw(box)
    font = get_font(16)
    padding = 14
    # input placeholders
    draw.text((padding, padding), "Email or phone", font=font, fill=(200,200,200,255))
    draw.rectangle([padding, padding+26, box_w-padding, padding+54], outline=(90,90,90,255), width=2)
    draw.text((padding, padding+68), "Password", font=font, fill=(200,200,200,255))
    draw.rectangle([padding, padding+96, box_w-padding, padding+124], outline=(90,90,90,255), width=2)
    # verify button
    btn_h = 40
    btn_w = box_w - 2*padding
    btn_y = box_h - padding - btn_h
    draw.rectangle([padding, btn_y, padding+btn_w, btn_y+btn_h], fill=(220,40,40,255))
    btn_text = "Verify"
    tw, th = measure_text(draw, btn_text, get_font(18))
    draw.text((padding + (btn_w - tw)//2, btn_y + (btn_h - th)//2), btn_text, font=get_font(18), fill=(255,255,255,255))
    # border to slightly lift
    border = Image.new("RGBA", (box_w+6, box_h+6), (0,0,0,100))
    border.paste(box, (3,3), box)
    img.paste(border, (x, y), border)
    return img

def add_fake_domain_strip(img, domain_text):
    w, h = img.size
    strip_h = int(h * 0.06)
    strip_w = int(w * 0.6)
    strip = Image.new("RGBA", (strip_w, strip_h), (30,30,30,220))
    draw = ImageDraw.Draw(strip)
    font = get_font(max(12, strip_h//3))
    tw, th = measure_text(draw, domain_text, font)
    draw.text((12, (strip_h - th)//2), domain_text, font=font, fill=(220,220,220,255))
    # warning box to left
    draw.rectangle((6,6,18,18), fill=(220,40,40,255))
    img.paste(strip, (int(w*0.05), int(h*0.04)), strip)
    return img

def add_noise_and_blur(img, noise_strength=0.02):
    # small gaussian blur sometimes
    if random.random() < 0.5:
        img = img.filter(ImageFilter.GaussianBlur(radius=random.uniform(0.2, 1.0)))
    # subtle noise overlay
    w, h = img.size
    noise = Image.effect_noise((w, h), random.uniform(1.0, 6.0)).convert("L")
    noise = ImageOps.colorize(noise, (0,0,0), (255,255,255)).convert("RGBA")
    alpha = int(255 * noise_strength)
    noise.putalpha(alpha)
    img = Image.alpha_composite(img.convert("RGBA"), noise)
    return img.convert("RGB")

def add_diagonal_watermark(img, text="SYNTHETIC"):
    w, h = img.size
    watermark = Image.new("RGBA", img.size, (0,0,0,0))
    draw = ImageDraw.Draw(watermark)
    font = get_font(max(20, w//28))
    # repeat across diagonal
    step = int(w * 0.6)
    for offset in range(-w, w*2, step):
        draw.text((offset, h//2), text, font=font, fill=(255,255,255,40))
    combined = Image.alpha_composite(img.convert("RGBA"), watermark)
    return combined.convert("RGB")

# -----------------------
# Main synthesis function
# -----------------------
def synthesize_one(path, out_dir, variants=4, banner_prob=0.85, login_prob=0.9, domain_list=None):
    try:
        base = Image.open(path).convert("RGB")
    except Exception as e:
        print(f"Skipping {path}: cannot open ({e})")
        return

    fname = Path(path).stem
    out_dir.mkdir(parents=True, exist_ok=True)

    if domain_list is None:
        domain_list = [
            "secure-verify.test", "confirm-login.test", "account-check.example",
            "verify-now.example", "login-update.test"
        ]

    for i in range(variants):
        img = base.copy()
        # optionally add banner
        if random.random() < banner_prob:
            txt = random.choice([
                "URGENT: VERIFY YOUR ACCOUNT",
                "ACTION REQUIRED: CONFIRM DETAILS",
                "SECURITY ALERT — VERIFY",
                "Verify to continue"
            ])
            img = add_translucent_banner(img, txt, color=(220,40,40))
        # optionally add fake login box
        if random.random() < login_prob:
            img = add_fake_login_box(img)
        # fake domain strip
        if random.random() < 0.9:
            d = random.choice(domain_list)
            img = add_fake_domain_strip(img, d)
        # noise/blur
        img = add_noise_and_blur(img, noise_strength=random.uniform(0.01, 0.04))
        # watermark
        img = add_diagonal_watermark(img, "SYNTHETIC")
        outname = f"{fname}_synth_{i+1}.png"
        outpath = out_dir / outname
        try:
            img.save(outpath, format="PNG", optimize=True)
            print(f"WROTE: {outpath}")
        except Exception as e:
            print(f"Failed saving {outpath}: {e}")

# -----------------------
# CLI
# -----------------------
def main():
    ap = argparse.ArgumentParser(description="Generate synthetic phishing-like screenshots from legit screenshots.")
    ap.add_argument("--src", default="reference_images", help="Source folder with legit screenshots")
    ap.add_argument("--dst", default="reference_synthetic", help="Destination folder for synthetic images")
    ap.add_argument("--variants", type=int, default=4, help="Number of synthetic variants per input image")
    ap.add_argument("--banner_prob", type=float, default=0.85, help="Probability to add top banner")
    ap.add_argument("--login_prob", type=float, default=0.9, help="Probability to add fake login box")
    ap.add_argument("--domain_file", default=None, help="Optional file with one fake domain per line")
    args = ap.parse_args()

    src = Path(args.src)
    dst = Path(args.dst)
    variants = max(1, args.variants)

    # load domain list if provided
    domains = None
    if args.domain_file:
        df = Path(args.domain_file)
        if df.exists():
            domains = [ln.strip() for ln in df.read_text(encoding="utf-8").splitlines() if ln.strip()]
            if not domains:
                domains = None

    if not src.exists():
        print(f"Source folder not found: {src}. Create it and add a few legitimate screenshots (PNG/JPG).")
        return

    imgs = [p for p in src.iterdir() if p.suffix.lower() in (".png", ".jpg", ".jpeg")]
    if not imgs:
        print(f"No images found in {src}. Put some screenshots there first.")
        return

    print(f"Found {len(imgs)} source images. Generating {variants} variants each -> {dst}")
    for p in imgs:
        synthesize_one(p, dst, variants=variants, banner_prob=args.banner_prob, login_prob=args.login_prob, domain_list=domains)

    print("Done. Synthetic images saved to:", dst)

if __name__ == "__main__":
    main()
