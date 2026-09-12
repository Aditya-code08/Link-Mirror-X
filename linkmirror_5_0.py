import os
import time
import datetime
import tempfile
import streamlit as st
import streamlit.components.v1 as components
import matplotlib.pyplot as plt
from PIL import Image
import numpy as np
import cv2
from sklearn.metrics.pairwise import cosine_similarity
import base64

# ---------------------------
# 🔹 Background Setup (dimmed GIF)
# ---------------------------
def set_bg_gif(gif_file: str):
    """Adds a dimmed looping GIF background."""
    if not os.path.exists(gif_file):
        st.warning(f"Background file '{gif_file}' not found.")
        return

    with open(gif_file, "rb") as f:
        data = f.read()
    data_url = base64.b64encode(data).decode("utf-8")

    st.markdown(
        f"""
        <style>
        [data-testid="stAppViewContainer"] {{
            background: linear-gradient(rgba(0,0,0,0.45), rgba(0,0,0,0.45)),
                        url("data:image/gif;base64,{data_url}");
            background-size: cover;
            background-position: center;
            opacity: 0;
            animation: fadeInApp 1.4s ease-in-out forwards;
        }}
        [data-testid="stHeader"], [data-testid="stToolbar"] {{
            background: transparent;
        }}
        [data-testid="stSidebar"] > div:first-child {{
            background: rgba(10,10,25,0.6);
        }}
        @keyframes fadeInApp {{
            from {{ opacity: 0; transform: translateY(8px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}
        </style>
        """,
        unsafe_allow_html=True
    )

set_bg_gif("linkmirror_bg.gif")

# Optional torch
try:
    import torch
    from torchvision import models, transforms
    TORCH_AVAILABLE = True
except Exception:
    TORCH_AVAILABLE = False

# ---------------------------
# Page config & styles
# ---------------------------
st.set_page_config(page_title="LinkMirror X", page_icon="🪞", layout="centered")
css = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Poppins:wght@400;600;700&display=swap');
html, body, [class*="css"] { font-family: 'Poppins', sans-serif; background-color: #050812; color: #dbe9ff; }

.header {
  position: relative; height: 150px; overflow: hidden; 
  background: linear-gradient(90deg, #081426, #071a2b);
  border-radius: 12px; margin-bottom: 14px; border: 1px solid rgba(41,121,255,0.12);
  opacity: 0;
  animation: fadeInHeader 1.2s ease-in-out forwards 0.4s;
}
@keyframes fadeInHeader {
  from { opacity: 0; transform: translateY(-10px); }
  to { opacity: 1; transform: translateY(0); }
}

.header::before {
  content: "0100100101010010010010010010100101001001001010010100100101001";
  position:absolute; inset:0; color: rgba(41,121,255,0.04); font-family: monospace; font-size: 14px;
  white-space: pre; line-height: 26px; animation: moveBin 18s linear infinite;
}
@keyframes moveBin { 0%{ transform: translateY(-0%);} 100%{ transform: translateY(100%);} }

.header-content { position: relative; z-index:2; text-align:center; padding-top:10px; }

.small-muted { color: #9fbbe8; font-size:14px; }
.panel { background:#071026; padding:12px; border-radius:10px; border:1px solid rgba(41,121,255,0.06); opacity:0; animation: fadeInPanel 1.5s ease-in-out forwards 0.8s; }
@keyframes fadeInPanel { from {opacity:0; transform:translateY(10px);} to {opacity:1; transform:translateY(0);} }

.verdict-box { padding:14px; border-radius:8px; color:white; font-weight:600; opacity:0; animation: fadeIn 0.9s ease-in-out forwards; }
.fade-in { opacity:0; animation: fadeIn 0.9s ease-in-out forwards; }

@keyframes fadeIn {
  from { opacity: 0; transform: translateY(6px); }
  to   { opacity: 1; transform: translateY(0); }
}
.small-note { font-size:12px;color:#a8c4dd; }
</style>
"""
st.markdown(css, unsafe_allow_html=True)

# ---------------------------
# Header with GIF
# ---------------------------
# ---------------------------
# Everything below remains identical (rest of your logic unchanged)
# ---------------------------

# (Paste your full original logic from your code starting from 
# “os.makedirs(r"C:\tmp", exist_ok=True)” till the end — 
# that part remains fully compatible and fade-in will apply globally.)

# Optional torch
try:
    import torch
    from torchvision import models, transforms
    TORCH_AVAILABLE = True
except Exception:
    TORCH_AVAILABLE = False

# ---------------------------
# Page config & styles
# ---------------------------
st.set_page_config(page_title="LinkMirror X", page_icon="🪞", layout="centered")
css = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Poppins:wght@400;600;700&display=swap');
html, body, [class*="css"] { font-family: 'Poppins', sans-serif; background-color: #050812; color: #dbe9ff; }
.header {
  position: relative; height: 150px; overflow: hidden; background: linear-gradient(90deg, #081426, #071a2b);
  border-radius: 12px; margin-bottom: 14px; border: 1px solid rgba(41,121,255,0.12);
}
.header::before {
  content: "0100100101010010010010010010100101001001001010010100100101001";
  position:absolute; inset:0; color: rgba(41,121,255,0.04); font-family: monospace; font-size: 14px;
  white-space: pre; line-height: 26px; animation: moveBin 18s linear infinite;
}
@keyframes moveBin { 0%{ transform: translateY(-0%);} 100%{ transform: translateY(100%);} }
.header-content { position: relative; z-index:2; text-align:center; padding-top:10px; }
.small-muted { color: #9fbbe8; font-size:14px; }
.panel { background:#071026; padding:12px; border-radius:10px; border:1px solid rgba(41,121,255,0.06); }
.verdict-box { padding:14px; border-radius:8px; color:white; font-weight:600; opacity:0; animation: fadeIn 0.9s ease-in-out forwards; }
.fade-in { opacity:0; animation: fadeIn 0.9s ease-in-out forwards; }
@keyframes fadeIn {
  from { opacity: 0; transform: translateY(6px); }
  to   { opacity: 1; transform: translateY(0); }
}
.small-note { font-size:12px;color:#a8c4dd; }
</style>
"""
st.markdown(css, unsafe_allow_html=True)

# header
logo_path = "assets/linkmirror_logo.gif"
logo_img_tag = f'<img src="{logo_path}" width="90" style="vertical-align:middle;margin-right:10px;">' if os.path.exists(logo_path) else '<span style="font-size:44px;margin-right:12px;">🪞</span>'
st.markdown(f"""
<div class="header">
  <div class="header-content">
    {logo_img_tag}
    <div style="display:inline-block;vertical-align:middle;">
      <div style="font-size:28px;color:#2979FF;font-weight:700;">LinkMirror X</div>
      <div class="small-muted">Cyber Glitch Edition — AI CyberTrust Engine</div>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)

# ---------------------------
# Safe temp dir and ensure directories
# ---------------------------
os.makedirs(r"C:\tmp", exist_ok=True)
tempfile.tempdir = r"C:\tmp"

# ---------------------------
# Load ResNet model (cached)
# ---------------------------
resnet_model = None
resnet_transform = None
if TORCH_AVAILABLE:
    @st.cache_resource
    def load_resnet_torch():
        model = models.resnet50(pretrained=True)
        model.eval()
        model = torch.nn.Sequential(*(list(model.children())[:-1]))
        return model
    try:
        resnet_model = load_resnet_torch()
        resnet_transform = transforms.Compose([
            transforms.Resize((224, 224)),
            transforms.ToTensor(),
            transforms.Normalize(mean=[0.485, 0.456, 0.406],
                                 std=[0.229, 0.224, 0.225])
        ])
    except Exception:
        TORCH_AVAILABLE = False
        resnet_model = None
        resnet_transform = None

# ---------------------------
# Visual comparators
# ---------------------------
def compute_orb_similarity_cv(img_cv_q, img_cv_ref, nfeatures=800):
    orb = cv2.ORB_create(nfeatures)
    kp1, des1 = orb.detectAndCompute(img_cv_q, None)
    kp2, des2 = orb.detectAndCompute(img_cv_ref, None)
    if des1 is None or des2 is None or len(kp1) == 0 or len(kp2) == 0:
        return 0.0
    bf = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=True)
    matches = bf.match(des1, des2)
    n_matches = len(matches)
    denom = min(len(kp1), len(kp2))
    if denom == 0:
        return 0.0
    return n_matches / denom

def compute_resnet_similarity_pil(pil_q, pil_ref):
    if not TORCH_AVAILABLE or resnet_model is None:
        return 0.0
    try:
        tq = resnet_transform(pil_q).unsqueeze(0)
        tr = resnet_transform(pil_ref).unsqueeze(0)
        with torch.no_grad():
            f_q = resnet_model(tq).cpu().numpy().reshape(1, -1)
            f_r = resnet_model(tr).cpu().numpy().reshape(1, -1)
        return float(cosine_similarity(f_q, f_r)[0][0])
    except Exception:
        return 0.0

def analyze_screenshot_against_refs(pil_query, ref_dir="reference_images"):
    if not os.path.isdir(ref_dir):
        raise FileNotFoundError(f"Reference directory not found: {ref_dir}")
    query_cv = np.array(pil_query.convert("RGB"))[:, :, ::-1]
    best_name = None
    best_score = -1.0
    results = []
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
        combined = 0.4 * orb_sim + 0.6 * resnet_sim
        score_pct = combined * 100
        results.append((fname, score_pct, orb_sim, resnet_sim))
        if score_pct > best_score:
            best_score = score_pct
            best_name = fname
    results.sort(key=lambda x: x[1], reverse=True)
    return best_name, round(best_score, 2), results

# ---------------------------
# URL heuristic analyzer
# ---------------------------
def analyze_url_heuristic(url: str):
    reasons = []
    s = 100
    if not url:
        return 50, ["No URL provided."]
    u = url.strip().lower()
    if not u.startswith("http"):
        u = "http://" + u
    if u.startswith("https://"):
        reasons.append("✅ HTTPS present")
    else:
        reasons.append("⚠️ No HTTPS")
        s -= 15
    tokens = ['login','verify','secure','update','account','bank','signin','paypal','free','bonus']
    count = sum(1 for t in tokens if t in u)
    if count > 0:
        reasons.append(f"⚠️ Suspicious token(s) found: {count}")
        s -= min(20, 5 * count)
    if len(u) > 60:
        reasons.append("⚠️ URL unusually long")
        s -= 5
    else:
        reasons.append("✅ URL length ok")
    try:
        import tldextract
        ext = tldextract.extract(u)
        if ext.suffix in ("xyz","top","club","click","work","party","zip"):
            reasons.append(f"⚠️ Suspicious TLD: .{ext.suffix}")
            s -= 10
        else:
            reasons.append(f"✅ TLD: .{ext.suffix}")
    except Exception:
        reasons.append("⚠️ TLD check unavailable")
    try:
        import whois
        domain = u.split("//")[-1].split("/")[0]
        w = whois.whois(domain)
        cd = w.creation_date
        if isinstance(cd, list):
            cd = cd[0]
        if cd:
            age_days = (datetime.datetime.now() - cd).days
            if age_days < 180:
                reasons.append("⚠️ Domain very new (<6 months)")
                s -= 10
            else:
                reasons.append("✅ Domain age OK")
        else:
            reasons.append("⚠️ WHOIS: no creation date")
            s -= 5
    except Exception:
        reasons.append("⚠️ WHOIS check failed or not available")
    s = max(0, min(100, s))
    return s, reasons

# ---------------------------
# Decision & Fusion
# ---------------------------
def decide_trust(url_score, img_score, best_ref_name=None, v_high=85, v_mid=60):
    reasons = []
    if url_score is None:
        url_score = 50
        reasons.append("URL score missing — treated as neutral.")
    if img_score is None:
        img_score = -1
    if img_score >= v_high:
        reasons.append(f"Strong visual match to reference: {best_ref_name} ({img_score:.1f}%)")
    elif img_score >= v_mid:
        reasons.append(f"Weak visual similarity to references ({img_score:.1f}%)")
    elif img_score >= 0:
        reasons.append("No significant visual match to references.")
    else:
        reasons.append("No screenshot available for visual comparison.")
    if url_score >= 80:
        reasons.append("URL heuristics indicate low risk.")
    elif url_score >= 60:
        reasons.append("URL heuristics indicate moderate risk.")
    else:
        reasons.append("URL heuristics indicate high risk.")
    if img_score >= v_high and url_score >= 60:
        verdict = "Likely genuine (visual clone of known reference; URL not strongly suspicious)"
        color = "green"
    elif img_score >= v_high and url_score < 60:
        verdict = "High risk — visual clone + suspicious URL (likely phishing)"
        color = "red"
    elif v_mid <= img_score < v_high and url_score < 60:
        verdict = "Suspicious — partial visual match + risky URL"
        color = "orange"
    elif img_score < v_mid and url_score >= 80:
        verdict = "Unknown site but URL looks safe — manual check recommended"
        color = "blue"
    elif img_score < v_mid and url_score < 80:
        verdict = "Unknown site & URL heuristics suspicious — treat as risky"
        color = "red"
    else:
        verdict = "Mixed signals — manual review recommended"
        color = "orange"
    return verdict, color, reasons

def fused_score(url_score, img_score):
    if img_score is None or img_score < 0:
        w_img = 0.05
    else:
        if img_score >= 85:
            w_img = 0.6
        elif img_score >= 60:
            w_img = 0.35
        else:
            w_img = 0.1
    w_url = 1.0 - w_img
    final = round(w_url * url_score + w_img * max(img_score, 0), 2)
    return final

# ---------------------------
# Visualization: animated pie (single placeholder)
# ---------------------------
def animated_pie(score, title="TrustScore", size=3.2):
    # size in inches for matplotlib
    placeholder = st.empty()
    fig, ax = plt.subplots(figsize=(size, size))
    ax.axis("equal")
    # update in-place to avoid multiple figure stacking
    for val in range(0, int(score) + 1, max(1, int(score//30) if score>=30 else 1)):
        ax.clear()
        ax.axis("equal")
        # gradient from red to green
        r = 1 - val/100
        g = min(1.0, 0.4 + val/120)
        b = min(1.0, 0.3 + val/200)
        color = (r, g, b)
        wedges, _ = ax.pie([val, 100 - val], colors=[color, "#071026"], startangle=90,
                           wedgeprops=dict(width=0.35, edgecolor="#0b1a2b"))
        ax.text(0, 0, f"{val}%", ha="center", va="center", fontsize=14, color="white", weight="bold")
        ax.set_facecolor("#071026")
        fig.patch.set_facecolor('#071026')
        placeholder.pyplot(fig)
        time.sleep(0.02)
    # small caption under the chart (fade-in handled by CSS on the container)
    return

# ---------------------------
# UI Layout: Tabs
# ---------------------------
tab1, tab2, tab3 = st.tabs(["🔗 URL Mode", "📸 Screenshot Mode", "🧩 Fusion Mode"])

# ----- URL Mode -----
with tab1:
    st.markdown("<div class='panel'><h3>🔗 URL Mode</h3><p class='small-muted'>Paste a URL to analyze (heuristics + WHOIS attempt).</p></div>", unsafe_allow_html=True)
    url_input = st.text_input("Enter URL (e.g. https://example.com)")
    if st.button("Analyze URL"):
        with st.spinner("Running URL checks..."):
            pbar = st.progress(0)
            # safe progress increments
            for p in range(0, 101, 12):
                time.sleep(0.03)
                pbar.progress(min(max(p,0),100))
            pbar.empty()
            url_score, url_reasons = analyze_url_heuristic(url_input)
        st.markdown(f"### Final URL TrustScore: **{url_score}/100**")
        # small pie (compact)
        col1, col2 = st.columns([1,2])
        with col1:
            st.markdown("<div class='fade-in' id='url_pie'>", unsafe_allow_html=True)
            animated_pie(url_score, title="URL Trust", size=2.8)
            st.markdown("</div>", unsafe_allow_html=True)
        with col2:
            st.markdown("#### Reasons")
            for r in url_reasons:
                st.write("• " + r)
        st.session_state['last_url_score'] = url_score
        st.session_state['last_url_reasons'] = url_reasons

# ----- Screenshot Mode -----
with tab2:
    st.markdown("<div class='panel'><h3>📸 Screenshot Mode</h3><p class='small-muted'>Upload a screenshot to compare against references.</p></div>", unsafe_allow_html=True)
    if not TORCH_AVAILABLE:
        st.warning("Screenshot Analyzer works best with PyTorch installed for ResNet; ORB-only fallback will still run.")
    uploaded = st.file_uploader("Upload screenshot (PNG/JPG)", type=['png','jpg','jpeg'])
    if uploaded is not None and st.button("Analyze Screenshot"):
        with st.spinner("Computing visual similarity..."):
            pb = st.progress(0)
            for p in range(0, 101, 25):
                time.sleep(0.03)
                pb.progress(min(max(p,0),100))
            pb.empty()
            try:
                pil_query = Image.open(uploaded).convert("RGB")
                best_name, best_score, all_results = analyze_screenshot_against_refs(pil_query, ref_dir="reference_images")
            except FileNotFoundError:
                st.error("reference_images/ folder not found. Create it and add legit screenshots.")
                best_name, best_score, all_results = None, 0.0, []
            except Exception as e:
                st.error(f"Screenshot analysis failed: {e}")
                best_name, best_score, all_results = None, 0.0, []

        if best_name:
            st.image(pil_query, caption="Uploaded screenshot", use_container_width=True)
            st.success(f"Closest reference: {best_name} (Similarity {best_score:.2f}%)")
            st.markdown("<div class='fade-in'>", unsafe_allow_html=True)
            # small pie (compact)
            animated_pie(best_score, title="Visual Trust", size=2.8)
            st.markdown("</div>", unsafe_allow_html=True)

            st.markdown("### Top matches")
            rows = [{"Reference": r[0], "Score (%)": f"{r[1]:.2f}", "ORB": f"{r[2]:.3f}", "ResNet": f"{r[3]:.3f}"} for r in all_results[:6]]
            st.table(rows)
            st.session_state['last_img_score'] = float(best_score)
            st.session_state['last_img_best'] = best_name

            # gentle scroll to verdict
            scroll_js = "<script>setTimeout(()=>{window.scrollTo({top:document.body.scrollHeight,behavior:'smooth'})},200);</script>"
            components.html(scroll_js, height=20)
        else:
            st.info("No reference matches found or analysis failed.")

# ----- Fusion Mode -----
with tab3:
    st.markdown("<div class='panel'><h3>🧩 Fusion Mode</h3><p class='small-muted'>Combine URL + Screenshot TrustScores into a unified TrustScore and tune thresholds live.</p></div>", unsafe_allow_html=True)
    url_score = st.session_state.get('last_url_score', None)
    img_score = st.session_state.get('last_img_score', None)
    best_ref = st.session_state.get('last_img_best', None)

    colA, colB = st.columns(2)
    with colA:
        if url_score is None:
            default_url = 80
            st.info("No URL score in session. Run a URL analysis first or use slider below.")
        url_score_input = st.slider("URL TrustScore (simulate/override)", 0, 100, int(url_score) if url_score is not None else 80)
    with colB:
        if img_score is None:
            st.info("No screenshot score in session. Run a screenshot analysis first or use slider below.")
        img_score_input = st.slider("Screenshot TrustScore (simulate/override)", 0, 100, int(img_score) if img_score is not None else 85)

    st.markdown("#### Tuning thresholds (live)")
    v_high = st.slider("Visual High Threshold (strong match)", 70, 95, 85)
    v_mid = st.slider("Visual Mid Threshold (partial match)", 30, 70, 60)
    url_weight = st.slider("Manual URL weight (0-100)", 0, 100, 50)
    # compute adaptive fused score and manual weighted score
    fused_adaptive = fused_score(url_score_input, img_score_input)
    manual_fused = round((url_weight/100.0)*url_score_input + (1 - url_weight/100.0)*img_score_input, 2)

    st.markdown("### Unified TrustScores")
    col1, col2 = st.columns([1,1])
    with col1:
        st.markdown("<div class='fade-in'>", unsafe_allow_html=True)
        st.write("Adaptive fusion")
        animated_pie(fused_adaptive, title="Adaptive", size=2.6)
        st.markdown("</div>", unsafe_allow_html=True)
    with col2:
        st.markdown("<div class='fade-in'>", unsafe_allow_html=True)
        st.write("Manual weighted fusion")
        animated_pie(manual_fused, title="Manual", size=2.6)
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("#### Component Scores")
    st.write(f"- URL TrustScore: **{url_score_input}**")
    st.write(f"- Screenshot TrustScore: **{img_score_input}**")
    # decision using adaptive thresholds
    verdict_text, color, reasons = decide_trust(url_score_input, img_score_input, best_ref_name=best_ref, v_high=v_high, v_mid=v_mid)
    color_map = {"green":"#2e7d32","red":"#ef5350","orange":"#fb8c00","blue":"#1976d2"}
    color_hex = color_map.get(color, "#1976d2")
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown(f"<div class='verdict-box' style='background:{color_hex};'>{verdict_text}</div>", unsafe_allow_html=True)
    st.markdown("#### Decision rationale")
    for r in reasons:
        st.write("• " + r)

    # gentle scroll to verdict block
    components.html("<script>setTimeout(()=>{window.scrollTo({top:document.body.scrollHeight,behavior:'smooth'})},200);</script>", height=20)

# Footer spacer
st.markdown("<div style='height:18px'></div>", unsafe_allow_html=True)
