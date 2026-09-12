# How to run LinkMirror X

## 1. Create/activate a virtual environment

Windows PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

## 2. Install dependencies

```powershell
py -m pip install -r requirements.txt
```

If PyTorch installation is not available in your environment, the visual engine can still use its structural fallback. For best visual results, install a compatible PyTorch/torchvision build.

## 3. Start the application

```powershell
py -m streamlit run app.py
```

## 4. Recommended demo flow

1. Open **Email Forensics** and load the included demo cases.
2. Open **Threat Graph** to show the dedicated restored graph.
3. Open **Analytics** to show case, severity and URL charts.
4. Open **LinkMirror Direct** → URL Intelligence for strict URL scoring.
5. Open **LinkMirror Direct** → Screenshot / Visual Analysis for side-by-side image visualization.
6. Open **LinkMirror Direct** → Fusion & Verdict for the original adaptive/manual fusion controls.
7. Open **Campaigns** to reveal Campaign DNA and attack-path reconstruction.
8. Open **Reports** for the forensic report.
