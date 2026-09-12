# LinkMirror X — SIH26106 Unified Investigation Platform

LinkMirror X is an investigator-focused prototype for SIH26106. It combines email forensics, QR/quishing detection, attachment triage, strict URL intelligence, visual impersonation analysis, infrastructure pivots, cross-case correlation, campaign analysis and forensic reporting.

## Main navigation

- **Email Forensics** — .eml ingestion, headers, indicators, QR codes, attachments, infrastructure, attack path and case risk.
- **Threat Graph** — restored dedicated threat-correlation graph section from the original prototype.
- **Analytics** — restored original score/severity/URL charts plus the new case-risk visualization.
- **LinkMirror Direct** — standalone URL analysis, screenshot/visual analysis and the original fusion workflow.
- **Campaigns** — Campaign DNA and attack-path views.
- **Reports** — preview/download forensic Markdown reports.
- **Sibling Prediction** — proactive typosquat/campaign-sibling forecasting: given one confirmed-malicious domain, predicts and ranks likely sibling domains the same attacker probably also registered, cross-checked against domains already seen in loaded cases.

## Restored LinkMirror visualizations

The original prototype's visual analysis experience is preserved:

- animated URL Trust pie/donut
- animated Visual Trust pie/donut
- Adaptive Fusion pie/donut
- Manual Weighted Fusion pie/donut
- fused trust score by case bar chart
- header finding severity bar chart
- fused score per URL bar chart
- dedicated threat correlation graph

## New investigation features

- automatic URL analysis from email cases
- QR destination decoding and automatic LinkMirror handoff
- static attachment red-flag checks
- SHA-256 attachment correlation
- unified case risk scoring
- Campaign DNA
- attack-path reconstruction
- cross-case shared infrastructure correlation
- explainable evidence summaries

The visual/URL analysis engine remains usable independently and is also callable automatically from the forensic workflow.
