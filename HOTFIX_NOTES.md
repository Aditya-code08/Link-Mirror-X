# Hotfix Notes

## v2 — 2026-09-08

Fixed a runtime regression in the animated graph build:

- Added the missing `numpy` import (`import numpy as np`) to `app.py`.
- This fixes `NameError: name 'np' is not defined` in animated bar, line, severity, and threat graph rendering after an email is processed.
- No investigation/backend logic was changed.
- Recompiled the Streamlit entrypoint and backend modules successfully.
