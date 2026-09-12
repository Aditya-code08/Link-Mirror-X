"""Safe static attachment triage. This does not execute or sandbox files."""
from __future__ import annotations
from dataclasses import dataclass
from typing import List
import re
from ingestion.eml_parser import Attachment

DANGEROUS_EXTENSIONS = {".exe", ".scr", ".com", ".bat", ".cmd", ".ps1", ".psm1", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh", ".hta", ".jar"}
MACRO_OFFICE_EXTENSIONS = {".docm", ".dotm", ".xlsm", ".xltm", ".pptm", ".potm", ".ppsm"}
SCRIPT_MIME_MARKERS = {"javascript", "vbscript", "x-msdownload", "x-msdos-program"}

@dataclass
class AttachmentFinding:
    severity: str
    check: str
    message: str


def analyze_attachment(att: Attachment) -> List[AttachmentFinding]:
    findings: List[AttachmentFinding] = []
    name = att.filename.lower().strip()
    parts = [p for p in re.split(r"[\\/]+", name) if p]
    leaf = parts[-1] if parts else name
    suffixes = ["." + p for p in leaf.split(".")[1:]] if "." in leaf else []

    if len(suffixes) >= 2 and suffixes[-1] in DANGEROUS_EXTENSIONS:
        findings.append(AttachmentFinding("high", "double_extension", f"Double extension detected: {att.filename}"))

    if att.extension in DANGEROUS_EXTENSIONS or any(marker in att.content_type.lower() for marker in SCRIPT_MIME_MARKERS):
        findings.append(AttachmentFinding("high", "executable_or_script", f"Executable/script attachment type detected: {att.filename} ({att.content_type})"))

    if att.extension in MACRO_OFFICE_EXTENSIONS:
        findings.append(AttachmentFinding("warning", "macro_enabled_office", f"Macro-enabled Office file detected: {att.filename}"))

    if not findings:
        findings.append(AttachmentFinding("info", "static_triage_ok", f"No high-risk extension pattern found for {att.filename}"))
    return findings


def analyze_attachments(attachments: List[Attachment]) -> dict:
    results = {}
    for att in attachments:
        results[att.sha256] = analyze_attachment(att)
    return results
