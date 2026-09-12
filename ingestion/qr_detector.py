"""QR/quishing detection using OpenCV's built-in QRCodeDetector."""
from __future__ import annotations
from dataclasses import dataclass
from typing import List
import numpy as np
import cv2

@dataclass
class QRFinding:
    source: str
    decoded: str
    success: bool
    message: str


def decode_qr_images(images: list) -> List[QRFinding]:
    detector = cv2.QRCodeDetector()
    findings: List[QRFinding] = []
    for image in images:
        data = getattr(image, "content", b"")
        if not data:
            continue
        arr = np.frombuffer(data, dtype=np.uint8)
        mat = cv2.imdecode(arr, cv2.IMREAD_COLOR)
        if mat is None:
            continue
        decoded = ""
        try:
            decoded, _, _ = detector.detectAndDecode(mat)
        except Exception:
            decoded = ""
        if decoded:
            findings.append(QRFinding(getattr(image, "filename", "inline-image"), decoded.strip(), True, "QR code decoded successfully; destination queued for URL analysis."))
    return findings
