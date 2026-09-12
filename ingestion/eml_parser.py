"""Robust .eml parser used by the LinkMirror X forensic pipeline."""
from __future__ import annotations

import email
import hashlib
from dataclasses import dataclass, field
from email import policy
from email.utils import getaddresses, parseaddr
from typing import List, Optional


@dataclass
class Attachment:
    filename: str
    content_type: str
    size_bytes: int
    sha256: str
    content: bytes = field(repr=False, default=b"")

    @property
    def extension(self) -> str:
        name = self.filename.lower().rsplit("/", 1)[-1]
        return ("." + name.rsplit(".", 1)[-1]) if "." in name else ""


@dataclass
class EmbeddedImage:
    filename: str
    content_type: str
    size_bytes: int
    content: bytes = field(repr=False, default=b"")
    content_id: Optional[str] = None


@dataclass
class ParsedEmail:
    subject: str
    from_display_name: str
    from_address: str
    reply_to: Optional[str]
    return_path: Optional[str]
    to_addresses: List[str]
    cc_addresses: List[str]
    date: Optional[str]
    message_id: Optional[str]
    received_chain: List[str]
    body_text: str
    body_html: str
    attachments: List[Attachment] = field(default_factory=list)
    embedded_images: List[EmbeddedImage] = field(default_factory=list)
    raw_headers: dict = field(default_factory=dict)
    raw_bytes_sha256: str = ""


def parse_eml_file(path: str) -> ParsedEmail:
    with open(path, "rb") as f:
        return parse_eml_bytes(f.read())


def parse_eml_bytes(raw_bytes: bytes) -> ParsedEmail:
    msg = email.message_from_bytes(raw_bytes, policy=policy.default)
    from_display_name, from_address = parseaddr(msg.get("From", ""))
    reply_to = parseaddr(msg.get("Reply-To", ""))[1] or msg.get("Reply-To")
    return_path = parseaddr(msg.get("Return-Path", ""))[1] or msg.get("Return-Path")

    attachments: List[Attachment] = []
    embedded_images: List[EmbeddedImage] = []
    body_text = ""
    body_html = ""

    parts = msg.walk() if msg.is_multipart() else [msg]
    for part in parts:
        if part.is_multipart():
            continue
        content_type = part.get_content_type()
        payload = part.get_payload(decode=True) or b""
        disposition = str(part.get("Content-Disposition", "")).lower()
        filename = part.get_filename() or ""

        is_attachment = "attachment" in disposition or bool(filename and content_type not in {"text/plain", "text/html"})
        if is_attachment:
            filename = filename or "unnamed_attachment"
            attachments.append(
                Attachment(
                    filename=filename,
                    content_type=content_type,
                    size_bytes=len(payload),
                    sha256=hashlib.sha256(payload).hexdigest(),
                    content=payload,
                )
            )
            continue

        if content_type.startswith("image/"):
            embedded_images.append(
                EmbeddedImage(
                    filename=filename or f"inline_{len(embedded_images)+1}.{content_type.split('/',1)[1]}",
                    content_type=content_type,
                    size_bytes=len(payload),
                    content=payload,
                    content_id=part.get("Content-ID"),
                )
            )
            continue

        if content_type == "text/plain" and not body_text:
            body_text = _decode_payload(payload, part)
        elif content_type == "text/html" and not body_html:
            body_html = _decode_payload(payload, part)

    headers = {}
    for key, value in msg.items():
        if key in headers:
            if isinstance(headers[key], list):
                headers[key].append(value)
            else:
                headers[key] = [headers[key], value]
        else:
            headers[key] = value

    return ParsedEmail(
        subject=msg.get("Subject", "(no subject)"),
        from_display_name=from_display_name,
        from_address=from_address,
        reply_to=reply_to,
        return_path=return_path,
        to_addresses=[a for _, a in getaddresses(msg.get_all("To", [])) if a],
        cc_addresses=[a for _, a in getaddresses(msg.get_all("Cc", [])) if a],
        date=msg.get("Date"),
        message_id=msg.get("Message-ID"),
        received_chain=msg.get_all("Received", []),
        body_text=body_text,
        body_html=body_html,
        attachments=attachments,
        embedded_images=embedded_images,
        raw_headers=headers,
        raw_bytes_sha256=hashlib.sha256(raw_bytes).hexdigest(),
    )


def _decode_payload(payload: bytes, part) -> str:
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except (LookupError, TypeError):
        return payload.decode("utf-8", errors="replace")
