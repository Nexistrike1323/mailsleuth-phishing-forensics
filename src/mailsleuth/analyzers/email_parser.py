"""Safe RFC-compliant EML parsing for MailSleuth."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Any


@dataclass
class AttachmentArtifact:
    filename: str | None
    content_type: str
    size: int
    sha256: str


@dataclass
class EmailArtifact:
    source_file: str
    subject: str
    sender: str
    reply_to: list[str]
    return_path: str
    recipients: list[str]
    date: str
    message_id: str
    received_headers: list[str]
    authentication_results: list[str]
    text_body: str
    has_html_body: bool
    attachments: list[AttachmentArtifact] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_file": self.source_file,
            "subject": self.subject,
            "sender": self.sender,
            "reply_to": self.reply_to,
            "return_path": self.return_path,
            "recipients": self.recipients,
            "date": self.date,
            "message_id": self.message_id,
            "received_headers": self.received_headers,
            "authentication_results": self.authentication_results,
            "text_body": self.text_body,
            "has_html_body": self.has_html_body,
            "attachments": [
                {
                    "filename": item.filename,
                    "content_type": item.content_type,
                    "size": item.size,
                    "sha256": item.sha256,
                }
                for item in self.attachments
            ],
            "warnings": self.warnings,
        }


def parse_eml(file_path: str | Path) -> EmailArtifact:
    """Parse an EML file without executing or saving its attachments."""

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Email file not found: {path}")

    if not path.is_file():
        raise ValueError("Input must be a regular file.")

    if path.suffix.lower() != ".eml":
        raise ValueError("Only .eml files are supported.")

    raw = path.read_bytes()

    if not raw:
        raise ValueError("Email file is empty.")

    message = BytesParser(policy=policy.default).parsebytes(raw)
    warnings: list[str] = []

    if not message.keys():
        warnings.append("No email headers were detected.")

    attachments: list[AttachmentArtifact] = []
    text_parts: list[str] = []
    has_html_body = False

    for part in message.walk():
        if part.is_multipart():
            continue

        content_type = part.get_content_type()
        filename = part.get_filename()
        payload = part.get_payload(decode=True) or b""

        if filename or part.get_content_disposition() == "attachment":
            attachments.append(
                AttachmentArtifact(
                    filename=filename,
                    content_type=content_type,
                    size=len(payload),
                    sha256=hashlib.sha256(payload).hexdigest(),
                )
            )
            continue

        if content_type == "text/plain":
            try:
                text_parts.append(part.get_content())
            except (LookupError, UnicodeDecodeError, ValueError):
                warnings.append("A text body part could not be decoded.")

        elif content_type == "text/html":
            has_html_body = True

    if not message.get("From"):
        warnings.append("Sender header is missing.")

    if not message.get("Date"):
        warnings.append("Date header is missing.")

    return EmailArtifact(
        source_file=path.name,
        subject=str(message.get("Subject", "")),
        sender=str(message.get("From", "")),
        reply_to=[str(value) for value in message.get_all("Reply-To", [])],
        return_path=str(message.get("Return-Path", "")),
        recipients=[
            str(value)
            for header in ("To", "Cc", "Bcc")
            for value in message.get_all(header, [])
        ],
        date=str(message.get("Date", "")),
        message_id=str(message.get("Message-ID", "")),
        received_headers=[
            str(value) for value in message.get_all("Received", [])
        ],
        authentication_results=[
            str(value)
            for value in message.get_all("Authentication-Results", [])
        ],
        text_body="\n".join(text_parts),
        has_html_body=has_html_body,
        attachments=attachments,
        warnings=warnings,
    )
