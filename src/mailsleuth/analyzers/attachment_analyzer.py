"""Safe static attachment analysis without executing attachment content."""

from __future__ import annotations

import hashlib
import mimetypes
from dataclasses import asdict, dataclass, field
from pathlib import Path


RISKY_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".com", ".msi",
    ".bat", ".cmd", ".ps1", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".hta", ".iso",
    ".img", ".lnk", ".jar", ".chm",
}

DOUBLE_EXTENSION_PATTERN = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".jpg", ".jpeg", ".png", ".txt",
}


SIGNATURES = {
    "PDF": (b"%PDF-",),
    "PNG": (b"\x89PNG\r\n\x1a\n",),
    "JPEG": (b"\xff\xd8\xff",),
    "GIF": (b"GIF87a", b"GIF89a"),
    "ZIP": (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"),
    "OLE": (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",),
    "GZIP": (b"\x1f\x8b",),
    "RAR": (b"Rar!\x1a\x07",),
    "7ZIP": (b"7z\xbc\xaf\x27\x1c",),
    "ELF": (b"\x7fELF",),
}


EXTENSION_SIGNATURES = {
    ".pdf": {"PDF"},
    ".png": {"PNG"},
    ".jpg": {"JPEG"},
    ".jpeg": {"JPEG"},
    ".gif": {"GIF"},
    ".zip": {"ZIP"},
    ".doc": {"OLE"},
    ".xls": {"OLE"},
    ".gz": {"GZIP"},
    ".rar": {"RAR"},
    ".7z": {"7ZIP"},
}


@dataclass
class AttachmentFinding:
    indicator: str
    severity: str
    evidence: str
    explanation: str


@dataclass
class AttachmentAnalysis:
    filename: str
    size: int
    sha256: str
    declared_mime: str
    detected_signature: str
    findings: list[AttachmentFinding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "filename": self.filename,
            "size": self.size,
            "sha256": self.sha256,
            "declared_mime": self.declared_mime,
            "detected_signature": self.detected_signature,
            "findings": [asdict(item) for item in self.findings],
        }


def detect_signature(content: bytes) -> str:
    """Identify a limited set of common file signatures."""

    for file_type, signatures in SIGNATURES.items():
        if any(content.startswith(signature) for signature in signatures):
            return file_type

    return "UNKNOWN"


def analyze_attachment(
    filename: str,
    content: bytes,
    declared_mime: str = "application/octet-stream",
    max_size_bytes: int = 25 * 1024 * 1024,
) -> AttachmentAnalysis:
    """Analyze attachment bytes without writing or executing them."""

    if not isinstance(content, bytes):
        raise TypeError("Attachment content must be bytes.")

    safe_name = Path(filename).name
    extension = Path(safe_name).suffix.lower()
    signature = detect_signature(content)
    findings: list[AttachmentFinding] = []

    if not content:
        findings.append(AttachmentFinding(
            indicator="Empty attachment",
            severity="low",
            evidence="Attachment size is 0 bytes",
            explanation="The attachment contains no file content.",
        ))

    if len(content) > max_size_bytes:
        findings.append(AttachmentFinding(
            indicator="Large attachment",
            severity="medium",
            evidence=f"Attachment size: {len(content)} bytes",
            explanation="The attachment exceeds the configured size threshold.",
        ))

    if extension in RISKY_EXTENSIONS:
        findings.append(AttachmentFinding(
            indicator="Potentially executable file type",
            severity="high",
            evidence=f"File extension: {extension}",
            explanation="This extension can represent executable or script content.",
        ))

    expected_signatures = EXTENSION_SIGNATURES.get(extension)

    if expected_signatures and signature not in expected_signatures:
        findings.append(AttachmentFinding(
            indicator="File extension and signature mismatch",
            severity="high",
            evidence=f"Extension: {extension}; detected signature: {signature}",
            explanation="The file content does not match the expected known signature.",
        ))

    if extension in DOUBLE_EXTENSION_PATTERN:
        lower_name = safe_name.lower()
        if any(
            lower_name.endswith(risky)
            and lower_name[:-len(risky)].endswith(tuple(DOUBLE_EXTENSION_PATTERN))
            for risky in RISKY_EXTENSIONS
        ):
            findings.append(AttachmentFinding(
                indicator="Potential double-extension filename",
                severity="high",
                evidence=f"Filename: {safe_name}",
                explanation="A risky extension appears after a document-like extension.",
            ))

    guessed_mime, _ = mimetypes.guess_type(safe_name)

    if guessed_mime and declared_mime:
        if guessed_mime != declared_mime:
            findings.append(AttachmentFinding(
                indicator="Declared MIME and filename MIME mismatch",
                severity="medium",
                evidence=f"Filename MIME: {guessed_mime}; declared MIME: {declared_mime}",
                explanation="The MIME declaration differs from the filename-based guess.",
            ))

    return AttachmentAnalysis(
        filename=safe_name,
        size=len(content),
        sha256=hashlib.sha256(content).hexdigest(),
        declared_mime=declared_mime,
        detected_signature=signature,
        findings=findings,
    )
