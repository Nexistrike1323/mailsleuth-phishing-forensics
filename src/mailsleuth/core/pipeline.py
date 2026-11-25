"""End-to-end email investigation pipeline."""

from __future__ import annotations

import hashlib
from email import policy
from email.parser import BytesParser
from pathlib import Path

from mailsleuth.analyzers.email_parser import parse_eml
from mailsleuth.analyzers.url_analyzer import extract_urls
from mailsleuth.analyzers.sender_analyzer import analyze_sender_headers
from mailsleuth.analyzers.auth_analyzer import analyze_authentication
from mailsleuth.analyzers.attachment_analyzer import analyze_attachment
from mailsleuth.core.verdict import assess
from mailsleuth.storage.database import CaseDatabase


def investigate(file_path, db_path="data/mailsleuth.db"):
    path = Path(file_path)
    if not path.is_file() or path.suffix.lower() != ".eml":
        raise ValueError("Provide an existing .eml file.")
    if path.stat().st_size > 20 * 1024 * 1024:
        raise ValueError("Email exceeds the 20 MiB input limit.")

    email = parse_eml(path)
    raw = path.read_bytes()
    message = BytesParser(policy=policy.default).parsebytes(raw)

    sender = analyze_sender_headers(
        email.sender, email.reply_to, email.return_path
    )
    auth = analyze_authentication(email.authentication_results)
    urls = extract_urls(email.text_body + "\n" + "\n".join(
        str(part.get_content())
        for part in message.walk()
        if not part.is_multipart()
        and part.get_content_type() == "text/html"
        and isinstance(part.get_content(), str)
    ))

    attachment_results = []
    for part in message.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if filename or part.get_content_disposition() == "attachment":
            payload = part.get_payload(decode=True) or b""
            attachment_results.append(analyze_attachment(
                filename or "unnamed-attachment",
                payload,
                part.get_content_type(),
            ))

    findings = []

    def add(category, indicator, severity, explanation, evidence=""):
        findings.append({
            "category": category,
            "indicator": indicator,
            "severity": severity,
            "explanation": explanation,
            "evidence": evidence,
        })

    for item in sender.findings:
        add("sender", item.indicator, item.severity,
            item.explanation, item.evidence)

    for item in auth.findings:
        if item.result in {"fail", "softfail", "permerror"}:
            severity = "high" if item.result == "fail" else "medium"
        elif item.result in {"temperror", "none"}:
            severity = "info"
        else:
            severity = "info"
        add("authentication", f"{item.mechanism.upper()} {item.result}",
            severity, item.explanation, item.evidence)

    for item in urls:
        for indicator in item.indicators:
            add("url", indicator, "medium",
                "Static URL characteristic requiring analyst review.",
                item.normalized_url)

    for attachment in attachment_results:
        for item in attachment.findings:
            add("attachment", item.indicator, item.severity,
                item.explanation, item.evidence)

    for warning in email.warnings + auth.warnings:
        add("parser", "Analysis limitation or missing evidence",
            "info", warning)

    assessment = assess(findings)
    db = CaseDatabase(db_path)
    case_id = db.create_case(path.name, email.subject, email.sender)

    db.add_evidence(
        case_id, "email", "Original EML SHA-256",
        hashlib.sha256(raw).hexdigest(),
        {"source_file": path.name, "message_id": email.message_id},
    )

    for item in urls:
        db.add_evidence(case_id, "url", item.normalized_url,
                        details=item.to_dict())

    for item in attachment_results:
        db.add_evidence(case_id, "attachment",
                        f"Attachment: {item.filename}",
                        item.sha256, item.to_dict())

    for item in findings:
        db.add_finding(
            case_id, item["category"], item["indicator"],
            item["severity"], item["explanation"], item["evidence"],
        )

    db.update_verdict(case_id, assessment["verdict"],
                      assessment["risk_score"])

    return {
        "case_id": case_id,
        "email": email.to_dict(),
        "sender_analysis": sender.to_dict(),
        "authentication_analysis": auth.to_dict(),
        "urls": [item.to_dict() for item in urls],
        "attachments": [item.to_dict() for item in attachment_results],
        "findings": findings,
        "assessment": assessment,
    }
