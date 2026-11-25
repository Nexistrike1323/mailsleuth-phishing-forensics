from email.message import EmailMessage
from pathlib import Path

from mailsleuth.core.pipeline import investigate
from mailsleuth.reporting.reporter import write_reports
from mailsleuth.storage.database import CaseDatabase


def make_email(path: Path, sender="billing@example.org",
               reply_to=None, body="Hello, this is a normal message."):
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = "analyst@example.net"
    msg["Subject"] = "Invoice update"
    msg["Date"] = "Tue, 25 Nov 2025 10:00:00 +0000"
    msg["Message-ID"] = "<test@example.org>"
    if reply_to:
        msg["Reply-To"] = reply_to
    msg.set_content(body)
    path.write_bytes(msg.as_bytes())


def test_benign_email_pipeline(tmp_path):
    eml = tmp_path / "benign.eml"
    make_email(eml)
    result = investigate(eml, tmp_path / "cases.db")
    assert result["case_id"].startswith("MS-")
    assert result["assessment"]["verdict"] == "NO_STRONG_INDICATORS"
    assert CaseDatabase(tmp_path / "cases.db").get_case(
        result["case_id"]
    ) is not None


def test_reply_to_mismatch_is_reported(tmp_path):
    eml = tmp_path / "mismatch.eml"
    make_email(eml, reply_to="attacker@other.example")
    result = investigate(eml, tmp_path / "cases.db")
    assert any("Reply-To" in f["indicator"] for f in result["findings"])


def test_suspicious_url_is_extracted(tmp_path):
    eml = tmp_path / "url.eml"
    make_email(eml, body="Please visit http://192.0.2.10/login")
    result = investigate(eml, tmp_path / "cases.db")
    assert result["urls"]
    assert any(f["category"] == "url" for f in result["findings"])


def test_reports_are_created(tmp_path):
    eml = tmp_path / "report.eml"
    make_email(eml)
    result = investigate(eml, tmp_path / "cases.db")
    json_path, md_path = write_reports(result, tmp_path / "reports")
    assert json_path.is_file()
    assert md_path.is_file()


def test_invalid_extension_rejected(tmp_path):
    file = tmp_path / "wrong.txt"
    file.write_text("not an email")
    try:
        investigate(file, tmp_path / "cases.db")
    except ValueError:
        pass
    else:
        raise AssertionError("Non-EML input should be rejected")
