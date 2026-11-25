"""Local FastAPI interface for the MailSleuth investigation engine."""

from __future__ import annotations

import re
import tempfile
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from mailsleuth.core.pipeline import investigate
from mailsleuth.reporting.reporter import write_reports
from mailsleuth.storage.database import CaseDatabase

ROOT = Path(__file__).resolve().parents[2]
DB_PATH = ROOT / "data" / "mailsleuth.db"
REPORTS = ROOT / "reports"
MAX_UPLOAD = 20 * 1024 * 1024

app = FastAPI(
    title="MailSleuth API",
    description="Local-first phishing email investigation API",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "MailSleuth API"}


@app.post("/api/analyze")
async def analyze_email(file: UploadFile = File(...)):
    filename = Path(file.filename or "").name

    if not filename.lower().endswith(".eml"):
        raise HTTPException(400, "Only .eml files are supported.")

    content = await file.read(MAX_UPLOAD + 1)

    if not content:
        raise HTTPException(400, "Uploaded email is empty.")

    if len(content) > MAX_UPLOAD:
        raise HTTPException(413, "Maximum email size is 20 MB.")

    temp_path = None

    try:
        with tempfile.NamedTemporaryFile(
            prefix="mailsleuth_", suffix=".eml", delete=False
        ) as temporary:
            temporary.write(content)
            temp_path = Path(temporary.name)

        result = investigate(temp_path, DB_PATH)
        write_reports(result, REPORTS)

        return result

    except (ValueError, OSError) as exc:
        raise HTTPException(422, str(exc)) from exc

    except Exception as exc:
        # Avoid exposing internal paths or stack traces to the browser.
        raise HTTPException(500, "Investigation failed. Check the API log.") from exc

    finally:
        await file.close()
        if temp_path and temp_path.exists():
            temp_path.unlink()


@app.get("/api/cases")
def list_cases():
    return CaseDatabase(DB_PATH).list_cases()


@app.get("/api/cases/{case_id}")
def get_case(case_id: str):
    if not re.fullmatch(r"MS-[A-F0-9]{12}", case_id):
        raise HTTPException(400, "Invalid case ID.")

    case = CaseDatabase(DB_PATH).get_case(case_id)

    if case is None:
        raise HTTPException(404, "Case not found.")

    return case


@app.get("/api/reports/{case_id}/{report_format}")
def download_report(case_id: str, report_format: str):
    if not re.fullmatch(r"MS-[A-F0-9]{12}", case_id):
        raise HTTPException(400, "Invalid case ID.")

    extensions = {"json": "json", "markdown": "md"}
    extension = extensions.get(report_format)

    if not extension:
        raise HTTPException(400, "Format must be json or markdown.")

    path = REPORTS / f"{case_id}.{extension}"

    if not path.is_file():
        raise HTTPException(404, "Report not found.")

    return FileResponse(
        path,
        filename=path.name,
        media_type="application/octet-stream",
    )
