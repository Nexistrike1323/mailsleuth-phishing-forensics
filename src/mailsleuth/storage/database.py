"""Persistent SQLite storage for MailSleuth investigations."""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_DB = Path("data/mailsleuth.db")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class CaseDatabase:
    def __init__(self, db_path: str | Path = DEFAULT_DB):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS cases (
                    case_id TEXT PRIMARY KEY,
                    source_file TEXT NOT NULL,
                    subject TEXT NOT NULL DEFAULT '',
                    sender TEXT NOT NULL DEFAULT '',
                    verdict TEXT NOT NULL DEFAULT 'PENDING',
                    risk_score INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS evidence (
                    evidence_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id TEXT NOT NULL,
                    evidence_type TEXT NOT NULL,
                    description TEXT NOT NULL,
                    sha256 TEXT,
                    details_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(case_id) REFERENCES cases(case_id)
                        ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS findings (
                    finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id TEXT NOT NULL,
                    category TEXT NOT NULL,
                    indicator TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    explanation TEXT NOT NULL,
                    evidence TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(case_id) REFERENCES cases(case_id)
                        ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_evidence_case
                    ON evidence(case_id);

                CREATE INDEX IF NOT EXISTS idx_findings_case
                    ON findings(case_id);
            """)

    def create_case(
        self,
        source_file: str,
        subject: str = "",
        sender: str = "",
    ) -> str:
        case_id = f"MS-{uuid.uuid4().hex[:12].upper()}"
        timestamp = utc_now()

        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO cases (
                    case_id, source_file, subject, sender,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (case_id, Path(source_file).name, subject, sender,
                 timestamp, timestamp),
            )

        return case_id

    def add_evidence(
        self,
        case_id: str,
        evidence_type: str,
        description: str,
        sha256: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> int:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO evidence (
                    case_id, evidence_type, description,
                    sha256, details_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    case_id,
                    evidence_type,
                    description,
                    sha256,
                    json.dumps(details or {}, ensure_ascii=False),
                    utc_now(),
                ),
            )
            connection.execute(
                "UPDATE cases SET updated_at = ? WHERE case_id = ?",
                (utc_now(), case_id),
            )
            return int(cursor.lastrowid)

    def add_finding(
        self,
        case_id: str,
        category: str,
        indicator: str,
        severity: str,
        explanation: str,
        evidence: str = "",
    ) -> int:
        allowed = {"info", "low", "medium", "high", "critical"}
        severity = severity.lower()

        if severity not in allowed:
            raise ValueError(f"Invalid severity: {severity}")

        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO findings (
                    case_id, category, indicator, severity,
                    explanation, evidence, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    case_id, category, indicator, severity,
                    explanation, evidence, utc_now(),
                ),
            )
            connection.execute(
                "UPDATE cases SET updated_at = ? WHERE case_id = ?",
                (utc_now(), case_id),
            )
            return int(cursor.lastrowid)

    def update_verdict(
        self,
        case_id: str,
        verdict: str,
        risk_score: int,
    ) -> None:
        if not 0 <= risk_score <= 100:
            raise ValueError("Risk score must be between 0 and 100.")

        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE cases
                SET verdict = ?, risk_score = ?, updated_at = ?
                WHERE case_id = ?
                """,
                (verdict, risk_score, utc_now(), case_id),
            )
            if cursor.rowcount == 0:
                raise ValueError(f"Case not found: {case_id}")

    def get_case(self, case_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            case = connection.execute(
                "SELECT * FROM cases WHERE case_id = ?", (case_id,)
            ).fetchone()

            if case is None:
                return None

            evidence = connection.execute(
                "SELECT * FROM evidence WHERE case_id = ? ORDER BY evidence_id",
                (case_id,),
            ).fetchall()

            findings = connection.execute(
                "SELECT * FROM findings WHERE case_id = ? ORDER BY finding_id",
                (case_id,),
            ).fetchall()

        result = dict(case)
        result["evidence"] = [
            {
                **dict(row),
                "details": json.loads(row["details_json"]),
            }
            for row in evidence
        ]
        result["findings"] = [dict(row) for row in findings]
        return result

    def list_cases(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM cases ORDER BY created_at DESC"
            ).fetchall()
        return [dict(row) for row in rows]
