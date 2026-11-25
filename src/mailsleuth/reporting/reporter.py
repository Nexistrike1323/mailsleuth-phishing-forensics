"""JSON and Markdown investigation report generation."""

import json
from pathlib import Path


def write_reports(result, output_dir="reports"):
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    case_id = result["case_id"]

    json_path = directory / f"{case_id}.json"
    markdown_path = directory / f"{case_id}.md"

    json_path.write_text(
        json.dumps(result, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    email = result["email"]
    assessment = result["assessment"]
    lines = [
        "# MailSleuth Investigation Report",
        "",
        f"- Case ID: `{case_id}`",
        f"- Source: `{email['source_file']}`",
        f"- Subject: {email['subject']}",
        f"- Sender: {email['sender']}",
        f"- Verdict: **{assessment['verdict']}**",
        f"- Risk score: **{assessment['risk_score']}/100**",
        "",
        "## Findings",
        "",
    ]

    if not result["findings"]:
        lines.append("No findings were generated.")
    for item in result["findings"]:
        lines += [
            f"### [{item['severity'].upper()}] {item['indicator']}",
            f"- Category: {item['category']}",
            f"- Explanation: {item['explanation']}",
            f"- Evidence: `{item['evidence']}`",
            "",
        ]

    lines += [
        "## Limitations",
        "",
        *[f"- {item}" for item in assessment["limitations"]],
        "- This report is for analyst triage and is not a malware certification.",
    ]

    markdown_path.write_text("\n".join(lines), encoding="utf-8")
    return json_path, markdown_path
