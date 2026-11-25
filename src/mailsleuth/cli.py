"""MailSleuth command-line interface."""

import argparse
import json
import sys

from mailsleuth.core.pipeline import investigate
from mailsleuth.reporting.reporter import write_reports
from mailsleuth.storage.database import CaseDatabase


def main():
    parser = argparse.ArgumentParser(
        prog="mailsleuth",
        description="Evidence-based phishing email investigation",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    analyze = commands.add_parser("analyze", help="Investigate an EML file")
    analyze.add_argument("file")
    analyze.add_argument("--db", default="data/mailsleuth.db")
    analyze.add_argument("--output", default="reports")

    listing = commands.add_parser("list", help="List investigation cases")
    listing.add_argument("--db", default="data/mailsleuth.db")

    show = commands.add_parser("show", help="Show a saved investigation")
    show.add_argument("case_id")
    show.add_argument("--db", default="data/mailsleuth.db")

    args = parser.parse_args()

    try:
        if args.command == "analyze":
            result = investigate(args.file, args.db)
            json_path, md_path = write_reports(result, args.output)
            print(f"Case: {result['case_id']}")
            print(f"Verdict: {result['assessment']['verdict']}")
            print(f"Risk score: {result['assessment']['risk_score']}/100")
            print(f"JSON report: {json_path}")
            print(f"Markdown report: {md_path}")

        elif args.command == "list":
            print(json.dumps(CaseDatabase(args.db).list_cases(), indent=2))

        elif args.command == "show":
            result = CaseDatabase(args.db).get_case(args.case_id)
            if result is None:
                print("Case not found.", file=sys.stderr)
                raise SystemExit(1)
            print(json.dumps(result, indent=2))

    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(2)


if __name__ == "__main__":
    main()
