"""Extract SPF, DKIM and DMARC authentication evidence from email headers."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field


VALID_RESULTS = {
    "pass",
    "fail",
    "softfail",
    "neutral",
    "none",
    "temperror",
    "permerror",
}

AUTH_PATTERN = re.compile(
    r"(?i)\b(spf|dkim|dmarc)\s*=\s*"
    r"(pass|fail|softfail|neutral|none|temperror|permerror)\b"
)

PROPERTY_PATTERN = re.compile(
    r"(?i)\b(?:header\.|smtp\.)?"
    r"(?:from|d|i|helo|mailfrom)\s*=\s*([^;\s]+)"
)


@dataclass
class AuthenticationFinding:
    mechanism: str
    result: str
    domain: str | None
    evidence: str
    explanation: str


@dataclass
class AuthenticationAnalysis:
    findings: list[AuthenticationFinding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "findings": [asdict(item) for item in self.findings],
            "warnings": self.warnings,
        }


def analyze_authentication(
    authentication_headers: list[str] | None,
) -> AuthenticationAnalysis:
    """Parse authentication results already present in supplied email headers.

    This function does not perform live SPF, DKIM or DMARC verification.
    """

    result = AuthenticationAnalysis()
    headers = authentication_headers or []

    if not headers:
        result.warnings.append(
            "No Authentication-Results header supplied; "
            "authentication status is unknown."
        )
        return result

    for header in headers:
        matches = list(AUTH_PATTERN.finditer(header))

        if not matches:
            result.warnings.append(
                "Authentication-Results header contained no recognized "
                "SPF, DKIM or DMARC result."
            )
            continue

        for match in matches:
            mechanism = match.group(1).lower()
            status = match.group(2).lower()

            domain = None
            property_match = PROPERTY_PATTERN.search(
                header[match.end():]
            )

            if property_match:
                domain = property_match.group(1).strip("\"'")

            explanations = {
                "pass": "The supplied header reports successful authentication.",
                "fail": "The supplied header reports authentication failure.",
                "softfail": "The supplied header reports a soft authentication failure.",
                "neutral": "The supplied header reports a neutral authentication result.",
                "none": "No authentication result was established.",
                "temperror": "A temporary authentication evaluation error was reported.",
                "permerror": "A permanent authentication evaluation error was reported.",
            }

            result.findings.append(
                AuthenticationFinding(
                    mechanism=mechanism,
                    result=status,
                    domain=domain,
                    evidence=match.group(0),
                    explanation=explanations[status],
                )
            )

    if not result.findings and not result.warnings:
        result.warnings.append("No authentication evidence was extracted.")

    return result
