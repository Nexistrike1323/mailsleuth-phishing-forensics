"""Evidence-based sender identity and header mismatch analysis."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from email.utils import getaddresses
from typing import Iterable


@dataclass
class SenderFinding:
    indicator: str
    severity: str
    evidence: str
    explanation: str


@dataclass
class SenderAnalysis:
    from_addresses: list[str] = field(default_factory=list)
    reply_to_addresses: list[str] = field(default_factory=list)
    return_path_addresses: list[str] = field(default_factory=list)
    findings: list[SenderFinding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "from_addresses": self.from_addresses,
            "reply_to_addresses": self.reply_to_addresses,
            "return_path_addresses": self.return_path_addresses,
            "findings": [asdict(item) for item in self.findings],
        }


def _extract_addresses(values: Iterable[str]) -> list[str]:
    parsed = getaddresses(list(values))
    return [
        address.strip().lower()
        for _, address in parsed
        if address and "@" in address
    ]


def _domain(address: str) -> str:
    return address.rsplit("@", 1)[-1].rstrip(".").lower()


def analyze_sender_headers(
    from_header: str,
    reply_to_headers: list[str] | None = None,
    return_path_header: str | None = None,
) -> SenderAnalysis:
    """Compare sender-related headers without assuming mismatch means phishing."""

    reply_to_headers = reply_to_headers or []
    return_path_header = return_path_header or ""

    from_addresses = _extract_addresses([from_header])
    reply_addresses = _extract_addresses(reply_to_headers)
    return_addresses = _extract_addresses([return_path_header])

    result = SenderAnalysis(
        from_addresses=from_addresses,
        reply_to_addresses=reply_addresses,
        return_path_addresses=return_addresses,
    )

    if not from_addresses:
        result.findings.append(SenderFinding(
            indicator="Missing or invalid From address",
            severity="medium",
            evidence=f"From: {from_header!r}",
            explanation="A valid sender email address could not be extracted.",
        ))
        return result

    if len(from_addresses) > 1:
        result.findings.append(SenderFinding(
            indicator="Multiple From addresses",
            severity="high",
            evidence=f"From addresses: {from_addresses}",
            explanation="Multiple sender addresses were found in the From header.",
        ))

    from_domains = {_domain(address) for address in from_addresses}

    if reply_addresses:
        reply_domains = {_domain(address) for address in reply_addresses}

        if from_domains.isdisjoint(reply_domains):
            result.findings.append(SenderFinding(
                indicator="From and Reply-To domain mismatch",
                severity="medium",
                evidence=f"From: {from_addresses}; Reply-To: {reply_addresses}",
                explanation=(
                    "Replies are directed to a different domain. "
                    "This may be legitimate, but requires investigation."
                ),
            ))

    if return_addresses:
        return_domains = {_domain(address) for address in return_addresses}

        if from_domains.isdisjoint(return_domains):
            result.findings.append(SenderFinding(
                indicator="From and Return-Path domain mismatch",
                severity="low",
                evidence=f"From: {from_addresses}; Return-Path: {return_addresses}",
                explanation=(
                    "The envelope return address uses a different domain. "
                    "Mailing services and forwarding can cause legitimate differences."
                ),
            ))

    return result
