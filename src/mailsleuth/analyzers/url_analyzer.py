"""Extract and statically inspect URLs found in email content."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass, field
from urllib.parse import unquote, urlsplit


URL_PATTERN = re.compile(
    r"""(?i)\b(?:https?://|hxxps?://|www\.)[^\s<>"']+"""
)

SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rb.gy",
}

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".scr", ".js", ".vbs", ".bat", ".cmd",
    ".ps1", ".hta", ".iso", ".img", ".msi",
}


@dataclass
class URLFinding:
    original_url: str
    normalized_url: str
    domain: str
    scheme: str
    path: str
    indicators: list[str] = field(default_factory=list)

    @property
    def suspicious(self) -> bool:
        return bool(self.indicators)

    def to_dict(self) -> dict:
        return asdict(self) | {"suspicious": self.suspicious}


def _normalize_url(value: str) -> str:
    value = value.strip().rstrip(".,;:!?)\"]}")
    value = value.replace("hxxps://", "https://")
    value = value.replace("hxxp://", "http://")

    if value.lower().startswith("www."):
        value = "http://" + value

    return value


def analyze_url(value: str) -> URLFinding:
    normalized = _normalize_url(value)
    indicators: list[str] = []

    try:
        parsed = urlsplit(normalized)
        hostname = parsed.hostname or ""
        scheme = parsed.scheme.lower()
        domain = hostname.encode("idna").decode("ascii").lower()
        path = unquote(parsed.path)

        if scheme not in {"http", "https"}:
            indicators.append("Unusual or unsupported URL scheme")

        if parsed.username or parsed.password:
            indicators.append("URL contains embedded user information")

        if scheme == "http":
            indicators.append("Unencrypted HTTP connection")

        if domain.startswith("xn--") or ".xn--" in domain:
            indicators.append("Internationalized/punycode domain")

        try:
            ipaddress.ip_address(domain)
            indicators.append("URL uses an IP address instead of a domain")
        except ValueError:
            pass

        if domain in SHORTENERS:
            indicators.append("Known URL shortening service")

        if len(domain) > 50:
            indicators.append("Unusually long hostname")

        if domain.count(".") >= 4:
            indicators.append("Hostname contains many subdomains")

        if "@" in normalized:
            indicators.append("URL contains an @ character")

        if re.search(r"%[0-9a-fA-F]{2}", normalized):
            indicators.append("URL contains percent-encoded characters")

        if any(path.lower().endswith(ext) for ext in SUSPICIOUS_EXTENSIONS):
            indicators.append("URL path ends with a potentially risky file extension")

        if len(normalized) > 200:
            indicators.append("Unusually long URL")

        if not hostname:
            indicators.append("URL hostname is missing")

    except (ValueError, UnicodeError):
        domain = ""
        scheme = ""
        path = ""
        indicators.append("URL could not be parsed safely")

    return URLFinding(
        original_url=value,
        normalized_url=normalized,
        domain=domain,
        scheme=scheme,
        path=path,
        indicators=indicators,
    )


def extract_urls(content: str) -> list[URLFinding]:
    """Extract unique URLs and inspect them without making network requests."""

    results: list[URLFinding] = []
    seen: set[str] = set()

    for match in URL_PATTERN.finditer(content):
        original = match.group(0)
        normalized = _normalize_url(original)

        if normalized in seen:
            continue

        seen.add(normalized)
        results.append(analyze_url(original))

    return results
