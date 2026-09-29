from dataclasses import dataclass
import math
import re


@dataclass
class SpamSummary:
    available: bool
    verdict: str
    score: float | None
    required_score: float | None
    level: str | None
    tests: list[str]
    autolearn: str | None
    version: str | None
    checker_version: str | None
    raw_status: str | None


def analyze_spam_headers(headers: list[tuple[str, str]]) -> SpamSummary:
    grouped = _group_headers(headers)
    spam_status = grouped.get("x-spam-status")
    spam_level = grouped.get("x-spam-level")
    checker_version = grouped.get("x-spam-checker-version")

    if not (spam_status or spam_level or checker_version):
        return SpamSummary(
            available=False,
            verdict="Unknown",
            score=None,
            required_score=None,
            level=None,
            tests=[],
            autolearn=None,
            version=None,
            checker_version=None,
            raw_status=None,
        )

    score = _extract_float(spam_status, "score")
    required_score = _extract_float(spam_status, "required")
    tests = _extract_tests(spam_status)
    autolearn = _extract_token(spam_status, "autolearn")
    version = _extract_token(spam_status, "version")
    verdict = _extract_verdict(spam_status, score, required_score)

    return SpamSummary(
        available=True,
        verdict=verdict,
        score=score,
        required_score=required_score,
        level=spam_level,
        tests=tests,
        autolearn=autolearn,
        version=version,
        checker_version=checker_version,
        raw_status=spam_status,
    )


def _group_headers(headers: list[tuple[str, str]]) -> dict[str, str]:
    grouped: dict[str, str] = {}
    for name, value in headers:
        key = name.lower()
        if key not in grouped:
            grouped[key] = " ".join(value.split())
    return grouped


def _extract_token(raw_status: str | None, key: str) -> str | None:
    if not raw_status:
        return None

    match = re.search(rf"{re.escape(key)}=([^\s]+)", raw_status)
    return match.group(1) if match else None


def _extract_float(raw_status: str | None, key: str) -> float | None:
    token = _extract_token(raw_status, key)
    if not token:
        return None
    try:
        value = float(token)
    except ValueError:
        return None
    return value if math.isfinite(value) else None


def _extract_tests(raw_status: str | None) -> list[str]:
    if not raw_status:
        return []

    match = re.search(r"tests=(.*?)(?:\s+[a-zA-Z_]+=[^\s]+|$)", raw_status)
    if not match:
        return []

    tests_raw = match.group(1).strip()
    if not tests_raw:
        return []

    return [value.strip() for value in tests_raw.split(",") if value.strip()]


def _extract_verdict(raw_status: str | None, score: float | None, required_score: float | None) -> str:
    status_token = _extract_status_token(raw_status)
    if status_token == "yes":
        return "Spam"
    if status_token == "no":
        return "Not Spam"
    if score is not None and required_score is not None:
        return "Spam" if score >= required_score else "Not Spam"
    return "Unknown"


def _extract_status_token(raw_status: str | None) -> str | None:
    if not raw_status:
        return None
    match = re.match(r"\s*([^,\s]+)", raw_status)
    return match.group(1).lower() if match else None
