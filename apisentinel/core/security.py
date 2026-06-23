from __future__ import annotations

from enum import StrEnum


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 30,
    Severity.HIGH: 20,
    Severity.MEDIUM: 10,
    Severity.LOW: 4,
    Severity.INFO: 1,
}


def calculate_security_score(severities: list[Severity]) -> int:
    """Return a 0-100 score where severe and repeated issues reduce confidence."""
    penalty = sum(SEVERITY_WEIGHTS[severity] for severity in severities)
    return max(0, min(100, 100 - penalty))


def severity_distribution(severities: list[Severity]) -> dict[str, int]:
    return {severity.value: severities.count(severity) for severity in Severity}
