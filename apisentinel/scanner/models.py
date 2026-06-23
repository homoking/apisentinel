from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import AnyHttpUrl, BaseModel, Field

from apisentinel.core.security import Severity, calculate_security_score, severity_distribution


class HttpMethod(StrEnum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"
    TRACE = "TRACE"


class Endpoint(BaseModel):
    path: str
    method: HttpMethod
    operation_id: str | None = None
    requires_auth: bool = False
    parameters: list[dict[str, Any]] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class DiscoveryResult(BaseModel):
    target: str
    base_url: str | None = None
    openapi_url: str | None = None
    title: str | None = None
    version: str | None = None
    endpoints: list[Endpoint] = Field(default_factory=list)
    raw_spec: dict[str, Any] | None = None


class AIAnalysis(BaseModel):
    explanation: str
    attack_scenario: str
    recommended_fix: str


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex)
    rule_id: str
    title: str
    severity: Severity
    endpoint: str | None = None
    method: HttpMethod | None = None
    description: str
    why_it_matters: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    ai: AIAnalysis | None = None


class ScanSummary(BaseModel):
    score: int
    findings_count: int
    severity_distribution: dict[str, int]


class ScanResult(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex)
    target: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    discovery: DiscoveryResult
    findings: list[Finding]
    summary: ScanSummary

    @classmethod
    def from_findings(
        cls,
        target: str,
        discovery: DiscoveryResult,
        findings: list[Finding],
    ) -> "ScanResult":
        severities = [finding.severity for finding in findings]
        return cls(
            target=target,
            discovery=discovery,
            findings=findings,
            summary=ScanSummary(
                score=calculate_security_score(severities),
                findings_count=len(findings),
                severity_distribution=severity_distribution(severities),
            ),
        )


class ScanRequest(BaseModel):
    target: str | AnyHttpUrl
