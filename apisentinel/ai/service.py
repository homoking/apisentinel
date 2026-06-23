from __future__ import annotations

from apisentinel.core.config import get_settings
from apisentinel.scanner.models import AIAnalysis, Finding

LOCAL_KNOWLEDGE: dict[str, AIAnalysis] = {
    "missing-rate-limiting": AIAnalysis(
        explanation="The API does not show evidence that repeated requests are throttled.",
        attack_scenario="An attacker automates login attempts, password resets, scraping, or expensive searches until accounts or capacity are exhausted.",
        recommended_fix="Apply per-IP and per-account limits on sensitive endpoints; for login, start with 5 failed attempts per minute and progressive backoff.",
    ),
    "missing-authentication": AIAnalysis(
        explanation="The endpoint appears callable without an authenticated user or service identity.",
        attack_scenario="A malicious user calls the endpoint directly to read private data or perform actions without permission.",
        recommended_fix="Require strong authentication by default and document security requirements in OpenAPI for every non-public operation.",
    ),
    "weak-jwt-configuration": AIAnalysis(
        explanation="The token configuration may allow ambiguous or weak JWT validation.",
        attack_scenario="An attacker forges or tampers with tokens if algorithms, issuers, audiences, or secrets are not strictly verified.",
        recommended_fix="Pin accepted algorithms, reject alg=none, validate issuer/audience/expiry, rotate keys, and prefer asymmetric signing for distributed systems.",
    ),
    "missing-security-header": AIAnalysis(
        explanation="A browser-facing response is missing a defense-in-depth HTTP security header.",
        attack_scenario="If an API is accessed from browsers, missing headers can make MIME sniffing, clickjacking, or injection impact worse.",
        recommended_fix="Set HSTS, X-Content-Type-Options: nosniff, and a minimal Content-Security-Policy at the gateway or application edge.",
    ),
    "dangerous-http-method": AIAnalysis(
        explanation="A method with destructive or historically risky behavior is exposed.",
        attack_scenario="An attacker abuses DELETE to remove data or TRACE to inspect reflected request data where intermediaries permit it.",
        recommended_fix="Disable unused methods, require authorization and CSRF-safe designs for state changes, and log destructive operations.",
    ),
    "public-openapi": AIAnalysis(
        explanation="API documentation appears reachable from the public internet.",
        attack_scenario="Attackers use the schema to discover hidden endpoints, object IDs, and request shapes before probing for weaknesses.",
        recommended_fix="Keep public docs only for public APIs; otherwise require SSO/VPN, redact internal operations, and monitor schema access.",
    ),
    "idor-indicator": AIAnalysis(
        explanation="The endpoint uses direct object identifiers and may lack object-level authorization.",
        attack_scenario="A user changes /users/123 to /users/124 and receives another user's data because ownership is not checked.",
        recommended_fix="Authorize every object access server-side using the caller identity, tenant, role, and resource ownership; add negative tests.",
    ),
}


class AIAnalysisService:
    """Generates security guidance. Defaults to deterministic local guidance for OSS usability."""

    def __init__(self) -> None:
        self.settings = get_settings()

    async def enrich(self, findings: list[Finding]) -> list[Finding]:
        for finding in findings:
            finding.ai = await self.analyze(finding)
        return findings

    async def analyze(self, finding: Finding) -> AIAnalysis:
        # Production extension point: call OpenAI or another approved model when configured.
        # The local mode is predictable, private, and works without network/API keys.
        if finding.rule_id in LOCAL_KNOWLEDGE:
            return LOCAL_KNOWLEDGE[finding.rule_id]
        return AIAnalysis(
            explanation=f"{finding.title}: {finding.description}",
            attack_scenario="An attacker may combine this weakness with endpoint knowledge or stolen credentials to increase impact.",
            recommended_fix="Validate the endpoint against your threat model, add automated tests, and enforce secure defaults at the API gateway and service layer.",
        )
