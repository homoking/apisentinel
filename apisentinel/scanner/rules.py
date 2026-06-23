from __future__ import annotations

import base64
import json
import re
from collections.abc import Iterable

from apisentinel.core.security import Severity
from apisentinel.scanner.models import DiscoveryResult, Finding, HttpMethod

SECURITY_HEADERS = {
    "strict-transport-security": "HTTP Strict Transport Security protects users from protocol downgrade attacks.",
    "x-content-type-options": "X-Content-Type-Options prevents MIME sniffing issues.",
    "content-security-policy": "Content Security Policy reduces browser-based injection impact.",
}
DANGEROUS_METHODS = {HttpMethod.TRACE, HttpMethod.DELETE}
IDOR_PARAMETER_HINTS = {"id", "user_id", "account_id", "customer_id", "tenant_id", "org_id"}


class RuleContext:
    def __init__(self, discovery: DiscoveryResult, observed_headers: dict[str, str] | None = None) -> None:
        self.discovery = discovery
        self.observed_headers = {k.lower(): v for k, v in (observed_headers or {}).items()}


class BaseRule:
    id: str
    title: str

    def check(self, context: RuleContext) -> Iterable[Finding]:
        raise NotImplementedError


class PublicOpenAPIRule(BaseRule):
    id = "public-openapi"
    title = "Public Swagger/OpenAPI exposure"

    def check(self, context: RuleContext) -> Iterable[Finding]:
        if context.discovery.openapi_url and context.discovery.base_url:
            yield Finding(
                rule_id=self.id,
                title=self.title,
                severity=Severity.LOW,
                description="An OpenAPI or Swagger document appears to be publicly reachable.",
                why_it_matters="Public API documentation helps attackers enumerate endpoints, parameters, and data models.",
                evidence={"url": context.discovery.openapi_url},
            )


class MissingAuthenticationRule(BaseRule):
    id = "missing-authentication"
    title = "Missing authentication"

    def check(self, context: RuleContext) -> Iterable[Finding]:
        for endpoint in context.discovery.endpoints:
            if endpoint.method in {HttpMethod.OPTIONS, HttpMethod.HEAD}:
                continue
            if not endpoint.requires_auth:
                severity = Severity.HIGH if _looks_sensitive(endpoint.path) else Severity.MEDIUM
                yield Finding(
                    rule_id=self.id,
                    title=self.title,
                    severity=severity,
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    description=f"{endpoint.method} {endpoint.path} does not declare an authentication requirement.",
                    why_it_matters="Unauthenticated API operations may expose sensitive data or allow unauthorized state changes.",
                    evidence={"path": endpoint.path, "method": endpoint.method.value},
                )


class DangerousMethodsRule(BaseRule):
    id = "dangerous-http-method"
    title = "Dangerous HTTP method"

    def check(self, context: RuleContext) -> Iterable[Finding]:
        for endpoint in context.discovery.endpoints:
            if endpoint.method in DANGEROUS_METHODS:
                yield Finding(
                    rule_id=self.id,
                    title=self.title,
                    severity=Severity.MEDIUM if endpoint.method == HttpMethod.DELETE else Severity.HIGH,
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    description=f"{endpoint.method} is exposed on {endpoint.path}.",
                    why_it_matters="Dangerous methods can increase destructive action or cross-site tracing risk if not tightly controlled.",
                    evidence={"path": endpoint.path, "method": endpoint.method.value},
                )


class MissingSecurityHeadersRule(BaseRule):
    id = "missing-security-header"
    title = "Missing security header"

    def check(self, context: RuleContext) -> Iterable[Finding]:
        if not context.discovery.base_url or not context.observed_headers:
            return
        for header, reason in SECURITY_HEADERS.items():
            if header not in context.observed_headers:
                yield Finding(
                    rule_id=self.id,
                    title=f"Missing {header}",
                    severity=Severity.LOW,
                    description=f"The API root response did not include {header}.",
                    why_it_matters=reason,
                    evidence={"header": header},
                )


class MissingRateLimitingRule(BaseRule):
    id = "missing-rate-limiting"
    title = "Missing rate limiting signals"

    def check(self, context: RuleContext) -> Iterable[Finding]:
        if not context.discovery.base_url or not context.observed_headers:
            return
        rate_headers = {"ratelimit-limit", "x-ratelimit-limit", "retry-after"}
        if not any(header in context.observed_headers for header in rate_headers):
            yield Finding(
                rule_id=self.id,
                title=self.title,
                severity=Severity.MEDIUM,
                description="No standard rate limiting headers were observed on the API root response.",
                why_it_matters="Without rate limiting, login, search, and write endpoints are more exposed to brute force and abuse.",
                evidence={"checked_headers": sorted(rate_headers)},
            )


class WeakJWTConfigurationRule(BaseRule):
    id = "weak-jwt-configuration"
    title = "Weak JWT configuration"

    def check(self, context: RuleContext) -> Iterable[Finding]:
        spec = context.discovery.raw_spec or {}
        components = spec.get("components", {}) or {}
        security_schemes = components.get("securitySchemes", {}) or {}
        for name, scheme in security_schemes.items():
            text = json.dumps(scheme).lower()
            if "bearer" in text and "jwt" not in text:
                yield Finding(
                    rule_id=self.id,
                    title="Bearer auth missing explicit JWT format",
                    severity=Severity.LOW,
                    description=f"Security scheme {name} uses bearer authentication without declaring bearerFormat: JWT.",
                    why_it_matters="Ambiguous token configuration can lead to inconsistent validation expectations across services.",
                    evidence={"scheme": name},
                )
            if "none" in text or "hs256" in text:
                yield Finding(
                    rule_id=self.id,
                    title=self.title,
                    severity=Severity.HIGH,
                    description=f"Security scheme {name} references weak JWT algorithm hints.",
                    why_it_matters="JWTs using alg=none or poorly managed shared HMAC secrets can enable token forgery.",
                    evidence={"scheme": name, "hint": scheme},
                )


class IDORIndicatorRule(BaseRule):
    id = "idor-indicator"
    title = "Possible IDOR indicator"

    def check(self, context: RuleContext) -> Iterable[Finding]:
        for endpoint in context.discovery.endpoints:
            names = {str(param.get("name", "")).lower() for param in endpoint.parameters}
            names.update(re.findall(r"{([^}]+)}", endpoint.path.lower()))
            suspicious = sorted(names & IDOR_PARAMETER_HINTS)
            if suspicious and not endpoint.requires_auth:
                yield Finding(
                    rule_id=self.id,
                    title=self.title,
                    severity=Severity.HIGH,
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    description=f"{endpoint.method} {endpoint.path} exposes object identifiers without declared authentication.",
                    why_it_matters="Object identifiers can enable attackers to enumerate or access another user's records when authorization is missing or weak.",
                    evidence={"parameters": suspicious},
                )


DEFAULT_RULES: tuple[BaseRule, ...] = (
    PublicOpenAPIRule(),
    MissingAuthenticationRule(),
    DangerousMethodsRule(),
    MissingSecurityHeadersRule(),
    MissingRateLimitingRule(),
    WeakJWTConfigurationRule(),
    IDORIndicatorRule(),
)


def _looks_sensitive(path: str) -> bool:
    path = path.lower()
    return any(token in path for token in ("user", "account", "admin", "payment", "order", "customer", "token"))


def decode_jwt_header(token: str) -> dict[str, str] | None:
    """Utility used by future active auth checks."""
    try:
        header = token.split(".", 1)[0]
        padding = "=" * (-len(header) % 4)
        return json.loads(base64.urlsafe_b64decode(header + padding))
    except Exception:
        return None
