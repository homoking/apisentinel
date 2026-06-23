from __future__ import annotations

import httpx

from apisentinel.ai.service import AIAnalysisService
from apisentinel.core.config import get_settings
from apisentinel.scanner.discovery import APIDiscoveryService
from apisentinel.scanner.models import ScanResult
from apisentinel.scanner.rules import DEFAULT_RULES, BaseRule, RuleContext


class ScannerEngine:
    """Application use case that orchestrates discovery, security rules, and AI guidance."""

    def __init__(
        self,
        discovery: APIDiscoveryService | None = None,
        ai: AIAnalysisService | None = None,
        rules: tuple[BaseRule, ...] = DEFAULT_RULES,
    ) -> None:
        self.discovery = discovery or APIDiscoveryService()
        self.ai = ai or AIAnalysisService()
        self.rules = rules
        self.settings = get_settings()

    async def scan(self, target: str, persist: bool = False) -> ScanResult:
        discovery = await self.discovery.discover(target)
        observed_headers = await self._fetch_root_headers(discovery.base_url)
        context = RuleContext(discovery=discovery, observed_headers=observed_headers)
        findings = []
        for rule in self.rules:
            findings.extend(list(rule.check(context)))
        findings = await self.ai.enrich(findings)
        result = ScanResult.from_findings(target=target, discovery=discovery, findings=findings)
        if persist:
            from apisentinel.database.repository import ScanRepository

            ScanRepository().save(result)
        return result

    async def _fetch_root_headers(self, base_url: str | None) -> dict[str, str]:
        if not base_url:
            return {}
        try:
            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=self.settings.request_timeout_seconds,
                headers={"User-Agent": self.settings.user_agent},
            ) as client:
                response = await client.get(base_url)
                return dict(response.headers)
        except httpx.HTTPError:
            return {}
