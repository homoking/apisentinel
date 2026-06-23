from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import httpx
import yaml

from apisentinel.core.config import get_settings
from apisentinel.scanner.models import DiscoveryResult, Endpoint, HttpMethod

OPENAPI_CANDIDATES = (
    "/openapi.json",
    "/swagger.json",
    "/api-docs",
    "/v3/api-docs",
    "/docs/swagger.json",
)
DOC_CANDIDATES = ("/docs", "/swagger", "/swagger-ui", "/redoc")


class DiscoveryError(RuntimeError):
    pass


class APIDiscoveryService:
    """Discovers OpenAPI documents and extracts endpoints."""

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self.settings = get_settings()
        self._client = client

    async def discover(self, target: str) -> DiscoveryResult:
        if self._looks_like_file(target):
            return self._discover_from_file(Path(target))
        return await self._discover_from_url(target.rstrip("/"))

    def _looks_like_file(self, target: str) -> bool:
        return Path(target).exists() or target.endswith((".json", ".yaml", ".yml"))

    def _discover_from_file(self, path: Path) -> DiscoveryResult:
        if not path.exists():
            raise DiscoveryError(f"OpenAPI file not found: {path}")
        spec = self._load_spec(path.read_text())
        return self._result_from_spec(target=str(path), spec=spec)

    async def _discover_from_url(self, base_url: str) -> DiscoveryResult:
        headers = {"User-Agent": self.settings.user_agent}
        client = self._client or httpx.AsyncClient(
            follow_redirects=True,
            timeout=self.settings.request_timeout_seconds,
            headers=headers,
        )
        close_client = self._client is None

        try:
            # تلاش برای پیدا کردن OpenAPI
            for candidate in OPENAPI_CANDIDATES:
                openapi_url = urljoin(base_url + "/", candidate.lstrip("/"))
                try:
                    response = await client.get(openapi_url)
                except httpx.RequestError as exc:
                    # خطای شبکه در این مرحله را فعلاً نگه می‌داریم؛
                    # اگر در ادامه هیچ docsـی هم پیدا نشد، تبدیلش می‌کنیم به DiscoveryError
                    last_error = exc
                    break

                content_type = response.headers.get("content-type", "")
                if response.status_code == 200 and (
                    "json" in content_type or response.text.strip().startswith(("{", "openapi:"))
                ):
                    spec = self._load_spec(response.text)
                    return self._result_from_spec(
                        target=base_url,
                        spec=spec,
                        base_url=base_url,
                        openapi_url=openapi_url,
                    )

            # اگر OpenAPI پیدا نشد، می‌رویم سراغ صفحات docs
            docs_seen: list[str] = []
            try:
                for candidate in DOC_CANDIDATES:
                    docs_url = urljoin(base_url + "/", candidate.lstrip("/"))
                    response = await client.get(docs_url)
                    if response.status_code == 200:
                        docs_seen.append(docs_url)
            except httpx.RequestError as exc:
                # در این‌جا یعنی اساساً به سرور نمی‌توانیم وصل شویم
                hint = "Make sure the target is reachable and not blocked by firewall or proxy."
                if isinstance(exc, httpx.UnsupportedProtocol):
                    hint = "Make sure the target URL starts with 'http://' or 'https://'."
                raise DiscoveryError(
                    f"Could not connect to target {base_url}. "
                    f"Network error: {exc.__class__.__name__}: {exc}. {hint}"
                ) from exc

            # اگر به سرور وصل شدیم ولی OpenAPI پیدا نکردیم، نتیجه بدون خطا برمی‌گردانیم
            return DiscoveryResult(
                target=base_url,
                base_url=base_url,
                endpoints=[],
                raw_spec=None,
                openapi_url=docs_seen[0] if docs_seen else None,
            )

        except httpx.RequestError as exc:
            # حالت کلی: مثل ConnectError / ConnectTimeout روی اولین درخواست‌ها
            hint = "Make sure the target is reachable and not blocked by firewall or proxy."
            if isinstance(exc, httpx.UnsupportedProtocol):
                hint = "Make sure the target URL starts with 'http://' or 'https://'."
            raise DiscoveryError(
                f"Could not connect to target {base_url}. "
                f"Network error: {exc.__class__.__name__}: {exc}. {hint}"
            ) from exc

        finally:
            if close_client:
                await client.aclose()

    def _load_spec(self, raw: str) -> dict[str, Any]:
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            parsed = yaml.safe_load(raw)
            if not isinstance(parsed, dict):
                raise DiscoveryError("OpenAPI document must be a JSON/YAML object")
            return parsed

    def _result_from_spec(
        self,
        target: str,
        spec: dict[str, Any],
        base_url: str | None = None,
        openapi_url: str | None = None,
    ) -> DiscoveryResult:
        paths = spec.get("paths", {}) or {}
        security = spec.get("security", []) or []
        endpoints: list[Endpoint] = []
        for path, operations in paths.items():
            if not isinstance(operations, dict):
                continue
            for method, operation in operations.items():
                method_upper = method.upper()
                if method_upper not in HttpMethod.__members__:
                    continue
                operation = operation or {}
                operation_security = operation.get("security", security)
                endpoints.append(
                    Endpoint(
                        path=path,
                        method=HttpMethod[method_upper],
                        operation_id=operation.get("operationId"),
                        requires_auth=bool(operation_security),
                        parameters=operation.get("parameters", []),
                        tags=operation.get("tags", []),
                    )
                )
        info = spec.get("info", {}) or {}
        return DiscoveryResult(
            target=target,
            base_url=base_url,
            openapi_url=openapi_url,
            title=info.get("title"),
            version=info.get("version"),
            endpoints=endpoints,
            raw_spec=spec,
        )
