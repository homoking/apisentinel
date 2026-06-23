from __future__ import annotations

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from sqlalchemy.orm import Session

from apisentinel.dashboard.routes import router as dashboard_router
from apisentinel.database.repository import ScanRepository
from apisentinel.database.session import get_session, init_db
from apisentinel.reports.generator import result_to_html, result_to_json, result_to_markdown
from apisentinel.scanner.engine import ScannerEngine
from apisentinel.scanner.models import ScanRequest
from apisentinel.scanner.discovery import DiscoveryError
import httpx

async def lifespan(app: FastAPI):
    init_db()
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="APISentinel",
        description="AI-powered API security scanner",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.include_router(dashboard_router)

    @app.get("/health", tags=["system"])
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/api/scans", tags=["scans"])
    async def create_scan(request: ScanRequest, _: Session = Depends(get_session)):
        try:
            result = await ScannerEngine().scan(str(request.target), persist=True)
            return result
        except DiscoveryError as exc:
            # مشکل در دسترسی به تارگت
            raise HTTPException(status_code=502, detail=str(exc))
        except httpx.HTTPError as exc:
            # هر خطای شبکه‌ای دیگری از httpx
            raise HTTPException(
                status_code=502,
                detail=f"Network error while contacting target: {exc.__class__.__name__}: {exc}",
            )


    @app.get("/api/scans", tags=["scans"])
    async def list_scans(limit: int = 50):
        return ScanRepository().list(limit=limit)

    @app.get("/api/scans/{scan_id}", tags=["scans"])
    async def get_scan(scan_id: str):
        result = ScanRepository().get(scan_id)
        if not result:
            raise HTTPException(status_code=404, detail="Scan not found")
        return result

    @app.get("/api/scans/{scan_id}/report", tags=["reports"])
    async def get_report(scan_id: str, format: str = "json"):
        result = ScanRepository().get(scan_id)
        if not result:
            raise HTTPException(status_code=404, detail="Scan not found")
        if format == "html":
            return HTMLResponse(result_to_html(result))
        if format in {"md", "markdown"}:
            return PlainTextResponse(result_to_markdown(result), media_type="text/markdown")
        if format == "json":
            return JSONResponse(content=result.model_dump(mode="json"))
        raise HTTPException(status_code=400, detail="format must be json, markdown, or html")

    return app


app = create_app()
