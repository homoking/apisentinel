from __future__ import annotations

from pathlib import Path
from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from apisentinel.database.repository import ScanRepository
from apisentinel.scanner.engine import ScannerEngine
from apisentinel.scanner.discovery import DiscoveryError

router = APIRouter(include_in_schema=False)
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


@router.get("/", response_class=HTMLResponse)
async def overview(request: Request):
    scans = ScanRepository().list(limit=10)
    latest = scans[0] if scans else None
    return templates.TemplateResponse(
        request=request,
        name="overview.html",
        context={"scans": scans, "latest": latest},
    )


@router.get("/scans", response_class=HTMLResponse)
async def scan_history(request: Request):
    scans = ScanRepository().list(limit=100)
    return templates.TemplateResponse(request=request, name="scans.html", context={"scans": scans})


@router.post("/scans", response_class=HTMLResponse)
async def run_scan(request: Request, target: str = Form(...)):
    error: str | None = None
    latest = None

    try:
        latest = await ScannerEngine().scan(target, persist=True)
    except DiscoveryError as exc:
        # خطای شبکه‌ای/دسترسی به تارگت
        error = str(exc)
    except Exception:
        # هر خطای غیرمنتظره‌ی دیگر
        error = "Unexpected error while running scan. Please check server logs."

    scans = ScanRepository().list(limit=10)
    # اگر اسکن موفق شود، latest همان نتیجه‌ی جدید است؛ اگر نه، آخرین اسکن موفقِ دیتابیس را نشان می‌دهیم
    if latest is None and scans:
        latest = scans[0]

    return templates.TemplateResponse(
        request=request,
        name="partials/recent_scans.html",
        context={"scans": scans, "latest": latest, "error": error},
    )


@router.get("/scans/{scan_id}", response_class=HTMLResponse)
async def report_detail(request: Request, scan_id: str):
    result = ScanRepository().get(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")
    return templates.TemplateResponse(request=request, name="detail.html", context={"result": result})


@router.get("/findings", response_class=HTMLResponse)
async def findings(request: Request):
    scans = ScanRepository().list(limit=100)
    all_findings = [(scan, finding) for scan in scans for finding in scan.findings]
    return templates.TemplateResponse(request=request, name="findings.html", context={"findings": all_findings})


@router.get("/status/running", response_class=HTMLResponse)
async def scan_running_status(request: Request):
    return templates.TemplateResponse(request=request, name="partials/scan_running.html", context={})


@router.get("/status/complete", response_class=HTMLResponse)
async def scan_complete_status(request: Request):
    return templates.TemplateResponse(request=request, name="partials/scan_complete.html", context={})
