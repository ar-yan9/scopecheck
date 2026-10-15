"""Local same-origin API. Do not publish this scanner as a public service."""

from pathlib import Path
import threading
import os
from jobs import Jobs
from reports import render_html
from fastapi.responses import HTMLResponse, JSONResponse
from scanner import local_addresses
from profiles import PRESETS
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware
from scanner import ports, resolve_plan, scan

app = FastAPI(
    title="ScopeCheck local workbench", docs_url=None, redoc_url=None, openapi_url=None
)
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["127.0.0.1", "localhost", "[::1]", "testserver"],
)
lock = threading.Lock()
manager = Jobs(
    os.environ.get(
        "SCOPECHECK_HISTORY_DB",
        str(Path(__file__).resolve().parent / "local-data" / "history.sqlite3"),
    )
)


@app.middleware("http")
async def local_boundary(request: Request, call_next):
    if request.method == "POST":
        origin = request.headers.get("origin")
        expected = str(request.base_url).rstrip("/")
        if origin and origin != expected:
            return __import__(
                "starlette.responses", fromlist=["JSONResponse"]
            ).JSONResponse(
                {"detail": "Only same-origin local requests accepted"}, status_code=403
            )
        if (
            not request.headers.get("content-type", "")
            .lower()
            .startswith("application/json")
        ):
            return __import__(
                "starlette.responses", fromlist=["JSONResponse"]
            ).JSONResponse({"detail": "JSON required"}, status_code=415)
        length = request.headers.get("content-length")
        if length is None or not length.isdigit() or int(length) > 8192:
            return __import__(
                "starlette.responses", fromlist=["JSONResponse"]
            ).JSONResponse(
                {"detail": "Request length required, maximum 8 KiB"}, status_code=413
            )
    response = await call_next(request)
    response.headers.update(
        {
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'",
            "Referrer-Policy": "no-referrer",
        }
    )
    return response


class ScanRequest(BaseModel):
    target: str = Field(default="127.0.0.1", min_length=1, max_length=253)
    ports: str = Field(default="22,80,443,8000,8080", min_length=1, max_length=800)
    authorized: bool = False
    scope: list[str] = Field(default_factory=list, max_length=16)
    http_ports: str = Field(default="", max_length=800)
    tls_ports: str = Field(default="", max_length=800)
    banner_ports: str = Field(default="", max_length=800)
    automatic: bool = True
    passive_unknown: bool = False
    timeout: float = Field(default=1, ge=0.1, le=5)
    workers: int = Field(default=32, ge=1, le=128)
    rate: float = Field(default=50, ge=0.2, le=200)


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "local_only": True,
        "version": "0.2.0",
        "active_job": manager.active,
    }


@app.get("/api/local-addresses")
def addresses():
    return {
        "addresses": sorted(local_addresses()),
        "note": "Only actual local interfaces; private subnets are not assumed owned",
    }


@app.get("/api/presets")
def presets():
    return {
        "presets": [
            {"id": "common100", "label": "Common 100 (curated)", "count": 100},
            {
                "id": "first1000",
                "label": "Ports 1-1000 (not popularity-ranked)",
                "count": 1000,
            },
            {"id": "all", "label": "All TCP 1-65535", "count": 65535},
        ]
    }


@app.post("/api/jobs")
def start_scan(body: ScanRequest):
    try:
        plan = resolve_plan(body.target, body.authorized, body.scope)
        if not plan["own_machine"] and not body.authorized:
            raise ValueError("External targets require permission confirmation")
        if not plan["own_machine"] and (body.rate > 25 or body.workers > 16):
            raise ValueError(
                "External targets: use at most 25 connections/sec and 16 workers, or lower per permission"
            )
        selected = ports(body.ports)
        options = {
            key: ports(getattr(body, key)) if getattr(body, key) else []
            for key in ["http_ports", "tls_ports", "banner_ports"]
        }
        if not lock.acquire(blocking=False):
            raise ValueError("One scan is already running")
        try:
            id = manager.start(
                plan,
                selected,
                timeout=body.timeout,
                workers=body.workers,
                rate=body.rate,
                auto=body.automatic,
                extended=body.passive_unknown,
                **options
            )
        finally:
            lock.release()
        return {
            "id": id,
            "status": "running",
            "target_plan": plan,
            "port_count": len(selected),
        }
    except (OSError, ValueError) as exc:
        raise HTTPException(
            409 if "already running" in str(exc) else 400, str(exc)
        ) from exc


@app.get("/api/jobs/{id}")
def status(id: str):
    result = manager.get(id)
    if not result:
        raise HTTPException(404, "Scan not found")
    # Keep progress polling compact; completed full reports use a separate route.
    return {k: v for k, v in result.items() if k != "report"}


@app.get("/api/jobs/{id}/report")
def report(id: str):
    result = manager.get(id)
    if not result or "report" not in result:
        raise HTTPException(404, "Report not ready")
    return result["report"]


@app.get("/api/jobs/{id}/html")
def report_html(id: str):
    result = manager.get(id)
    if not result or "report" not in result:
        raise HTTPException(404, "Report not ready")
    return HTMLResponse(
        render_html(result["report"]),
        headers={
            "Content-Disposition": 'attachment; filename="scopecheck-report.html"'
        },
    )


@app.get("/api/jobs/{id}/print")
def printable(id: str):
    result = manager.get(id)
    if not result or "report" not in result:
        raise HTTPException(404, "Report not ready")
    return HTMLResponse(render_html(result["report"]))


@app.post("/api/jobs/{id}/cancel")
def cancel(id: str):
    return {
        "requested": manager.cancel(id),
        "note": "In-flight socket operations finish within their timeouts; DNS can take longer",
    }


@app.get("/api/history")
def history():
    return {
        "reports": manager.history(),
        "retention": "Last 20 reports, up to 7 days, stored locally. Clear removes app records, not forensic disk copies.",
    }


@app.post("/api/history/clear")
def clear_history():
    manager.clear()
    return {"cleared": True}


# Compatibility endpoint for old CLI/API users, now delegates to the same full-range engine.
@app.post("/api/scan")
def old_scan(body: ScanRequest):
    if not body.authorized:
        raise HTTPException(400, "Confirm ownership or written permission")
    if not lock.acquire(blocking=False):
        raise HTTPException(409, "One scan is already running")
    try:
        if manager.active:
            raise HTTPException(409, "One scan is already running")
        from engine import execute

        plan = resolve_plan(body.target, body.authorized, body.scope)
        return execute(
            plan,
            ports(body.ports),
            timeout=body.timeout,
            workers=body.workers,
            rate=body.rate,
            auto=body.automatic,
            **{
                key: ports(getattr(body, key)) if getattr(body, key) else []
                for key in ["http_ports", "tls_ports", "banner_ports"]
            }
        )
    except (OSError, ValueError) as exc:
        raise HTTPException(400, str(exc)) from exc
    finally:
        lock.release()


ROOT = Path(__file__).resolve().parent / "frontend" / "dist"
if ROOT.exists():
    app.mount("/assets", StaticFiles(directory=ROOT / "assets"), name="assets")

    @app.get("/")
    def home():
        return FileResponse(ROOT / "index.html")
