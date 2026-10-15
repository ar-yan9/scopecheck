"""Local same-origin API. Do not publish this scanner as a public service."""
from pathlib import Path
import threading
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware
from scanner import ports, resolve_plan, scan

app = FastAPI(title='ScopeCheck local workbench', docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=['127.0.0.1','localhost','[::1]','testserver'])
lock = threading.Lock()

@app.middleware('http')
async def local_boundary(request: Request, call_next):
    if request.method == 'POST':
        origin = request.headers.get('origin')
        expected = str(request.base_url).rstrip('/')
        if origin and origin != expected:
            return __import__('starlette.responses',fromlist=['JSONResponse']).JSONResponse({'detail':'Only same-origin local requests accepted'},status_code=403)
        if not request.headers.get('content-type','').lower().startswith('application/json'):
            return __import__('starlette.responses',fromlist=['JSONResponse']).JSONResponse({'detail':'JSON required'},status_code=415)
        length = request.headers.get('content-length')
        if length is None or not length.isdigit() or int(length) > 8192:
            return __import__('starlette.responses',fromlist=['JSONResponse']).JSONResponse({'detail':'Request length required, maximum 8 KiB'},status_code=413)
    response = await call_next(request)
    response.headers.update({'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY',
                             'Content-Security-Policy':"default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'",'Referrer-Policy':'no-referrer'})
    return response

class ScanRequest(BaseModel):
    target: str = Field(default='127.0.0.1',min_length=1,max_length=253)
    ports: str = Field(default='22,80,443,8000,8080',min_length=1,max_length=800)
    authorized: bool = False
    scope: list[str] = Field(default_factory=list,max_length=16)
    http_ports: str = Field(default='',max_length=800)
    tls_ports: str = Field(default='',max_length=800)
    banner_ports: str = Field(default='',max_length=800)
    timeout: float = Field(default=1,ge=.1,le=5)
    workers: int = Field(default=4,ge=1,le=16)
    rate: float = Field(default=5,ge=.2,le=10)

@app.get('/api/health')
def health():
    return {'status':'ok','local_only':True,'draft':True}

@app.post('/api/scan')
def run_scan(body: ScanRequest):
    if not body.authorized:
        raise HTTPException(400,'Confirm ownership or written permission before starting, including the lab demo')
    if not lock.acquire(blocking=False):
        raise HTTPException(409,'One scan is already running. Wait for it to finish.')
    try:
        plan = resolve_plan(body.target, body.authorized, body.scope)
        selected = ports(body.ports)
        options = {key: ports(getattr(body,key)) if getattr(body,key) else [] for key in ['http_ports','tls_ports','banner_ports']}
        return scan(plan,selected,body.timeout,body.workers,body.rate,**options)
    except (ValueError,OSError) as exc:
        raise HTTPException(400,str(exc)) from exc
    finally:
        lock.release()

ROOT=Path(__file__).resolve().parent/'frontend'/'dist'
if ROOT.exists():
    app.mount('/assets',StaticFiles(directory=ROOT/'assets'),name='assets')
    @app.get('/')
    def home():
        return FileResponse(ROOT/'index.html')
