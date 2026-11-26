import hashlib
import hmac
import os
import secrets
import time
from urllib.parse import urlencode

import docker
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, URLSafeTimedSerializer

from discovery import (
    discover_odoo_containers,
    discover_odoo_databases,
    get_containers_stats,
    parse_nginx_domain_mapping,
)
from monitoring import get_system_metrics

app = FastAPI(title="SOS Cloud Control Panel - Odoo.sh Style")

from danger import router as admin_actions_router  # noqa: E402

from backups import router as backups_router
app.include_router(admin_actions_router)
app.include_router(backups_router)
if os.path.isdir("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

PANEL_ADMIN_USER = os.environ.get("PANEL_ADMIN_USER", "admin")
PANEL_ADMIN_PASSWORD = os.environ.get("PANEL_ADMIN_PASSWORD", "admin")
PANEL_SESSION_SECRET = os.environ.get("PANEL_SESSION_SECRET", secrets.token_hex(32))
SOS_SSO_SECRET = os.environ.get("SOS_SSO_SECRET", "")

serializer = URLSafeTimedSerializer(PANEL_SESSION_SECRET)
SESSION_COOKIE_NAME = "sos_cloud_session"


def is_authenticated(request: Request) -> bool:
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return False
    try:
        data = serializer.loads(token, max_age=86400 * 7)
        return data.get("user") == PANEL_ADMIN_USER
    except BadSignature:
        return False


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if is_authenticated(request):
        return RedirectResponse(url="/", status_code=302)
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@app.post("/login", response_class=HTMLResponse)
async def login_submit(request: Request, username: str = Form(...), password: str = Form(...)):
    user_ok = hmac.compare_digest(username.strip(), PANEL_ADMIN_USER)
    pass_ok = hmac.compare_digest(password, PANEL_ADMIN_PASSWORD)
    if not (user_ok and pass_ok):
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Credenciales inválidas. Verifique usuario y contraseña."},
            status_code=401,
        )
    token = serializer.dumps({"user": PANEL_ADMIN_USER, "ts": int(time.time())})
    response = RedirectResponse(url="/", status_code=302)
    response.set_cookie(key=SESSION_COOKIE_NAME, value=token, httponly=True, max_age=86400 * 7, samesite="lax")
    return response


@app.get("/logout")
async def logout():
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie(SESSION_COOKIE_NAME)
    return response


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    if not is_authenticated(request):
        return RedirectResponse(url="/login", status_code=302)
    nginx_map = parse_nginx_domain_mapping()
    containers = discover_odoo_containers(nginx_map["port_to_domains"])
    databases = discover_odoo_databases(nginx_map["db_to_domain"])
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "containers": containers,
            "databases": databases,
            "total_dbs": len(databases),
            "running_containers": sum(1 for c in containers if c.get("is_running")),
            "total_containers": len(containers),
        },
    )


@app.get("/go/sso")
async def go_sso(request: Request, db: str, base_url: str, uid: int = 2):
    if not is_authenticated(request):
        return RedirectResponse(url="/login", status_code=302)
    if not SOS_SSO_SECRET:
        raise HTTPException(status_code=500, detail="SOS_SSO_SECRET no está configurado.")
    ts = int(time.time())
    nonce = secrets.token_hex(8)
    payload = f"{db}:{uid}:{ts}:{nonce}"
    sig = hmac.new(SOS_SSO_SECRET.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    clean_base = base_url.strip().rstrip("/")
    params = urlencode({"db": db, "uid": uid, "ts": ts, "nonce": nonce, "sig": sig})
    return RedirectResponse(url=f"{clean_base}/sso/login?{params}", status_code=302)


@app.post("/api/containers/{container_name}/restart")
async def restart_container(request: Request, container_name: str):
    if not is_authenticated(request):
        raise HTTPException(status_code=401, detail="No autorizado")
    try:
        client = docker.from_env()
        container = client.containers.get(container_name)
        container.restart(timeout=10)
        return JSONResponse({"ok": True, "message": f"Contenedor '{container_name}' reiniciado correctamente."})
    except Exception as e:
        return JSONResponse({"ok": False, "message": str(e)}, status_code=500)


@app.get("/api/containers/{container_name}/logs")
async def container_logs(request: Request, container_name: str, tail: int = 120):
    if not is_authenticated(request):
        raise HTTPException(status_code=401, detail="No autorizado")
    try:
        client = docker.from_env()
        container = client.containers.get(container_name)
        raw_logs = container.logs(tail=tail, timestamps=True).decode("utf-8", errors="replace")
        return JSONResponse({"ok": True, "container": container_name, "logs": raw_logs})
    except Exception as e:
        return JSONResponse({"ok": False, "message": str(e)}, status_code=500)


@app.get("/api/monitoring")
def api_monitoring(request: Request, sort: str = "cpu", order: str = "desc", limit: int = 60):
    if not is_authenticated(request):
        raise HTTPException(status_code=401, detail="No autorizado")
    if sort not in ("cpu", "memory", "io"):
        sort = "cpu"
    if order not in ("asc", "desc"):
        order = "desc"
    return JSONResponse(get_system_metrics(sort_by=sort, order=order, limit=limit))


@app.get("/api/containers/stats")
def api_containers_stats(request: Request):
    if not is_authenticated(request):
        raise HTTPException(status_code=401, detail="No autorizado")
    return JSONResponse({"ok": True, "stats": get_containers_stats()})
