from contextlib import asynccontextmanager
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
from itsdangerous import URLSafeTimedSerializer

import audit
from discovery import (
    discover_odoo_containers,
    discover_odoo_databases,
    get_containers_stats,
    parse_nginx_domain_mapping,
)
from monitoring import get_system_metrics
import scheduler
import security_auth
import storage


@asynccontextmanager
async def lifespan(_app: FastAPI):
    storage.init_db()
    scheduler.start_scheduler()
    yield
    scheduler.stop_scheduler()


app = FastAPI(title="SOS Cloud Control Panel - Odoo.sh Style", lifespan=lifespan)

from danger import router as admin_actions_router  # noqa: E402
from backups import router as backups_router  # noqa: E402
import backup_routes  # noqa: E402
import compliance_routes  # noqa: E402
import guard_routes  # noqa: E402
import health_routes  # noqa: E402

app.include_router(admin_actions_router)
app.include_router(backups_router)
app.include_router(backup_routes.router)
app.include_router(compliance_routes.router)
app.include_router(guard_routes.router)
app.include_router(security_auth.router)
app.include_router(health_routes.router)

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
    return security_auth.verify_session_request(request, serializer, SESSION_COOKIE_NAME)


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if is_authenticated(request):
        return RedirectResponse(url="/", status_code=302)
    return templates.TemplateResponse("login.html", {"request": request, "error": None, "step": "credentials"})


@app.post("/login", response_class=HTMLResponse)
async def login_submit(request: Request, username: str = Form(...), password: str = Form(...)):
    ip = audit.get_client_ip(request)
    wait_s = security_auth.check_login_rate_limit(ip)
    if wait_s:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": f"Demasiados intentos fallidos. Intente de nuevo en {wait_s} segundos.", "step": "credentials"},
            status_code=429,
        )

    clean_user = username.strip()
    user_ok = hmac.compare_digest(clean_user, PANEL_ADMIN_USER)
    pass_ok = hmac.compare_digest(password, PANEL_ADMIN_PASSWORD)
    if not (user_ok and pass_ok):
        security_auth.record_login_failure(ip)
        audit.log_event(
            request,
            "auth.login",
            target=clean_user or "unknown",
            status="failed",
            detail="Credenciales inválidas",
            username=clean_user or "unknown",
        )
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Credenciales inválidas. Verifique usuario y contraseña.", "step": "credentials"},
            status_code=401,
        )

    if security_auth.is_totp_enabled():
        preauth_token = security_auth.create_preauth_token(serializer, PANEL_ADMIN_USER, ip)
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": None, "step": "2fa", "preauth_token": preauth_token},
        )

    security_auth.clear_login_failures(ip)
    token, _sid = security_auth.issue_session_cookie_token(serializer, request, PANEL_ADMIN_USER)
    audit.log_event(request, "auth.login", target=PANEL_ADMIN_USER, status="ok", detail="Sesión iniciada (clave maestra)", username=PANEL_ADMIN_USER)
    response = RedirectResponse(url="/", status_code=302)
    response.set_cookie(key=SESSION_COOKIE_NAME, value=token, httponly=True, max_age=86400 * 7, samesite="lax")
    return response


@app.post("/login/2fa", response_class=HTMLResponse)
async def login_2fa_submit(request: Request, preauth_token: str = Form(...), totp_code: str = Form(...)):
    ip = audit.get_client_ip(request)
    wait_s = security_auth.check_login_rate_limit(ip)
    if wait_s:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": f"Demasiados intentos. Intente en {wait_s} segundos.", "step": "credentials"},
            status_code=429,
        )

    verified_user = security_auth.verify_preauth_token(serializer, preauth_token, ip)
    if not verified_user:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "La ventana de verificación expiró. Ingrese sus credenciales nuevamente.", "step": "credentials"},
            status_code=401,
        )

    ok_2fa, method = security_auth.verify_2fa_code(totp_code)
    if not ok_2fa:
        security_auth.record_login_failure(ip)
        audit.log_event(request, "auth.login_2fa", target=verified_user, status="failed", detail="Código 2FA inválido", username=verified_user)
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Código 2FA o de respaldo inválido.", "step": "2fa", "preauth_token": preauth_token},
            status_code=401,
        )

    security_auth.clear_login_failures(ip)
    token, _sid = security_auth.issue_session_cookie_token(serializer, request, verified_user)
    audit.log_event(
        request,
        "auth.login",
        target=verified_user,
        status="ok",
        detail=f"Sesión iniciada con 2FA ({'código de respaldo' if method == 'backup' else 'TOTP'})",
        username=verified_user,
    )
    response = RedirectResponse(url="/", status_code=302)
    response.set_cookie(key=SESSION_COOKIE_NAME, value=token, httponly=True, max_age=86400 * 7, samesite="lax")
    return response


@app.get("/logout")
async def logout(request: Request):
    if is_authenticated(request):
        sid = getattr(request.state, "sid", "")
        if sid:
            storage.revoke_session(sid)
        audit.log_event(request, "auth.logout", target=getattr(request.state, "username", PANEL_ADMIN_USER), status="ok", detail="Cierre manual de sesión")
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
            "totp_enabled": security_auth.is_totp_enabled(),
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
    audit.log_event(request, "sso.login", target=db, status="ok", detail=f"UID={uid} • {clean_base}")
    return RedirectResponse(url=f"{clean_base}/sso/login?{params}", status_code=302)


@app.post("/api/containers/{container_name}/restart")
async def restart_container(request: Request, container_name: str):
    if not is_authenticated(request):
        raise HTTPException(status_code=401, detail="No autorizado")
    try:
        client = docker.from_env()
        container = client.containers.get(container_name)
        container.restart(timeout=10)
        audit.log_event(request, "container.restart", target=container_name, status="ok")
        return JSONResponse({"ok": True, "message": f"Contenedor '{container_name}' reiniciado correctamente."})
    except Exception as e:
        audit.log_event(request, "container.restart", target=container_name, status="error", detail=str(e))
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
