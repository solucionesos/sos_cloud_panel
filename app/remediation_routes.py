"""Rutas API para el Motor de Auto-Remediación ('Fix' en 1 Clic) en Salud, SSL, Nginx, Odoo y Disco."""
import hmac
import os

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

import audit
import health_monitor
import remediation
import security_auth

router = APIRouter()

PANEL_ADMIN_PASSWORD = os.environ.get("PANEL_ADMIN_PASSWORD", "admin")


def _require_auth(request: Request) -> None:
    from main import is_authenticated
    if not is_authenticated(request):
        raise HTTPException(status_code=401, detail="No autorizado")


def _verify_master_key(request: Request, supplied_pw: str, action_name: str) -> None:
    ip = audit.get_client_ip(request)
    wait_s = security_auth.check_login_rate_limit(ip)
    if wait_s:
        raise HTTPException(status_code=429, detail=f"Demasiados intentos. Espere {wait_s} s.")
    if not hmac.compare_digest(str(supplied_pw or ""), PANEL_ADMIN_PASSWORD):
        security_auth.record_login_failure(ip)
        audit.log_event(request, action_name, target="remediation", status="denied", detail="Clave maestra incorrecta")
        raise HTTPException(status_code=403, detail="Clave maestra del panel incorrecta.")
    security_auth.clear_login_failures(ip)


@router.get("/api/remediation/diagnose")
def diagnose_fix(request: Request, kind: str = "", target: str = "", control: str = ""):
    _require_auth(request)
    return JSONResponse(remediation.diagnose_remediation(kind=kind, target=target, control=control))


@router.get("/api/remediation/ignored-domains")
def list_ignored_domains(request: Request):
    _require_auth(request)
    return JSONResponse({"ok": True, "ignored_domains": health_monitor.get_ignored_domains()})


@router.post("/api/remediation/execute")
async def execute_fix_action(request: Request):
    _require_auth(request)
    data = await request.json()
    action_id = str(data.get("action_id") or "").strip()
    params = data.get("params") if isinstance(data.get("params"), dict) else {}

    # dns_assistant es solo informativo; todas las demás acciones modifican estado y exigen clave maestra
    if action_id != "dns_assistant":
        _verify_master_key(request, data.get("admin_password", ""), f"fix.{action_id}")

    if action_id == "nginx_hardening":
        ok, msg = remediation.execute_nginx_hardening(
            domain=str(params.get("domain") or ""),
            also_odoo_proxy=bool(params.get("also_odoo_proxy")),
        )
    elif action_id == "odoo_disable_list_db":
        ok, msg = remediation.execute_odoo_disable_list_db(
            container_name=str(params.get("container_name") or ""),
            domain=str(params.get("domain") or ""),
        )
    elif action_id == "ssl_renew_cert":
        ok, msg = remediation.execute_ssl_renew_cert(
            cert_name=str(params.get("cert_name") or ""),
            domain=str(params.get("domain") or ""),
        )
    elif action_id == "ssl_issue_http01":
        ok, msg = remediation.execute_ssl_issue_http01(domain=str(params.get("domain") or ""))
    elif action_id == "https_redirect":
        ok, msg = remediation.execute_https_redirect(domain=str(params.get("domain") or ""))
    elif action_id == "ssl_wildcard_start":
        res = remediation.start_wildcard_dns_challenge(base_domain=str(params.get("base_domain") or ""))
        audit.log_event(request, "fix.ssl_wildcard_start", target=str(params.get("base_domain") or ""), status="ok" if res.get("ok") else "error", detail=res.get("message", ""))
        return JSONResponse(res, status_code=200 if res.get("ok") else 400)
    elif action_id == "ssl_wildcard_complete":
        res = remediation.complete_wildcard_dns_challenge(
            base_domain=str(params.get("base_domain") or ""),
            force=bool(params.get("force")),
        )
        if res.get("completed"):
            audit.log_event(request, "fix.ssl_wildcard_complete", target=str(params.get("base_domain") or ""), status="ok", detail=res.get("message", ""))
        return JSONResponse(res, status_code=200 if (res.get("ok") or res.get("needs_wait")) else 400)
    elif action_id == "uptime_restart_container":
        ok, msg = remediation.execute_uptime_restart_container(
            container_name=str(params.get("container_name") or ""),
            domain=str(params.get("domain") or ""),
        )
    elif action_id == "ignore_domain":
        ok, msg = remediation.execute_ignore_inactive_domain(domain=str(params.get("domain") or ""))
    elif action_id == "restore_domain":
        ok, msg = remediation.execute_restore_ignored_domain(domain=str(params.get("domain") or ""))
    elif action_id == "disk_cleanup":
        ok, msg = remediation.execute_disk_cleanup()
    elif action_id == "dns_assistant":
        root_dom = str(params.get("root_domain") or "")
        srv_ip = str(params.get("server_ip") or "")
        return JSONResponse({
            "ok": True,
            "dns_records": [
                {"type": "TXT", "host": root_dom, "value": f"v=spf1 a mx ip4:{srv_ip} ~all"},
                {"type": "TXT", "host": f"_dmarc.{root_dom}", "value": f"v=DMARC1; p=quarantine; rua=mailto:admin@{root_dom}; pct=100"},
            ],
            "message": f"Agregue estos dos registros TXT en el panel DNS de {root_dom}:",
        })
    else:
        return JSONResponse({"ok": False, "message": f"Acción '{action_id}' no reconocida."}, status_code=400)

    target_str = str(params.get("domain") or params.get("container_name") or params.get("cert_name") or "host")
    audit.log_event(request, f"fix.{action_id}", target=target_str, status="ok" if ok else "error", detail=msg)
    return JSONResponse({"ok": ok, "message": msg}, status_code=200 if ok else 400)
