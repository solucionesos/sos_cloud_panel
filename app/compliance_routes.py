"""Rutas API para Fase 5: Inspector Antivirus de Filestore (YARA-X + Cuarentena) y Cumplimiento Normativo."""
import hmac
import json
import os
import threading
import time

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

import audit
import compliance
import filestore_scanner
import security_auth
import storage

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
        audit.log_event(request, action_name, target="compliance_av", status="denied", detail="Clave maestra incorrecta")
        raise HTTPException(status_code=403, detail="Clave maestra del panel incorrecta.")
    security_auth.clear_login_failures(ip)


@router.get("/api/compliance/overview")
def compliance_overview(request: Request):
    _require_auth(request)
    matrix = compliance.evaluate_compliance_matrix()
    last_scan = storage.get_last_filestore_scan()
    findings = storage.list_filestore_findings()
    return JSONResponse({
        "ok": True,
        "matrix": matrix,
        "filestore": {
            "is_scanning": filestore_scanner._scan_lock.locked(),
            "last_scan": last_scan,
            "findings": findings,
        },
    })


@router.get("/api/compliance/report")
def export_compliance_report(request: Request, fmt: str = "html", framework: str = ""):
    _require_auth(request)
    matrix = compliance.evaluate_compliance_matrix()
    audit.log_event(
        request,
        "compliance.report_exported",
        target=framework or "all_frameworks",
        status="ok",
        detail=f"Formato={fmt} • Puntaje={matrix['global_score_pct']}% • SHA256={matrix['evidence_sha256'][:12]}",
    )
    if fmt == "json":
        raw = json.dumps(matrix, indent=2, ensure_ascii=False)
        return Response(
            content=raw,
            media_type="application/json; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="sos_cumplimiento_{int(time.time())}.json"'},
        )

    html_doc = compliance.render_printable_compliance_html(matrix, framework_filter=framework)
    return HTMLResponse(content=html_doc)


@router.post("/api/filestore/scan")
async def trigger_filestore_scan(request: Request):
    _require_auth(request)
    try:
        data = await request.json()
    except Exception:
        data = {}
    days = int((data or {}).get("max_age_days") or 0)

    if filestore_scanner._scan_lock.locked():
        return JSONResponse({"ok": False, "message": "Ya hay un escaneo de Filestore en curso."}, status_code=409)

    threading.Thread(
        target=filestore_scanner.scan_all_filestores,
        kwargs={"max_age_days": days},
        name="sos-filestore-av",
        daemon=True,
    ).start()

    audit.log_event(
        request,
        "filestore.scan_started",
        target="all_filestores",
        status="ok",
        detail=f"Alcance: {'últimos ' + str(days) + ' días' if days > 0 else 'escaneo profundo completo'}",
    )
    return JSONResponse({
        "ok": True,
        "message": "Escaneo antimalware YARA-X iniciado en segundo plano.",
    })


@router.post("/api/filestore/findings/{finding_id}/quarantine")
async def quarantine_filestore_item(request: Request, finding_id: int):
    _require_auth(request)
    data = await request.json()
    _verify_master_key(request, data.get("admin_password", ""), "filestore.quarantine")

    ok, msg = filestore_scanner.quarantine_finding(finding_id)
    audit.log_event(request, "filestore.quarantine", target=f"finding:{finding_id}", status="ok" if ok else "error", detail=msg)
    return JSONResponse({"ok": ok, "message": msg}, status_code=200 if ok else 400)


@router.post("/api/filestore/findings/{finding_id}/restore")
async def restore_filestore_item(request: Request, finding_id: int):
    _require_auth(request)
    data = await request.json()
    _verify_master_key(request, data.get("admin_password", ""), "filestore.restore")

    ok, msg = filestore_scanner.restore_quarantined_finding(finding_id)
    audit.log_event(request, "filestore.restore", target=f"finding:{finding_id}", status="ok" if ok else "error", detail=msg)
    return JSONResponse({"ok": ok, "message": msg}, status_code=200 if ok else 400)
