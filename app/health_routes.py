"""Rutas API para Salud en Vivo (Uptime/SSL), Escáner de Seguridad Odoo/Nginx/DNS y Alertas Multi-Canal."""
import hmac
import json
import os
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

import audit
import health_monitor
import notifications
import security_auth
import security_scanner
import storage

router = APIRouter()

PANEL_ADMIN_PASSWORD = os.environ.get("PANEL_ADMIN_PASSWORD", "admin")


def _require_auth(request: Request) -> None:
    from main import is_authenticated
    if not is_authenticated(request):
        raise HTTPException(status_code=401, detail="No autorizado")


@router.get("/api/health/overview")
def health_overview(request: Request):
    _require_auth(request)
    targets = health_monitor.discover_monitored_targets()
    uptime_map = storage.get_uptime_summary_by_domain()
    ssl_map = storage.get_all_ssl_status()
    scan_map = storage.get_all_security_scans()
    incidents = storage.list_incidents(limit=40)

    items: List[Dict[str, Any]] = []
    up_count = 0
    uptime_24_vals = []
    ssl_days_vals = []
    scan_scores = []

    for t in targets:
        dom = t["domain"]
        up = uptime_map.get(dom)
        sl = ssl_map.get(dom)
        sc = scan_map.get(dom)

        is_up = up["is_up"] if up else None
        if is_up is True:
            up_count += 1
        if up:
            uptime_24_vals.append(float(up.get("uptime_24h", 100.0)))
        if sl and sl.get("valid") and sl.get("days_left", -1) >= 0:
            ssl_days_vals.append(int(sl["days_left"]))

        findings = []
        score = None
        grade = "-"
        scanned_at = 0
        if sc:
            score = int(sc["score"])
            grade = sc["grade"]
            scanned_at = int(sc["scanned_at"])
            scan_scores.append(score)
            try:
                findings = json.loads(sc.get("findings_json") or "[]")
            except Exception:
                findings = []

        items.append({
            "domain": dom,
            "url": t["url"],
            "is_odoo": t["is_odoo"],
            "container_name": t["container_name"],
            "db_name": t["db_name"],
            "company_name": t["company_name"],
            "uptime": up,
            "ssl": sl,
            "security": {
                "score": score,
                "grade": grade,
                "scanned_at": scanned_at,
                "findings": findings,
            },
        })

    open_inc_count = sum(1 for i in incidents if i.get("status") == "open")
    global_uptime = round(sum(uptime_24_vals) / len(uptime_24_vals), 2) if uptime_24_vals else 100.0
    min_ssl_days = min(ssl_days_vals) if ssl_days_vals else None
    avg_score = int(round(sum(scan_scores) / len(scan_scores))) if scan_scores else None

    return JSONResponse({
        "ok": True,
        "summary": {
            "total_targets": len(targets),
            "up_targets": up_count,
            "global_uptime_24h": global_uptime,
            "min_ssl_days": min_ssl_days,
            "avg_security_score": avg_score,
            "avg_security_grade": security_scanner._score_to_grade(avg_score) if avg_score is not None else "-",
            "open_incidents": open_inc_count,
        },
        "targets": items,
        "incidents": incidents,
    })


@router.post("/api/health/check-now")
def trigger_health_check_now(request: Request):
    _require_auth(request)
    up_res = health_monitor.run_uptime_checks()
    ssl_res = health_monitor.run_ssl_checks()
    health_monitor.run_host_threshold_checks()
    audit.log_event(request, "health.check_now", target="all_domains", status="ok", detail=f"{len(up_res)} dominios sondeados")
    return JSONResponse({
        "ok": True,
        "checked_domains": len(up_res),
        "checked_ssl": len(ssl_res),
        "message": f"Sondeo completado en {len(up_res)} dominios.",
    })


@router.post("/api/health/scan")
async def trigger_security_scan(request: Request):
    _require_auth(request)
    try:
        body = await request.json()
    except Exception:
        body = {}
    domain = str((body or {}).get("domain") or "").strip().lower()

    targets = health_monitor.discover_monitored_targets()
    if domain:
        matched = next((t for t in targets if t["domain"] == domain), None)
        if not matched:
            return JSONResponse({"ok": False, "message": f"Dominio '{domain}' no encontrado."}, status_code=404)
        res = security_scanner.scan_single_target(matched)
        audit.log_event(request, "security.scan", target=domain, status="ok", detail=f"Puntaje {res['score']}/100 ({res['grade']})")
        return JSONResponse({"ok": True, "scanned": 1, "result": res, "message": f"Diagnóstico de {domain}: {res['score']}/100 ({res['grade']})"})

    results = security_scanner.run_all_security_scans()
    avg = int(round(sum(r["score"] for r in results) / len(results))) if results else 0
    audit.log_event(request, "security.scan_all", target="all_domains", status="ok", detail=f"{len(results)} dominios • Promedio {avg}/100")
    return JSONResponse({"ok": True, "scanned": len(results), "message": f"Escaneo finalizado en {len(results)} dominios (Promedio: {avg}/100)."})


@router.get("/api/notifications/config")
def get_notifications_settings(request: Request):
    _require_auth(request)
    return JSONResponse({"ok": True, "config": notifications.get_notify_config(mask_secrets=True)})


@router.post("/api/notifications/config")
async def save_notifications_settings(request: Request):
    _require_auth(request)
    data = await request.json()
    ip = audit.get_client_ip(request)
    wait_s = security_auth.check_login_rate_limit(ip)
    if wait_s:
        raise HTTPException(status_code=429, detail=f"Demasiados intentos. Espere {wait_s} s.")

    supplied_pw = str(data.get("admin_password") or "")
    if not hmac.compare_digest(supplied_pw, PANEL_ADMIN_PASSWORD):
        security_auth.record_login_failure(ip)
        audit.log_event(request, "notifications.config", target="channels", status="denied", detail="Clave maestra incorrecta")
        return JSONResponse({"ok": False, "message": "Clave maestra del panel incorrecta."}, status_code=403)

    security_auth.clear_login_failures(ip)
    cfg_in = data.get("config") if isinstance(data.get("config"), dict) else data
    saved = notifications.save_notify_config(cfg_in)
    enabled_list = [ch for ch in ("telegram", "webhook", "smtp") if saved.get(f"{ch}_enabled")]
    audit.log_event(
        request,
        "notifications.config_saved",
        target="channels",
        status="ok",
        detail=f"Canales activos: {', '.join(enabled_list) if enabled_list else 'ninguno'}",
    )
    return JSONResponse({"ok": True, "config": saved, "message": "Configuración de alertas guardada correctamente."})


@router.post("/api/notifications/test")
def test_notifications_channels(request: Request):
    _require_auth(request)
    results = notifications.dispatch_notification(
        event_type="test",
        severity="warning",
        target="sos_cloud_panel",
        title="Prueba de Alerta — SOS Cloud Panel",
        detail="Este es un mensaje de verificación enviado manualmente desde el panel de control.",
    )
    if not results:
        return JSONResponse({
            "ok": False,
            "message": "No hay ningún canal habilitado. Active y guarde primero Telegram, Webhook o SMTP.",
        }, status_code=400)

    ok_all = all(r[1] for r in results)
    summary_txt = " | ".join(f"{ch}: {'OK' if ok else msg}" for ch, ok, msg in results)
    audit.log_event(request, "notifications.test", target="channels", status="ok" if ok_all else "error", detail=summary_txt)
    return JSONResponse({
        "ok": ok_all,
        "results": [{"channel": ch, "ok": ok, "message": msg} for ch, ok, msg in results],
        "message": f"Resultado de prueba: {summary_txt}",
    })
