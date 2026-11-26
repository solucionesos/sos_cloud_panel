"""Rutas API para Fase 4: Guardia & Portero (Firewall SOS_GUARD, Fuerza Bruta SSH/Odoo, Honeypots e Integridad)."""
import hmac
import ipaddress
import os

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

import audit
import security_auth
import storage
import threat_guard

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
        audit.log_event(request, action_name, target="guard", status="denied", detail="Clave maestra incorrecta")
        raise HTTPException(status_code=403, detail="Clave maestra del panel incorrecta.")
    security_auth.clear_login_failures(ip)


@router.get("/api/guard/overview")
def guard_overview(request: Request, vector: str = ""):
    _require_auth(request)
    storage.expire_old_blocks()
    policy = threat_guard.get_guard_policy()
    fw_ok, fw_detail = threat_guard.check_firewall_capability()

    enforced_v4 = len(threat_guard._get_current_chain_ips(ipv6=False)) if fw_ok else 0
    enforced_v6 = len(threat_guard._get_current_chain_ips(ipv6=True)) if fw_ok else 0

    blocked = storage.list_blocked_ips(only_active=True)
    events = storage.list_threat_events(limit=120, vector_filter=vector.strip())
    summary = storage.get_threat_summary_24h()
    integrity_records = list(storage.get_integrity_baselines().values())
    integrity_alerts = sum(1 for r in integrity_records if r.get("status") != "ok")

    return JSONResponse({
        "ok": True,
        "client_ip": audit.get_client_ip(request),
        "policy": policy,
        "firewall": {
            "capable": fw_ok,
            "detail": fw_detail,
            "enforced_rules_count": enforced_v4 + enforced_v6,
        },
        "summary": {
            **summary,
            "integrity_total": len(integrity_records),
            "integrity_alerts": integrity_alerts,
        },
        "blocked_ips": blocked,
        "events": events,
        "integrity": integrity_records,
    })


@router.post("/api/guard/mode")
async def switch_guard_mode(request: Request):
    _require_auth(request)
    data = await request.json()
    _verify_master_key(request, data.get("admin_password", ""), "guard.switch_mode")

    new_mode = str(data.get("mode") or "").strip().lower()
    if new_mode not in ("monitor", "enforce"):
        return JSONResponse({"ok": False, "message": "Modo inválido."}, status_code=400)

    # Protección anti-lockout: al activar 'enforce', registrar automáticamente la IP actual del admin en trusted_ips
    admin_ip = audit.get_client_ip(request)
    if new_mode == "enforce":
        try:
            ip_obj = ipaddress.ip_address(admin_ip)
            if not ip_obj.is_private and not ip_obj.is_loopback:
                storage.add_trusted_ip(admin_ip, note="Auto-protegida al activar Modo Bloquear", created_by=getattr(request.state, "username", "admin"))
        except ValueError:
            pass

    saved = threat_guard.save_guard_policy({"mode": new_mode})
    fw_sync = threat_guard.sync_firewall_rules()
    audit.log_event(
        request,
        "guard.mode_changed",
        target=new_mode,
        status="ok",
        detail=fw_sync.get("detail", ""),
    )
    label = "Modo BLOQUEAR activo en Firewall" if new_mode == "enforce" else "Modo OBSERVAR activo (bloqueos en firewall levantados)"
    return JSONResponse({"ok": True, "policy": saved, "firewall": fw_sync, "message": label})


@router.post("/api/guard/policy")
async def update_guard_policy(request: Request):
    _require_auth(request)
    data = await request.json()
    _verify_master_key(request, data.get("admin_password", ""), "guard.policy")
    cfg_in = data.get("policy") if isinstance(data.get("policy"), dict) else data
    saved = threat_guard.save_guard_policy(cfg_in)
    fw_sync = threat_guard.sync_firewall_rules()
    audit.log_event(
        request,
        "guard.policy_saved",
        target=saved["mode"],
        status="ok",
        detail=f"SSH={saved['ssh_max_failures']} • Odoo={saved['odoo_max_failures']} • Dur={saved['block_duration_minutes']}m",
    )
    return JSONResponse({"ok": True, "policy": saved, "firewall": fw_sync, "message": "Reglas de protección actualizadas."})


@router.post("/api/guard/block")
async def manual_block_ip(request: Request):
    _require_auth(request)
    data = await request.json()
    raw_ip = str(data.get("ip") or "").strip()
    reason = str(data.get("reason") or "Bloqueo manual por administrador").strip()
    minutes = int(data.get("duration_minutes") or 0)

    try:
        ip_norm = str(ipaddress.ip_address(raw_ip))
    except ValueError:
        return JSONResponse({"ok": False, "message": "Dirección IP inválida."}, status_code=400)

    if threat_guard.is_ip_exempt(ip_norm):
        return JSONResponse({
            "ok": False,
            "message": f"La IP {ip_norm} está protegida (propio servidor, red privada o en Lista Blanca).",
        }, status_code=400)

    storage.upsert_blocked_ip(ip_norm, reason=reason, source="manual", duration_seconds=max(0, minutes * 60))
    storage.insert_threat_event(
        ip=ip_norm,
        vector="manual",
        severity="warning",
        target="firewall",
        action_taken="blocked" if threat_guard.get_guard_policy()["mode"] == "enforce" else "observed",
        detail=reason,
    )
    fw_sync = threat_guard.sync_firewall_rules()
    audit.log_event(request, "guard.ip_blocked", target=ip_norm, status="ok", detail=reason)
    return JSONResponse({"ok": True, "firewall": fw_sync, "message": f"IP {ip_norm} agregada a la lista de bloqueo."})


@router.post("/api/guard/unblock")
async def manual_unblock_ip(request: Request):
    _require_auth(request)
    data = await request.json()
    raw_ip = str(data.get("ip") or "").strip()
    whitelist = bool(data.get("add_to_whitelist"))
    if not raw_ip:
        return JSONResponse({"ok": False, "message": "IP requerida."}, status_code=400)

    storage.deactivate_blocked_ip(raw_ip)
    if whitelist:
        storage.add_trusted_ip(raw_ip, note="Movida a Lista Blanca desde Bloqueos", created_by=getattr(request.state, "username", "admin"))
    fw_sync = threat_guard.sync_firewall_rules()
    audit.log_event(request, "guard.ip_unblocked", target=raw_ip, status="ok", detail="Con whitelist" if whitelist else "Desbloqueo directo")
    return JSONResponse({"ok": True, "firewall": fw_sync, "message": f"IP {raw_ip} desbloqueada."})


@router.post("/api/guard/unblock-all")
async def emergency_unblock_all(request: Request):
    _require_auth(request)
    data = await request.json()
    _verify_master_key(request, data.get("admin_password", ""), "guard.unblock_all")
    res = threat_guard.unblock_all_emergency()
    audit.log_event(request, "guard.unblock_all", target="SOS_GUARD", status="ok", detail=f"{res['unblocked_count']} IPs liberadas")
    return JSONResponse({"ok": True, **res, "message": f"Se levantaron todos los bloqueos ({res['unblocked_count']} IPs liberadas y cadena SOS_GUARD limpia)."})


@router.post("/api/guard/integrity/check")
def trigger_integrity_check(request: Request):
    _require_auth(request)
    res = threat_guard.run_host_integrity_check()
    audit.log_event(request, "guard.integrity_check", target="host", status="ok", detail=f"{res['ok_files']}/{res['total_files']} íntegros")
    return JSONResponse({"ok": True, **res, "message": f"Verificación completada: {res['ok_files']}/{res['total_files']} archivos críticos coinciden con la línea base."})


@router.post("/api/guard/integrity/approve")
async def approve_integrity_change(request: Request):
    _require_auth(request)
    data = await request.json()
    _verify_master_key(request, data.get("admin_password", ""), "guard.integrity_approve")
    filepath = str(data.get("filepath") or "").strip()
    if filepath == "__ALL__":
        res = threat_guard.run_host_integrity_check(approve_all_as_baseline=True)
        audit.log_event(request, "guard.integrity_approve_all", target="all_files", status="ok", detail=f"{res['total_files']} archivos aprobados")
        return JSONResponse({"ok": True, "message": "Línea base completa actualizada."})

    if not filepath:
        return JSONResponse({"ok": False, "message": "Ruta de archivo requerida."}, status_code=400)
    threat_guard.approve_single_integrity_file(filepath)
    audit.log_event(request, "guard.integrity_approve", target=filepath, status="ok")
    return JSONResponse({"ok": True, "message": f"Cambio en '{filepath}' aprobado como nueva línea base."})
