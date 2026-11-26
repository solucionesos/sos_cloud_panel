"""Rutas API para Respaldos Programados, Verificados (Restore-Test), Cifrados (age) y Multi-Destino (Fase 3)."""
import hmac
import json
import os

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse

import audit
import backup_manager
import discovery
import scheduler
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
        audit.log_event(request, action_name, target="backups", status="denied", detail="Clave maestra incorrecta")
        raise HTTPException(status_code=403, detail="Clave maestra del panel incorrecta.")
    security_auth.clear_login_failures(ip)


@router.get("/api/backups/overview")
def backups_overview(request: Request):
    _require_auth(request)
    policy = backup_manager.get_backup_policy(mask_secrets=True)
    summary = storage.get_backup_summary_30d()
    runs = storage.list_backup_runs(limit=60)
    for r in runs:
        try:
            r["destinations"] = json.loads(r.get("destinations_json") or "{}")
        except Exception:
            r["destinations"] = {}

    local_files = backup_manager.list_local_backup_files()
    local_total_mb = round(sum(f["size_mb"] for f in local_files), 2)
    remotes = backup_manager.list_rclone_remotes()

    dbs = [
        {"name": d["name"], "pg_container": d.get("pg_container") or ""}
        for d in discovery.discover_odoo_databases({})
        if d.get("name") and not str(d["name"]).startswith("Error") and not str(d["name"]).lower().startswith("tmp_")
    ]

    return JSONResponse({
        "ok": True,
        "summary": summary,
        "policy": policy,
        "rclone_remotes": remotes,
        "available_databases": dbs,
        "runs": runs,
        "local_files": local_files,
        "local_total_mb": local_total_mb,
        "is_locked": backup_manager._run_lock.locked(),
    })


@router.post("/api/backups/config")
async def save_backups_config(request: Request):
    _require_auth(request)
    data = await request.json()
    _verify_master_key(request, data.get("admin_password", ""), "backups.config")

    cfg_in = data.get("policy") if isinstance(data.get("policy"), dict) else data
    try:
        saved = backup_manager.save_backup_policy(cfg_in)
    except ValueError as ve:
        return JSONResponse({"ok": False, "message": str(ve)}, status_code=400)

    scheduler.sync_backup_schedule_job()
    dests = [d for d in ("local", "rclone", "s3") if saved.get(f"{d}_enabled")]
    audit.log_event(
        request,
        "backups.policy_saved",
        target="schedule" if saved.get("schedule_enabled") else "manual",
        status="ok",
        detail=f"Destinos={','.join(dests) or 'ninguno'} • RestoreTest={saved.get('verify_restore')} • Cifrado={saved.get('encryption_enabled')}",
    )
    return JSONResponse({"ok": True, "policy": saved, "message": "Política de respaldos guardada correctamente."})


@router.post("/api/backups/age-keygen")
async def create_age_keys(request: Request):
    _require_auth(request)
    data = await request.json()
    _verify_master_key(request, data.get("admin_password", ""), "backups.age_keygen")

    kp = backup_manager.generate_age_keypair()
    audit.log_event(request, "backups.age_keygen", target="age", status="ok", detail=f"Pubkey: {kp['public_key'][:20]}...")
    return JSONResponse({"ok": True, **kp})


@router.post("/api/backups/test-destination")
async def test_backup_destination(request: Request):
    _require_auth(request)
    data = await request.json()
    dest_type = str(data.get("type") or "").strip().lower()
    ok, msg = backup_manager.test_destination_connection(dest_type)
    audit.log_event(request, "backups.test_dest", target=dest_type, status="ok" if ok else "error", detail=msg)
    return JSONResponse({"ok": ok, "message": msg}, status_code=200 if ok else 400)


@router.post("/api/backups/run")
async def run_managed_backup_now(request: Request):
    _require_auth(request)
    try:
        data = await request.json()
    except Exception:
        data = {}

    db_name = str((data or {}).get("db_name") or "").strip()
    pg_container = str((data or {}).get("pg_container") or "").strip()

    targets = [(db_name, pg_container)] if db_name else None
    started = backup_manager.trigger_async_backup(targets=targets, trigger_type="manual")
    if not started:
        return JSONResponse({"ok": False, "message": "Ya hay una tarea de respaldo ejecutándose en segundo plano."}, status_code=409)

    audit.log_event(
        request,
        "backups.run_triggered",
        target=db_name or "all_configured",
        status="ok",
        detail="Ejecución iniciada en segundo plano",
    )
    return JSONResponse({
        "ok": True,
        "message": f"Respaldo verificado iniciado en segundo plano ({db_name or 'todas las bases configuradas'}).",
    })


@router.get("/api/backups/local/{db_name}/{filename}")
def download_local_backup_file(request: Request, db_name: str, filename: str):
    _require_auth(request)
    safe_db = os.path.basename(db_name)
    safe_fn = os.path.basename(filename)
    if safe_db != db_name or safe_fn != filename or ".." in safe_fn:
        raise HTTPException(status_code=400, detail="Ruta inválida.")
    full_path = os.path.join(backup_manager.LOCAL_BACKUPS_ROOT, safe_db, safe_fn)
    if not os.path.isfile(full_path):
        raise HTTPException(status_code=404, detail="Archivo no encontrado.")
    audit.log_event(request, "backups.local_download", target=f"{safe_db}/{safe_fn}", status="ok")
    return FileResponse(path=full_path, media_type="application/octet-stream", filename=safe_fn)


@router.delete("/api/backups/local/{db_name}/{filename}")
async def delete_local_backup_file(request: Request, db_name: str, filename: str):
    _require_auth(request)
    data = await request.json()
    _verify_master_key(request, data.get("admin_password", ""), "backups.local_delete")

    safe_db = os.path.basename(db_name)
    safe_fn = os.path.basename(filename)
    full_path = os.path.join(backup_manager.LOCAL_BACKUPS_ROOT, safe_db, safe_fn)
    if not os.path.isfile(full_path):
        return JSONResponse({"ok": False, "message": "Archivo no encontrado."}, status_code=404)
    os.remove(full_path)
    mf = full_path + ".manifest.json"
    if os.path.isfile(mf):
        os.remove(mf)
    audit.log_event(request, "backups.local_delete", target=f"{safe_db}/{safe_fn}", status="ok")
    return JSONResponse({"ok": True, "message": f"Copia local '{safe_fn}' eliminada."})
