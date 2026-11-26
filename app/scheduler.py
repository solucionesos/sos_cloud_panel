"""Planificador de tareas en segundo plano (APScheduler) para monitoreo, seguridad y mantenimiento."""
import logging
import os
import threading
import time
from typing import Any, Dict, Optional

from apscheduler.schedulers.background import BackgroundScheduler

import health_monitor
import security_scanner
import storage
import threat_guard

_logger = logging.getLogger("sos_scheduler")
_scheduler: Optional[BackgroundScheduler] = None
_last_housekeeping_ts: Optional[int] = None

AUDIT_RETENTION_DAYS = int(os.environ.get("AUDIT_RETENTION_DAYS", "180"))


def _run_housekeeping() -> None:
    global _last_housekeeping_ts
    try:
        res = storage.purge_expired_data(audit_retention_days=AUDIT_RETENTION_DAYS)
        _last_housekeeping_ts = int(time.time())
        if any(res.values()):
            _logger.info("Housekeeping completado: %s", res)
    except Exception as exc:
        _logger.warning("Error en tarea housekeeping: %s", exc)


def _safe_uptime_job() -> None:
    try:
        health_monitor.run_uptime_checks()
    except Exception as exc:
        _logger.warning("Error en job uptime_monitor: %s", exc)


def _safe_ssl_job() -> None:
    try:
        health_monitor.run_ssl_checks()
    except Exception as exc:
        _logger.warning("Error en job ssl_monitor: %s", exc)


def _safe_thresholds_job() -> None:
    try:
        health_monitor.run_host_threshold_checks()
    except Exception as exc:
        _logger.warning("Error en job host_thresholds: %s", exc)


def _safe_scanner_job() -> None:
    try:
        security_scanner.run_all_security_scans()
    except Exception as exc:
        _logger.warning("Error en job security_scanner: %s", exc)


def _safe_scheduled_backups_job() -> None:
    try:
        import backup_manager
        backup_manager.run_batch_backups(targets=None, trigger_type="scheduled")
    except Exception as exc:
        _logger.warning("Error en job scheduled_backups: %s", exc)


def sync_backup_schedule_job() -> None:
    if _scheduler is None or not _scheduler.running:
        return
    try:
        import backup_manager
        policy = backup_manager.get_backup_policy(mask_secrets=False)
        job_id = "scheduled_backups_daily"
        if policy.get("schedule_enabled"):
            _scheduler.add_job(
                _safe_scheduled_backups_job,
                trigger="cron",
                hour=int(policy.get("schedule_hour", 2)),
                minute=int(policy.get("schedule_minute", 0)),
                id=job_id,
                replace_existing=True,
                max_instances=1,
                coalesce=True,
            )
        else:
            if _scheduler.get_job(job_id):
                _scheduler.remove_job(job_id)
    except Exception as exc:
        _logger.warning("No se pudo sincronizar job de backups: %s", exc)


def _safe_guard_job() -> None:
    try:
        threat_guard.run_threat_guard_cycle()
    except Exception as exc:
        _logger.warning("Error en job threat_guard: %s", exc)


def _safe_integrity_job() -> None:
    try:
        threat_guard.run_host_integrity_check()
    except Exception as exc:
        _logger.warning("Error en job host_integrity: %s", exc)


def _initial_warmup() -> None:
    """Puebla el primer sondeo de Uptime, SSL, Integridad y Escáner al arrancar sin bloquear Uvicorn."""
    time.sleep(2)
    _safe_guard_job()
    _safe_integrity_job()
    _safe_uptime_job()
    _safe_ssl_job()
    _safe_thresholds_job()
    if not storage.get_all_security_scans():
        _safe_scanner_job()


def start_scheduler() -> BackgroundScheduler:
    global _scheduler
    if _scheduler is not None and _scheduler.running:
        return _scheduler

    storage.init_db()
    _run_housekeeping()

    sched = BackgroundScheduler(timezone="UTC")
    sched.add_job(_run_housekeeping, trigger="interval", minutes=60, id="panel_housekeeping", replace_existing=True, max_instances=1, coalesce=True)
    sched.add_job(_safe_guard_job, trigger="interval", seconds=30, id="threat_guard_30s", replace_existing=True, max_instances=1, coalesce=True)
    sched.add_job(_safe_integrity_job, trigger="interval", minutes=15, id="integrity_monitor_15m", replace_existing=True, max_instances=1, coalesce=True)
    sched.add_job(_safe_uptime_job, trigger="interval", minutes=1, id="uptime_monitor_1m", replace_existing=True, max_instances=1, coalesce=True)
    sched.add_job(_safe_thresholds_job, trigger="interval", minutes=5, id="host_thresholds_5m", replace_existing=True, max_instances=1, coalesce=True)
    sched.add_job(_safe_ssl_job, trigger="interval", hours=6, id="ssl_monitor_6h", replace_existing=True, max_instances=1, coalesce=True)
    sched.add_job(_safe_scanner_job, trigger="interval", hours=12, id="security_scanner_12h", replace_existing=True, max_instances=1, coalesce=True)
    sched.start()
    _scheduler = sched
    sync_backup_schedule_job()

    threading.Thread(target=_initial_warmup, name="sos-health-warmup", daemon=True).start()
    _logger.info("APScheduler iniciado con 7 tareas programadas.")
    return sched


def stop_scheduler() -> None:
    global _scheduler
    if _scheduler is not None:
        try:
            if _scheduler.running:
                _scheduler.shutdown(wait=False)
        except Exception:
            pass
        _scheduler = None


def get_scheduler() -> Optional[BackgroundScheduler]:
    return _scheduler


def get_scheduler_status() -> Dict[str, Any]:
    if _scheduler is None or not _scheduler.running:
        return {"running": False, "jobs_count": 0, "jobs": [], "last_housekeeping_ts": _last_housekeeping_ts}

    jobs_info = []
    for job in _scheduler.get_jobs():
        next_run = int(job.next_run_time.timestamp()) if job.next_run_time else None
        jobs_info.append({"id": job.id, "next_run_ts": next_run})

    return {
        "running": True,
        "jobs_count": len(jobs_info),
        "jobs": jobs_info,
        "last_housekeeping_ts": _last_housekeeping_ts,
    }
