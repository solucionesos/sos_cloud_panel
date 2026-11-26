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


def _initial_warmup() -> None:
    """Puebla el primer sondeo de Uptime, SSL y Escáner al arrancar sin bloquear Uvicorn."""
    time.sleep(2)
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
    sched.add_job(_safe_uptime_job, trigger="interval", minutes=1, id="uptime_monitor_1m", replace_existing=True, max_instances=1, coalesce=True)
    sched.add_job(_safe_thresholds_job, trigger="interval", minutes=5, id="host_thresholds_5m", replace_existing=True, max_instances=1, coalesce=True)
    sched.add_job(_safe_ssl_job, trigger="interval", hours=6, id="ssl_monitor_6h", replace_existing=True, max_instances=1, coalesce=True)
    sched.add_job(_safe_scanner_job, trigger="interval", hours=12, id="security_scanner_12h", replace_existing=True, max_instances=1, coalesce=True)
    sched.start()
    _scheduler = sched

    threading.Thread(target=_initial_warmup, name="sos-health-warmup", daemon=True).start()
    _logger.info("APScheduler iniciado con 5 tareas programadas.")
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
