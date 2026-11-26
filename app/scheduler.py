"""Planificador de tareas en segundo plano (APScheduler) para mantenimiento y futuras fases."""
import logging
import os
import time
from typing import Any, Dict, Optional

from apscheduler.schedulers.background import BackgroundScheduler

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
        if res["purged_sessions"] or res["purged_audit_logs"]:
            _logger.info("Housekeeping completado: %s", res)
    except Exception as exc:
        _logger.warning("Error en tarea housekeeping: %s", exc)


def start_scheduler() -> BackgroundScheduler:
    global _scheduler
    if _scheduler is not None and _scheduler.running:
        return _scheduler

    storage.init_db()
    _run_housekeeping()

    sched = BackgroundScheduler(timezone="UTC")
    sched.add_job(
        _run_housekeeping,
        trigger="interval",
        minutes=60,
        id="panel_housekeeping",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )
    sched.start()
    _scheduler = sched
    _logger.info("APScheduler iniciado correctamente.")
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
