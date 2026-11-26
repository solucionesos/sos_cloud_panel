"""Capa de persistencia SQLite (modo WAL) para SOS Cloud Control Panel."""
import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from typing import Any, Dict, List, Optional

_init_lock = threading.Lock()
_initialized = False


def _resolve_db_path() -> str:
    env_dir = os.environ.get("PANEL_DATA_DIR", "").strip()
    if env_dir:
        data_dir = env_dir
    elif os.path.isdir("/app"):
        data_dir = "/app/data"
    else:
        data_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data"))
    os.makedirs(data_dir, exist_ok=True)
    return os.path.join(data_dir, "panel.db")


DB_PATH = _resolve_db_path()


@contextmanager
def get_conn():
    init_db()
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    global _initialized
    if _initialized:
        return
    with _init_lock:
        if _initialized:
            return
        conn = sqlite3.connect(DB_PATH, timeout=10.0)
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            conn.execute("PRAGMA foreign_keys=ON;")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS sessions (
                    sid TEXT PRIMARY KEY,
                    username TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    user_agent TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    last_seen INTEGER NOT NULL,
                    revoked INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_sessions_active ON sessions(revoked, last_seen DESC);

                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts INTEGER NOT NULL,
                    username TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    action TEXT NOT NULL,
                    target TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'ok',
                    detail TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_logs(ts DESC);
                CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action);

                CREATE TABLE IF NOT EXISTS trusted_ips (
                    ip TEXT PRIMARY KEY,
                    note TEXT NOT NULL DEFAULT '',
                    created_at INTEGER NOT NULL,
                    created_by TEXT NOT NULL DEFAULT 'admin'
                );

                CREATE TABLE IF NOT EXISTS uptime_checks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts INTEGER NOT NULL,
                    domain TEXT NOT NULL,
                    url TEXT NOT NULL,
                    is_up INTEGER NOT NULL,
                    status_code INTEGER NOT NULL DEFAULT 0,
                    latency_ms INTEGER NOT NULL DEFAULT 0,
                    error TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS idx_uptime_domain_ts ON uptime_checks(domain, ts DESC);
                CREATE INDEX IF NOT EXISTS idx_uptime_ts ON uptime_checks(ts DESC);

                CREATE TABLE IF NOT EXISTS ssl_status (
                    domain TEXT PRIMARY KEY,
                    checked_at INTEGER NOT NULL,
                    valid INTEGER NOT NULL DEFAULT 0,
                    days_left INTEGER NOT NULL DEFAULT -1,
                    not_after TEXT NOT NULL DEFAULT '',
                    issuer TEXT NOT NULL DEFAULT '',
                    tls_version TEXT NOT NULL DEFAULT '',
                    error TEXT NOT NULL DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS security_scans (
                    domain TEXT PRIMARY KEY,
                    scanned_at INTEGER NOT NULL,
                    score INTEGER NOT NULL DEFAULT 0,
                    grade TEXT NOT NULL DEFAULT 'F',
                    db_name TEXT NOT NULL DEFAULT '',
                    findings_json TEXT NOT NULL DEFAULT '[]'
                );

                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_key TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    severity TEXT NOT NULL DEFAULT 'warning',
                    target TEXT NOT NULL,
                    title TEXT NOT NULL,
                    detail TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'open',
                    opened_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    resolved_at INTEGER NOT NULL DEFAULT 0,
                    notified_at INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status, opened_at DESC);
                CREATE INDEX IF NOT EXISTS idx_incidents_key ON incidents(incident_key, status);

                CREATE TABLE IF NOT EXISTS backup_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    started_at INTEGER NOT NULL,
                    finished_at INTEGER NOT NULL DEFAULT 0,
                    trigger_type TEXT NOT NULL DEFAULT 'manual',
                    db_name TEXT NOT NULL,
                    pg_container TEXT NOT NULL DEFAULT '',
                    fmt TEXT NOT NULL DEFAULT 'zip',
                    filename TEXT NOT NULL DEFAULT '',
                    size_bytes INTEGER NOT NULL DEFAULT 0,
                    sha256 TEXT NOT NULL DEFAULT '',
                    encrypted INTEGER NOT NULL DEFAULT 0,
                    restore_tested INTEGER NOT NULL DEFAULT 0,
                    restore_ok INTEGER NOT NULL DEFAULT 0,
                    restore_detail TEXT NOT NULL DEFAULT '',
                    destinations_json TEXT NOT NULL DEFAULT '{}',
                    status TEXT NOT NULL DEFAULT 'running',
                    error TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS idx_backup_runs_ts ON backup_runs(started_at DESC);
                CREATE INDEX IF NOT EXISTS idx_backup_runs_db ON backup_runs(db_name, started_at DESC);
                """
            )
            conn.commit()
            _initialized = True
        finally:
            conn.close()


# --- Settings ---

def get_setting(key: str, default: Optional[str] = None) -> Optional[str]:
    with get_conn() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default


def set_setting(key: str, value: str) -> None:
    now = int(time.time())
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO settings (key, value, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
            """,
            (key, value, now),
        )


def delete_setting(key: str) -> None:
    with get_conn() as conn:
        conn.execute("DELETE FROM settings WHERE key = ?", (key,))


# --- Sessions ---

def create_session(sid: str, username: str, ip: str, user_agent: str) -> None:
    now = int(time.time())
    ua = (user_agent or "Unknown")[:250]
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO sessions (sid, username, ip, user_agent, created_at, last_seen, revoked)
            VALUES (?, ?, ?, ?, ?, ?, 0)
            """,
            (sid, username, ip, ua, now, now),
        )


def get_valid_session(sid: str, max_age_seconds: int = 86400 * 7) -> Optional[Dict[str, Any]]:
    now = int(time.time())
    with get_conn() as conn:
        row = conn.execute(
            "SELECT sid, username, ip, user_agent, created_at, last_seen, revoked FROM sessions WHERE sid = ?",
            (sid,),
        ).fetchone()
        if not row:
            return None
        if row["revoked"] != 0:
            return None
        if now - row["created_at"] > max_age_seconds:
            return None
        # Actualizar last_seen como máximo una vez por minuto para evitar escrituras constantes por polling
        if now - row["last_seen"] >= 60:
            conn.execute("UPDATE sessions SET last_seen = ? WHERE sid = ?", (now, sid))
        return dict(row)


def revoke_session(sid: str) -> bool:
    with get_conn() as conn:
        cur = conn.execute("UPDATE sessions SET revoked = 1 WHERE sid = ? AND revoked = 0", (sid,))
        return cur.rowcount > 0


def revoke_other_sessions(current_sid: str) -> int:
    with get_conn() as conn:
        cur = conn.execute("UPDATE sessions SET revoked = 1 WHERE sid != ? AND revoked = 0", (current_sid,))
        return cur.rowcount


def list_active_sessions(max_age_seconds: int = 86400 * 7) -> List[Dict[str, Any]]:
    cutoff = int(time.time()) - max_age_seconds
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT sid, username, ip, user_agent, created_at, last_seen
            FROM sessions
            WHERE revoked = 0 AND created_at >= ?
            ORDER BY last_seen DESC
            """,
            (cutoff,),
        ).fetchall()
        return [dict(r) for r in rows]


# --- Trusted IPs ---

def list_trusted_ips() -> List[Dict[str, Any]]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT ip, note, created_at, created_by FROM trusted_ips ORDER BY created_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]


def add_trusted_ip(ip: str, note: str = "", created_by: str = "admin") -> None:
    now = int(time.time())
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO trusted_ips (ip, note, created_at, created_by)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET note = excluded.note, created_at = excluded.created_at, created_by = excluded.created_by
            """,
            (ip.strip(), note.strip()[:200], now, created_by),
        )


def remove_trusted_ip(ip: str) -> bool:
    with get_conn() as conn:
        cur = conn.execute("DELETE FROM trusted_ips WHERE ip = ?", (ip.strip(),))
        return cur.rowcount > 0


# --- Audit Logs ---

def insert_audit_log(username: str, ip: str, action: str, target: str = "", status: str = "ok", detail: str = "") -> None:
    now = int(time.time())
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO audit_logs (ts, username, ip, action, target, status, detail)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (now, username[:80], ip[:80], action[:80], target[:200], status[:30], detail[:500]),
        )


def query_audit_logs(limit: int = 150, action_filter: str = "", status_filter: str = "", search: str = "") -> List[Dict[str, Any]]:
    clauses = []
    params: List[Any] = []
    if action_filter:
        clauses.append("action = ?")
        params.append(action_filter)
    if status_filter:
        clauses.append("status = ?")
        params.append(status_filter)
    if search:
        q = f"%{search.lower()}%"
        clauses.append("(LOWER(username) LIKE ? OR LOWER(ip) LIKE ? OR LOWER(action) LIKE ? OR LOWER(target) LIKE ? OR LOWER(detail) LIKE ?)")
        params.extend([q, q, q, q, q])

    where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    safe_limit = max(1, min(int(limit), 500))
    params.append(safe_limit)

    with get_conn() as conn:
        rows = conn.execute(
            f"""
            SELECT id, ts, username, ip, action, target, status, detail
            FROM audit_logs
            {where_sql}
            ORDER BY ts DESC, id DESC
            LIMIT ?
            """,
            params,
        ).fetchall()
        return [dict(r) for r in rows]


def count_audit_summary_24h() -> Dict[str, int]:
    cutoff = int(time.time()) - 86400
    with get_conn() as conn:
        total = conn.execute("SELECT COUNT(*) AS c FROM audit_logs WHERE ts >= ?", (cutoff,)).fetchone()["c"]
        failed = conn.execute("SELECT COUNT(*) AS c FROM audit_logs WHERE ts >= ? AND status != 'ok'", (cutoff,)).fetchone()["c"]
        sso = conn.execute("SELECT COUNT(*) AS c FROM audit_logs WHERE ts >= ? AND action = 'sso.login'", (cutoff,)).fetchone()["c"]
        return {"events_24h": total, "failed_24h": failed, "sso_24h": sso}


# --- Fase 2: Uptime, SSL, Security Scans & Incidents ---

def insert_uptime_batch(rows: List[Dict[str, Any]]) -> None:
    if not rows:
        return
    with get_conn() as conn:
        conn.executemany(
            """
            INSERT INTO uptime_checks (ts, domain, url, is_up, status_code, latency_ms, error)
            VALUES (:ts, :domain, :url, :is_up, :status_code, :latency_ms, :error)
            """,
            rows,
        )


def get_domain_recent_failures(domain: str, limit: int = 2) -> int:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT is_up FROM uptime_checks WHERE domain = ? ORDER BY ts DESC, id DESC LIMIT ?",
            (domain, limit),
        ).fetchall()
        count = 0
        for r in rows:
            if r["is_up"] == 0:
                count += 1
            else:
                break
        return count


def get_uptime_summary_by_domain() -> Dict[str, Dict[str, Any]]:
    cutoff_24h = int(time.time()) - 86400
    cutoff_7d = int(time.time()) - 86400 * 7
    out: Dict[str, Dict[str, Any]] = {}
    with get_conn() as conn:
        # Estadísticas agregadas 24h y 7d
        agg_24 = {
            r["domain"]: dict(r)
            for r in conn.execute(
                """
                SELECT domain,
                       COUNT(*) AS total_24h,
                       SUM(is_up) AS up_24h,
                       ROUND(AVG(CASE WHEN is_up = 1 THEN latency_ms END), 0) AS avg_latency_24h
                FROM uptime_checks
                WHERE ts >= ?
                GROUP BY domain
                """,
                (cutoff_24h,),
            ).fetchall()
        }
        agg_7d = {
            r["domain"]: dict(r)
            for r in conn.execute(
                """
                SELECT domain, COUNT(*) AS total_7d, SUM(is_up) AS up_7d
                FROM uptime_checks
                WHERE ts >= ?
                GROUP BY domain
                """,
                (cutoff_7d,),
            ).fetchall()
        }
        latest_rows = conn.execute(
            """
            SELECT u.domain, u.url, u.ts, u.is_up, u.status_code, u.latency_ms, u.error
            FROM uptime_checks u
            INNER JOIN (
                SELECT domain, MAX(id) AS max_id
                FROM uptime_checks
                GROUP BY domain
            ) m ON u.id = m.max_id
            """
        ).fetchall()

        for r in latest_rows:
            dom = r["domain"]
            a24 = agg_24.get(dom, {})
            a7 = agg_7d.get(dom, {})
            t24 = a24.get("total_24h") or 0
            u24 = a24.get("up_24h") or 0
            t7 = a7.get("total_7d") or 0
            u7 = a7.get("up_7d") or 0
            out[dom] = {
                "domain": dom,
                "url": r["url"],
                "last_ts": r["ts"],
                "is_up": bool(r["is_up"]),
                "status_code": r["status_code"],
                "latency_ms": r["latency_ms"],
                "error": r["error"],
                "uptime_24h": round((u24 / t24) * 100.0, 2) if t24 > 0 else 100.0,
                "uptime_7d": round((u7 / t7) * 100.0, 2) if t7 > 0 else 100.0,
                "avg_latency_24h": int(a24.get("avg_latency_24h") or r["latency_ms"] or 0),
                "checks_24h": t24,
            }
    return out


def upsert_ssl_status(
    domain: str,
    valid: bool,
    days_left: int,
    not_after: str,
    issuer: str,
    tls_version: str,
    error: str = "",
) -> None:
    now = int(time.time())
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO ssl_status (domain, checked_at, valid, days_left, not_after, issuer, tls_version, error)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(domain) DO UPDATE SET
                checked_at = excluded.checked_at,
                valid = excluded.valid,
                days_left = excluded.days_left,
                not_after = excluded.not_after,
                issuer = excluded.issuer,
                tls_version = excluded.tls_version,
                error = excluded.error
            """,
            (domain, now, 1 if valid else 0, days_left, not_after[:80], issuer[:160], tls_version[:40], error[:300]),
        )


def get_all_ssl_status() -> Dict[str, Dict[str, Any]]:
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM ssl_status").fetchall()
        return {r["domain"]: dict(r) for r in rows}


def upsert_security_scan(domain: str, score: int, grade: str, db_name: str, findings_json: str) -> None:
    now = int(time.time())
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO security_scans (domain, scanned_at, score, grade, db_name, findings_json)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(domain) DO UPDATE SET
                scanned_at = excluded.scanned_at,
                score = excluded.score,
                grade = excluded.grade,
                db_name = excluded.db_name,
                findings_json = excluded.findings_json
            """,
            (domain, now, int(score), grade[:4], db_name[:120], findings_json),
        )


def get_all_security_scans() -> Dict[str, Dict[str, Any]]:
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM security_scans").fetchall()
        return {r["domain"]: dict(r) for r in rows}


def get_open_incident(incident_key: str) -> Optional[Dict[str, Any]]:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM incidents WHERE incident_key = ? AND status = 'open' ORDER BY id DESC LIMIT 1",
            (incident_key,),
        ).fetchone()
        return dict(row) if row else None


def create_or_touch_incident(
    incident_key: str,
    kind: str,
    severity: str,
    target: str,
    title: str,
    detail: str,
) -> Dict[str, Any]:
    now = int(time.time())
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM incidents WHERE incident_key = ? AND status = 'open' ORDER BY id DESC LIMIT 1",
            (incident_key,),
        ).fetchone()
        if row:
            conn.execute(
                "UPDATE incidents SET severity = ?, title = ?, detail = ?, updated_at = ? WHERE id = ?",
                (severity, title[:200], detail[:500], now, row["id"]),
            )
            d = dict(row)
            d.update({"severity": severity, "title": title[:200], "detail": detail[:500], "updated_at": now, "is_new": False})
            return d

        cur = conn.execute(
            """
            INSERT INTO incidents (incident_key, kind, severity, target, title, detail, status, opened_at, updated_at, resolved_at, notified_at)
            VALUES (?, ?, ?, ?, ?, ?, 'open', ?, ?, 0, 0)
            """,
            (incident_key[:140], kind[:60], severity[:20], target[:160], title[:200], detail[:500], now, now),
        )
        return {
            "id": cur.lastrowid,
            "incident_key": incident_key,
            "kind": kind,
            "severity": severity,
            "target": target,
            "title": title,
            "detail": detail,
            "status": "open",
            "opened_at": now,
            "updated_at": now,
            "resolved_at": 0,
            "notified_at": 0,
            "is_new": True,
        }


def mark_incident_notified(incident_id: int) -> None:
    now = int(time.time())
    with get_conn() as conn:
        conn.execute("UPDATE incidents SET notified_at = ? WHERE id = ?", (now, incident_id))


def resolve_open_incident(incident_key: str, resolution_detail: str = "") -> Optional[Dict[str, Any]]:
    now = int(time.time())
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM incidents WHERE incident_key = ? AND status = 'open' ORDER BY id DESC LIMIT 1",
            (incident_key,),
        ).fetchone()
        if not row:
            return None
        new_detail = resolution_detail[:500] if resolution_detail else row["detail"]
        conn.execute(
            "UPDATE incidents SET status = 'resolved', resolved_at = ?, updated_at = ?, detail = ? WHERE id = ?",
            (now, now, new_detail, row["id"]),
        )
        d = dict(row)
        d.update({"status": "resolved", "resolved_at": now, "updated_at": now, "detail": new_detail})
        return d


def list_incidents(limit: int = 60, status_filter: str = "") -> List[Dict[str, Any]]:
    safe_limit = max(1, min(int(limit), 250))
    with get_conn() as conn:
        if status_filter in ("open", "resolved"):
            rows = conn.execute(
                "SELECT * FROM incidents WHERE status = ? ORDER BY CASE WHEN status='open' THEN 0 ELSE 1 END, opened_at DESC LIMIT ?",
                (status_filter, safe_limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM incidents ORDER BY CASE WHEN status='open' THEN 0 ELSE 1 END, opened_at DESC LIMIT ?",
                (safe_limit,),
            ).fetchall()
        return [dict(r) for r in rows]


# --- Fase 3: Backup Runs ---

def create_backup_run(db_name: str, pg_container: str, fmt: str, trigger_type: str = "manual") -> int:
    now = int(time.time())
    with get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO backup_runs (started_at, trigger_type, db_name, pg_container, fmt, status)
            VALUES (?, ?, ?, ?, ?, 'running')
            """,
            (now, trigger_type[:30], db_name[:120], pg_container[:120], fmt[:10]),
        )
        return int(cur.lastrowid)


def finish_backup_run(
    run_id: int,
    status: str,
    filename: str = "",
    size_bytes: int = 0,
    sha256: str = "",
    encrypted: bool = False,
    restore_tested: bool = False,
    restore_ok: bool = False,
    restore_detail: str = "",
    destinations_json: str = "{}",
    error: str = "",
) -> None:
    now = int(time.time())
    with get_conn() as conn:
        conn.execute(
            """
            UPDATE backup_runs
            SET finished_at = ?,
                status = ?,
                filename = ?,
                size_bytes = ?,
                sha256 = ?,
                encrypted = ?,
                restore_tested = ?,
                restore_ok = ?,
                restore_detail = ?,
                destinations_json = ?,
                error = ?
            WHERE id = ?
            """,
            (
                now,
                status[:20],
                filename[:220],
                int(size_bytes),
                sha256[:80],
                1 if encrypted else 0,
                1 if restore_tested else 0,
                1 if restore_ok else 0,
                restore_detail[:300],
                destinations_json,
                error[:500],
                int(run_id),
            ),
        )


def list_backup_runs(limit: int = 80, db_filter: str = "") -> List[Dict[str, Any]]:
    safe_limit = max(1, min(int(limit), 300))
    with get_conn() as conn:
        if db_filter:
            rows = conn.execute(
                "SELECT * FROM backup_runs WHERE db_name = ? ORDER BY id DESC LIMIT ?",
                (db_filter, safe_limit),
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM backup_runs ORDER BY id DESC LIMIT ?", (safe_limit,)).fetchall()
        return [dict(r) for r in rows]


def get_backup_summary_30d() -> Dict[str, Any]:
    cutoff = int(time.time()) - (30 * 86400)
    with get_conn() as conn:
        total = conn.execute("SELECT COUNT(*) AS c FROM backup_runs WHERE started_at >= ?", (cutoff,)).fetchone()["c"]
        ok_cnt = conn.execute("SELECT COUNT(*) AS c FROM backup_runs WHERE started_at >= ? AND status = 'ok'", (cutoff,)).fetchone()["c"]
        verified = conn.execute("SELECT COUNT(*) AS c FROM backup_runs WHERE started_at >= ? AND restore_ok = 1", (cutoff,)).fetchone()["c"]
        failed = conn.execute("SELECT COUNT(*) AS c FROM backup_runs WHERE started_at >= ? AND status = 'failed'", (cutoff,)).fetchone()["c"]
        running = conn.execute("SELECT COUNT(*) AS c FROM backup_runs WHERE status = 'running'").fetchone()["c"]
        last_ok = conn.execute("SELECT finished_at, db_name FROM backup_runs WHERE status = 'ok' ORDER BY finished_at DESC LIMIT 1").fetchone()
        return {
            "total_30d": total,
            "ok_30d": ok_cnt,
            "verified_30d": verified,
            "failed_30d": failed,
            "running_now": running,
            "last_ok_ts": last_ok["finished_at"] if last_ok else 0,
            "last_ok_db": last_ok["db_name"] if last_ok else "",
        }


# --- Housekeeping ---

def purge_expired_data(session_max_age: int = 86400 * 7, audit_retention_days: int = 180) -> Dict[str, int]:
    now = int(time.time())
    sess_cutoff = now - session_max_age
    audit_cutoff = now - (max(7, audit_retention_days) * 86400)
    uptime_cutoff = now - (14 * 86400)
    incidents_cutoff = now - (90 * 86400)
    backups_hist_cutoff = now - (180 * 86400)
    with get_conn() as conn:
        c1 = conn.execute("DELETE FROM sessions WHERE created_at < ? OR (revoked = 1 AND last_seen < ?)", (sess_cutoff, now - 86400)).rowcount
        c2 = conn.execute("DELETE FROM audit_logs WHERE ts < ?", (audit_cutoff,)).rowcount
        c3 = conn.execute("DELETE FROM uptime_checks WHERE ts < ?", (uptime_cutoff,)).rowcount
        c4 = conn.execute("DELETE FROM incidents WHERE status = 'resolved' AND resolved_at > 0 AND resolved_at < ?", (incidents_cutoff,)).rowcount
        c5 = conn.execute("DELETE FROM backup_runs WHERE status != 'running' AND started_at < ?", (backups_hist_cutoff,)).rowcount
    return {"purged_sessions": c1, "purged_audit_logs": c2, "purged_uptime": c3, "purged_incidents": c4, "purged_backup_runs": c5}
