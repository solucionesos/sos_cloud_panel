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

                CREATE TABLE IF NOT EXISTS blocked_ips (
                    ip TEXT PRIMARY KEY,
                    reason TEXT NOT NULL,
                    source TEXT NOT NULL DEFAULT 'manual',
                    hits INTEGER NOT NULL DEFAULT 1,
                    reoffenses INTEGER NOT NULL DEFAULT 0,
                    blocked_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL DEFAULT 0,
                    active INTEGER NOT NULL DEFAULT 1
                );
                CREATE INDEX IF NOT EXISTS idx_blocked_active ON blocked_ips(active, blocked_at DESC);

                CREATE TABLE IF NOT EXISTS threat_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts INTEGER NOT NULL,
                    ip TEXT NOT NULL,
                    vector TEXT NOT NULL,
                    severity TEXT NOT NULL DEFAULT 'warning',
                    target TEXT NOT NULL DEFAULT '',
                    action_taken TEXT NOT NULL DEFAULT 'observed',
                    detail TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS idx_threat_ts ON threat_events(ts DESC);
                CREATE INDEX IF NOT EXISTS idx_threat_vector ON threat_events(vector, ts DESC);

                CREATE TABLE IF NOT EXISTS host_integrity_baseline (
                    filepath TEXT PRIMARY KEY,
                    sha256 TEXT NOT NULL,
                    mtime INTEGER NOT NULL DEFAULT 0,
                    size_bytes INTEGER NOT NULL DEFAULT 0,
                    first_seen INTEGER NOT NULL,
                    last_checked INTEGER NOT NULL,
                    status TEXT NOT NULL DEFAULT 'ok',
                    current_sha256 TEXT NOT NULL DEFAULT '',
                    detail TEXT NOT NULL DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS filestore_scan_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    started_at INTEGER NOT NULL,
                    finished_at INTEGER NOT NULL DEFAULT 0,
                    scanned_dbs INTEGER NOT NULL DEFAULT 0,
                    scanned_files INTEGER NOT NULL DEFAULT 0,
                    threats_found INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL DEFAULT 'running'
                );

                CREATE TABLE IF NOT EXISTS filestore_findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    detected_at INTEGER NOT NULL,
                    db_name TEXT NOT NULL,
                    store_fname TEXT NOT NULL,
                    original_name TEXT NOT NULL DEFAULT '',
                    declared_mime TEXT NOT NULL DEFAULT '',
                    host_path TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL DEFAULT 0,
                    file_uid INTEGER NOT NULL DEFAULT 0,
                    file_gid INTEGER NOT NULL DEFAULT 0,
                    file_mode INTEGER NOT NULL DEFAULT 420,
                    rule_name TEXT NOT NULL,
                    severity TEXT NOT NULL DEFAULT 'critical',
                    detail TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'detected',
                    quarantine_path TEXT NOT NULL DEFAULT '',
                    UNIQUE(host_path, sha256)
                );
                CREATE INDEX IF NOT EXISTS idx_fs_findings_status ON filestore_findings(status, detected_at DESC);
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


# --- Fase 4: Threat Guard, Blocked IPs & Host Integrity ---

def insert_threat_event(
    ip: str,
    vector: str,
    severity: str,
    target: str,
    action_taken: str,
    detail: str,
) -> None:
    now = int(time.time())
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO threat_events (ts, ip, vector, severity, target, action_taken, detail)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (now, ip[:80], vector[:50], severity[:20], target[:180], action_taken[:30], detail[:400]),
        )


def list_threat_events(limit: int = 120, vector_filter: str = "") -> List[Dict[str, Any]]:
    safe_limit = max(1, min(int(limit), 300))
    with get_conn() as conn:
        if vector_filter:
            rows = conn.execute(
                "SELECT * FROM threat_events WHERE vector = ? ORDER BY ts DESC, id DESC LIMIT ?",
                (vector_filter, safe_limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM threat_events ORDER BY ts DESC, id DESC LIMIT ?",
                (safe_limit,),
            ).fetchall()
        return [dict(r) for r in rows]


def get_threat_summary_24h() -> Dict[str, int]:
    cutoff = int(time.time()) - 86400
    with get_conn() as conn:
        total = conn.execute("SELECT COUNT(*) AS c FROM threat_events WHERE ts >= ?", (cutoff,)).fetchone()["c"]
        ssh = conn.execute("SELECT COUNT(*) AS c FROM threat_events WHERE ts >= ? AND vector = 'ssh_bruteforce'", (cutoff,)).fetchone()["c"]
        odoo = conn.execute("SELECT COUNT(*) AS c FROM threat_events WHERE ts >= ? AND vector = 'odoo_login'", (cutoff,)).fetchone()["c"]
        web = conn.execute("SELECT COUNT(*) AS c FROM threat_events WHERE ts >= ? AND vector = 'web_honeypot'", (cutoff,)).fetchone()["c"]
        active_blocks = conn.execute("SELECT COUNT(*) AS c FROM blocked_ips WHERE active = 1").fetchone()["c"]
        return {
            "events_24h": total,
            "ssh_24h": ssh,
            "odoo_24h": odoo,
            "web_24h": web,
            "active_blocks": active_blocks,
        }


def upsert_blocked_ip(
    ip: str,
    reason: str,
    source: str,
    duration_seconds: int,
    hits: int = 1,
) -> Dict[str, Any]:
    now = int(time.time())
    with get_conn() as conn:
        prev = conn.execute("SELECT reoffenses, active FROM blocked_ips WHERE ip = ?", (ip,)).fetchone()
        reoffenses = int(prev["reoffenses"]) + (1 if prev and prev["active"] == 0 else 0) if prev else 0
        # Escalar castigo en reincidentes automáticos (hasta 24h)
        if duration_seconds > 0 and reoffenses > 0 and source != "manual":
            scaled = min(86400, duration_seconds * (2 ** min(reoffenses, 4)))
        else:
            scaled = duration_seconds
        expires_at = (now + scaled) if scaled > 0 else 0

        conn.execute(
            """
            INSERT INTO blocked_ips (ip, reason, source, hits, reoffenses, blocked_at, expires_at, active)
            VALUES (?, ?, ?, ?, ?, ?, ?, 1)
            ON CONFLICT(ip) DO UPDATE SET
                reason = excluded.reason,
                source = excluded.source,
                hits = blocked_ips.hits + excluded.hits,
                reoffenses = ?,
                blocked_at = excluded.blocked_at,
                expires_at = excluded.expires_at,
                active = 1
            """,
            (ip.strip(), reason[:220], source[:40], max(1, hits), reoffenses, now, expires_at, reoffenses),
        )
        return {"ip": ip.strip(), "expires_at": expires_at, "reoffenses": reoffenses}


def expire_old_blocks() -> List[str]:
    now = int(time.time())
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT ip FROM blocked_ips WHERE active = 1 AND expires_at > 0 AND expires_at <= ?",
            (now,),
        ).fetchall()
        expired_ips = [r["ip"] for r in rows]
        if expired_ips:
            conn.execute(
                "UPDATE blocked_ips SET active = 0 WHERE active = 1 AND expires_at > 0 AND expires_at <= ?",
                (now,),
            )
        return expired_ips


def deactivate_blocked_ip(ip: str) -> bool:
    with get_conn() as conn:
        cur = conn.execute("UPDATE blocked_ips SET active = 0 WHERE ip = ? AND active = 1", (ip.strip(),))
        return cur.rowcount > 0


def deactivate_all_blocked_ips() -> int:
    with get_conn() as conn:
        cur = conn.execute("UPDATE blocked_ips SET active = 0 WHERE active = 1")
        return cur.rowcount


def list_blocked_ips(only_active: bool = True) -> List[Dict[str, Any]]:
    with get_conn() as conn:
        if only_active:
            rows = conn.execute(
                "SELECT * FROM blocked_ips WHERE active = 1 ORDER BY blocked_at DESC"
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM blocked_ips ORDER BY active DESC, blocked_at DESC LIMIT 200"
            ).fetchall()
        return [dict(r) for r in rows]


def get_integrity_baselines() -> Dict[str, Dict[str, Any]]:
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM host_integrity_baseline ORDER BY filepath ASC").fetchall()
        return {r["filepath"]: dict(r) for r in rows}


def upsert_integrity_record(
    filepath: str,
    sha256: str,
    mtime: int,
    size_bytes: int,
    status: str = "ok",
    current_sha256: str = "",
    detail: str = "",
    approve_baseline: bool = False,
) -> None:
    now = int(time.time())
    with get_conn() as conn:
        existing = conn.execute("SELECT * FROM host_integrity_baseline WHERE filepath = ?", (filepath,)).fetchone()
        if not existing or approve_baseline:
            conn.execute(
                """
                INSERT INTO host_integrity_baseline (filepath, sha256, mtime, size_bytes, first_seen, last_checked, status, current_sha256, detail)
                VALUES (?, ?, ?, ?, ?, ?, 'ok', ?, ?)
                ON CONFLICT(filepath) DO UPDATE SET
                    sha256 = excluded.sha256,
                    mtime = excluded.mtime,
                    size_bytes = excluded.size_bytes,
                    last_checked = excluded.last_checked,
                    status = 'ok',
                    current_sha256 = excluded.sha256,
                    detail = excluded.detail
                """,
                (filepath, sha256, mtime, size_bytes, existing["first_seen"] if existing else now, now, sha256, detail[:240]),
            )
        else:
            conn.execute(
                """
                UPDATE host_integrity_baseline
                SET last_checked = ?, status = ?, current_sha256 = ?, mtime = ?, size_bytes = ?, detail = ?
                WHERE filepath = ?
                """,
                (now, status, current_sha256 or sha256, mtime, size_bytes, detail[:240], filepath),
            )


def remove_integrity_record(filepath: str) -> None:
    with get_conn() as conn:
        conn.execute("DELETE FROM host_integrity_baseline WHERE filepath = ?", (filepath,))


# --- Fase 5: Filestore Antivirus Findings & Quarantine ---

def create_filestore_scan_run() -> int:
    now = int(time.time())
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO filestore_scan_runs (started_at, status) VALUES (?, 'running')",
            (now,),
        )
        return int(cur.lastrowid)


def finish_filestore_scan_run(run_id: int, scanned_dbs: int, scanned_files: int, threats_found: int, status: str = "ok") -> None:
    now = int(time.time())
    with get_conn() as conn:
        conn.execute(
            """
            UPDATE filestore_scan_runs
            SET finished_at = ?, scanned_dbs = ?, scanned_files = ?, threats_found = ?, status = ?
            WHERE id = ?
            """,
            (now, scanned_dbs, scanned_files, threats_found, status, run_id),
        )


def get_last_filestore_scan() -> Optional[Dict[str, Any]]:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM filestore_scan_runs ORDER BY id DESC LIMIT 1").fetchone()
        return dict(row) if row else None


def upsert_filestore_finding(
    db_name: str,
    store_fname: str,
    original_name: str,
    declared_mime: str,
    host_path: str,
    sha256: str,
    size_bytes: int,
    file_uid: int,
    file_gid: int,
    file_mode: int,
    rule_name: str,
    severity: str,
    detail: str,
) -> Optional[int]:
    now = int(time.time())
    with get_conn() as conn:
        existing = conn.execute(
            "SELECT id, status FROM filestore_findings WHERE host_path = ? AND sha256 = ?",
            (host_path, sha256),
        ).fetchone()
        if existing:
            # Si ya fue marcado como whitelisted/restored por el administrador, respetarlo
            if existing["status"] == "ignored":
                return None
            return int(existing["id"])
        cur = conn.execute(
            """
            INSERT INTO filestore_findings (
                detected_at, db_name, store_fname, original_name, declared_mime,
                host_path, sha256, size_bytes, file_uid, file_gid, file_mode,
                rule_name, severity, detail, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'detected')
            """,
            (
                now, db_name[:100], store_fname[:180], original_name[:200], declared_mime[:120],
                host_path, sha256, size_bytes, file_uid, file_gid, file_mode,
                rule_name[:100], severity[:20], detail[:350],
            ),
        )
        return int(cur.lastrowid)


def get_filestore_finding(finding_id: int) -> Optional[Dict[str, Any]]:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM filestore_findings WHERE id = ?", (int(finding_id),)).fetchone()
        return dict(row) if row else None


def update_filestore_finding_status(finding_id: int, status: str, quarantine_path: str = "") -> None:
    with get_conn() as conn:
        conn.execute(
            "UPDATE filestore_findings SET status = ?, quarantine_path = ? WHERE id = ?",
            (status, quarantine_path, int(finding_id)),
        )


def list_filestore_findings(status_filter: str = "") -> List[Dict[str, Any]]:
    with get_conn() as conn:
        if status_filter:
            rows = conn.execute(
                "SELECT * FROM filestore_findings WHERE status = ? ORDER BY detected_at DESC LIMIT 200",
                (status_filter,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM filestore_findings ORDER BY CASE WHEN status='detected' THEN 0 WHEN status='quarantined' THEN 1 ELSE 2 END, detected_at DESC LIMIT 200"
            ).fetchall()
        return [dict(r) for r in rows]


# --- Housekeeping ---

def purge_expired_data(session_max_age: int = 86400 * 7, audit_retention_days: int = 180) -> Dict[str, int]:
    now = int(time.time())
    sess_cutoff = now - session_max_age
    audit_cutoff = now - (max(7, audit_retention_days) * 86400)
    uptime_cutoff = now - (14 * 86400)
    incidents_cutoff = now - (90 * 86400)
    backups_hist_cutoff = now - (180 * 86400)
    threats_cutoff = now - (60 * 86400)
    with get_conn() as conn:
        c1 = conn.execute("DELETE FROM sessions WHERE created_at < ? OR (revoked = 1 AND last_seen < ?)", (sess_cutoff, now - 86400)).rowcount
        c2 = conn.execute("DELETE FROM audit_logs WHERE ts < ?", (audit_cutoff,)).rowcount
        c3 = conn.execute("DELETE FROM uptime_checks WHERE ts < ?", (uptime_cutoff,)).rowcount
        c4 = conn.execute("DELETE FROM incidents WHERE status = 'resolved' AND resolved_at > 0 AND resolved_at < ?", (incidents_cutoff,)).rowcount
        c5 = conn.execute("DELETE FROM backup_runs WHERE status != 'running' AND started_at < ?", (backups_hist_cutoff,)).rowcount
        c6 = conn.execute("DELETE FROM threat_events WHERE ts < ?", (threats_cutoff,)).rowcount
    return {"purged_sessions": c1, "purged_audit_logs": c2, "purged_uptime": c3, "purged_incidents": c4, "purged_backup_runs": c5, "purged_threats": c6}
