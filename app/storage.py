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


# --- Housekeeping ---

def purge_expired_data(session_max_age: int = 86400 * 7, audit_retention_days: int = 180) -> Dict[str, int]:
    now = int(time.time())
    sess_cutoff = now - session_max_age
    audit_cutoff = now - (max(7, audit_retention_days) * 86400)
    with get_conn() as conn:
        c1 = conn.execute("DELETE FROM sessions WHERE created_at < ? OR (revoked = 1 AND last_seen < ?)", (sess_cutoff, now - 86400)).rowcount
        c2 = conn.execute("DELETE FROM audit_logs WHERE ts < ?", (audit_cutoff,)).rowcount
    return {"purged_sessions": c1, "purged_audit_logs": c2}
