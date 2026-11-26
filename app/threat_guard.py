"""Fase 4 — Guardia & Portero (Protección Activa de Servidor, Odoo, Nginx e Integridad del Host):
- Detección incremental de fuerza bruta SSH (/hostfs/var/log/auth.log).
- Detección incremental de fuerza bruta en login Odoo (logs de contenedores Docker).
- Detección de rutas trampa (Honeypots) y escáneres en Nginx (/hostfs/var/log/nginx/access.log).
- Sincronización reversible y fail-open con cadena dedicada 'SOS_GUARD' en iptables del host vía nsenter.
- Vigilancia de integridad SHA-256 de authorized_keys, crontabs, sshd_config, sudoers y passwd.
"""
from collections import defaultdict
import glob
import hashlib
import ipaddress
import json
import logging
import os
import re
import socket
import subprocess
import threading
import time
from typing import Any, Dict, List, Set, Tuple

import docker

import discovery
import notifications
import storage

_logger = logging.getLogger("sos_threat_guard")
_guard_lock = threading.Lock()

POLICY_KEY = "guard_policy_config"
CHAIN_NAME = "SOS_GUARD"

DEFAULT_GUARD_POLICY: Dict[str, Any] = {
    "mode": "monitor",  # 'monitor' (Observar) | 'enforce' (Bloquear en firewall)
    "ssh_max_failures": 8,
    "odoo_max_failures": 10,
    "window_minutes": 10,
    "honeypot_enabled": True,
    "honeypot_hits_threshold": 2,
    "block_duration_minutes": 60,
}

# Cursores incrementales en memoria para no releer archivos completos en cada ciclo
_file_cursors: Dict[str, Tuple[int, int]] = {}  # path -> (inode, offset)
_odoo_log_cursors: Dict[str, int] = {}  # container_name -> last_unix_ts
_sliding_hits: Dict[Tuple[str, str], List[float]] = defaultdict(list)  # (vector, ip) -> [timestamps]
_self_ips_cache: Tuple[float, Set[str]] = (0.0, set())

SSH_FAIL_PATTERNS = [
    re.compile(r"Failed password for (?:invalid user )?(\S+) from ([0-9a-fA-F:\.]+)"),
    re.compile(r"Invalid user (\S+) from ([0-9a-fA-F:\.]+)"),
    re.compile(r"Connection closed by authenticating user (\S+) ([0-9a-fA-F:\.]+) port \d+ \[preauth\]"),
]

ODOO_FAIL_RE = re.compile(r"Login failed for db:(\S+) login:(\S+) from ([0-9a-fA-F:\.]+)")

NGINX_LINE_RE = re.compile(
    r'^([0-9a-fA-F:\.]+)\s+\S+\s+\S+\s+\[[^\]]+\]\s+"(?:GET|POST|HEAD|PUT|PROPFIND)\s+([^\s\?"]+)[^"]*"\s+(\d{3})\s+\d+\s+"[^"]*"\s+"([^"]*)"'
)

HONEYPOT_PREFIXES = (
    "/.env",
    "/.git/",
    "/wp-login.php",
    "/wp-admin",
    "/xmlrpc.php",
    "/phpmyadmin",
    "/pma",
    "/vendor/phpunit",
    "/boaform/",
    "/actuator/env",
    "/cgi-bin/",
    "/eval-stdin.php",
)


def get_guard_policy() -> Dict[str, Any]:
    cfg = dict(DEFAULT_GUARD_POLICY)
    raw = storage.get_setting(POLICY_KEY, "")
    if raw:
        try:
            saved = json.loads(raw)
            if isinstance(saved, dict):
                cfg.update(saved)
        except Exception:
            pass
    if cfg.get("mode") not in ("monitor", "enforce"):
        cfg["mode"] = "monitor"
    return cfg


def save_guard_policy(incoming: Dict[str, Any]) -> Dict[str, Any]:
    cfg = get_guard_policy()
    if "mode" in incoming and incoming["mode"] in ("monitor", "enforce"):
        cfg["mode"] = incoming["mode"]
    for int_key, lo, hi in (
        ("ssh_max_failures", 3, 100),
        ("odoo_max_failures", 3, 100),
        ("window_minutes", 1, 120),
        ("honeypot_hits_threshold", 1, 50),
        ("block_duration_minutes", 5, 10080),
    ):
        if int_key in incoming:
            try:
                cfg[int_key] = max(lo, min(hi, int(incoming[int_key])))
            except (ValueError, TypeError):
                pass
    if "honeypot_enabled" in incoming:
        cfg["honeypot_enabled"] = bool(incoming["honeypot_enabled"])

    storage.set_setting(POLICY_KEY, json.dumps(cfg))
    return cfg


# --- Verificación de IPs exentas (Loopback, Privadas, Propio Servidor y Trusted IPs) ---

def _get_server_own_ips() -> Set[str]:
    global _self_ips_cache
    now = time.time()
    if now - _self_ips_cache[0] < 600 and _self_ips_cache[1]:
        return _self_ips_cache[1]
    ips: Set[str] = {"127.0.0.1", "::1"}
    for host in (discovery.DEFAULT_BASE_DOMAIN, f"cloud.{discovery.DEFAULT_BASE_DOMAIN}"):
        try:
            for info in socket.getaddrinfo(host, None):
                addr = info[4][0]
                if addr:
                    ips.add(addr)
        except Exception:
            continue
    _self_ips_cache = (now, ips)
    return ips


def is_ip_exempt(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return True  # Nunca procesar cadenas malformadas

    if ip_obj.is_loopback or ip_obj.is_private or ip_obj.is_link_local or ip_obj.is_multicast:
        return True

    if ip_str in _get_server_own_ips():
        return True

    for row in storage.list_trusted_ips():
        entry = row["ip"]
        try:
            if "/" in entry:
                if ip_obj in ipaddress.ip_network(entry, strict=False):
                    return True
            elif ip_obj == ipaddress.ip_address(entry):
                return True
        except ValueError:
            continue
    return False


# --- Sincronización de Firewall en Host (nsenter -> iptables SOS_GUARD) ---

def _run_host_iptables(args: List[str], ipv6: bool = False) -> Tuple[int, str]:
    bin_path = "/usr/sbin/ip6tables" if ipv6 else "/usr/sbin/iptables"
    cmd = ["nsenter", "-t", "1", "-m", "-n", "--", bin_path, "-w", "3"] + args
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=6, check=False)
        return res.returncode, ((res.stdout or "") + (res.stderr or "")).strip()
    except Exception as exc:
        return 1, str(exc)


def check_firewall_capability() -> Tuple[bool, str]:
    code, out = _run_host_iptables(["-S", "INPUT"])
    if code == 0:
        return True, "iptables del host accesible vía nsenter"
    return False, out[:180] or "Sin permiso NET_ADMIN/SYS_ADMIN para nsenter"


def _ensure_chain_for_proto(ipv6: bool) -> bool:
    code, _ = _run_host_iptables(["-L", CHAIN_NAME, "-n"], ipv6=ipv6)
    if code != 0:
        c_new, _ = _run_host_iptables(["-N", CHAIN_NAME], ipv6=ipv6)
        if c_new != 0:
            return False

    # Asegurar salto en INPUT posición 1
    c_chk, _ = _run_host_iptables(["-C", "INPUT", "-j", CHAIN_NAME], ipv6=ipv6)
    if c_chk != 0:
        _run_host_iptables(["-I", "INPUT", "1", "-j", CHAIN_NAME], ipv6=ipv6)

    # Si existe DOCKER-USER en IPv4, asegurar salto posición 1 para proteger puertos Docker expuestos
    if not ipv6:
        c_du, _ = _run_host_iptables(["-L", "DOCKER-USER", "-n"], ipv6=False)
        if c_du == 0:
            c_du_chk, _ = _run_host_iptables(["-C", "DOCKER-USER", "-j", CHAIN_NAME], ipv6=False)
            if c_du_chk != 0:
                _run_host_iptables(["-I", "DOCKER-USER", "1", "-j", CHAIN_NAME], ipv6=False)
    return True


def _get_current_chain_ips(ipv6: bool) -> Set[str]:
    code, out = _run_host_iptables(["-S", CHAIN_NAME], ipv6=ipv6)
    if code != 0:
        return set()
    ips: Set[str] = set()
    for line in out.splitlines():
        # Ej: -A SOS_GUARD -s 198.51.100.77/32 -j DROP
        m = re.search(r"-A\s+" + CHAIN_NAME + r"\s+-s\s+([^\s]+)\s+-j\s+DROP", line)
        if m:
            raw = m.group(1)
            if raw.endswith("/32") or raw.endswith("/128"):
                raw = raw.split("/")[0]
            ips.add(raw)
    return ips


def sync_firewall_rules() -> Dict[str, Any]:
    """Sincroniza la cadena SOS_GUARD en iptables del host según el modo actual y las IPs bloqueadas."""
    storage.expire_old_blocks()
    policy = get_guard_policy()
    can_fw, fw_msg = check_firewall_capability()
    if not can_fw:
        return {"ok": False, "enforced_count": 0, "detail": fw_msg}

    if policy["mode"] != "enforce":
        # En modo Observar ('monitor'), garantizar cadena limpia (fail-open inmediato)
        for v6 in (False, True):
            c, _ = _run_host_iptables(["-L", CHAIN_NAME, "-n"], ipv6=v6)
            if c == 0:
                _run_host_iptables(["-F", CHAIN_NAME], ipv6=v6)
        return {"ok": True, "enforced_count": 0, "detail": "Modo Observar activo (0 bloqueos en kernel)"}

    active_rows = storage.list_blocked_ips(only_active=True)
    desired_v4: Set[str] = set()
    desired_v6: Set[str] = set()

    for r in active_rows:
        ip_s = r["ip"].strip()
        if is_ip_exempt(ip_s):
            storage.deactivate_blocked_ip(ip_s)
            continue
        try:
            ip_obj = ipaddress.ip_address(ip_s)
            if ip_obj.version == 6:
                desired_v6.add(str(ip_obj))
            else:
                desired_v4.add(str(ip_obj))
        except ValueError:
            continue

    for is_v6, desired in ((False, desired_v4), (True, desired_v6)):
        if not _ensure_chain_for_proto(ipv6=is_v6):
            continue
        current = _get_current_chain_ips(ipv6=is_v6)
        for to_remove in (current - desired):
            _run_host_iptables(["-D", CHAIN_NAME, "-s", to_remove, "-j", "DROP"], ipv6=is_v6)
        for to_add in (desired - current):
            _run_host_iptables(["-A", CHAIN_NAME, "-s", to_add, "-j", "DROP"], ipv6=is_v6)

    total_enforced = len(desired_v4) + len(desired_v6)
    return {"ok": True, "enforced_count": total_enforced, "detail": f"{total_enforced} IPs aplicadas en {CHAIN_NAME}"}


def unblock_all_emergency() -> Dict[str, Any]:
    count = storage.deactivate_all_blocked_ips()
    for v6 in (False, True):
        c, _ = _run_host_iptables(["-L", CHAIN_NAME, "-n"], ipv6=v6)
        if c == 0:
            _run_host_iptables(["-F", CHAIN_NAME], ipv6=v6)
    return {"ok": True, "unblocked_count": count}


# --- Lectura incremental de logs y disparo de detecciones ---

def _read_new_lines(filepath: str, initial_tail_bytes: int = 0) -> List[str]:
    if not os.path.isfile(filepath):
        return []
    try:
        st = os.stat(filepath)
        inode, size = st.st_ino, st.st_size
        if filepath not in _file_cursors:
            # Primera vez: posicionarse al final (o leer últimos bytes recientes) para no procesar histórico viejo
            start_pos = max(0, size - initial_tail_bytes) if initial_tail_bytes > 0 else size
            _file_cursors[filepath] = (inode, start_pos)
            if start_pos == size:
                return []

        prev_inode, prev_offset = _file_cursors[filepath]
        if inode != prev_inode or size < prev_offset:
            # Archivo rotado por logrotate
            prev_offset = 0

        if size == prev_offset:
            return []

        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            f.seek(prev_offset)
            data = f.read(524288)  # Máx 512 KB por ciclo
            new_offset = f.tell()

        _file_cursors[filepath] = (inode, new_offset)
        return data.splitlines()
    except Exception:
        return []


def _record_hit_and_evaluate(
    vector: str,
    ip: str,
    threshold: int,
    window_sec: int,
    block_minutes: int,
    mode: str,
    target: str,
    reason_label: str,
    sample_detail: str,
) -> bool:
    if is_ip_exempt(ip):
        return False

    now = time.time()
    key = (vector, ip)
    arr = [t for t in _sliding_hits[key] if (now - t) <= window_sec]
    arr.append(now)
    _sliding_hits[key] = arr

    if len(arr) < threshold:
        return False

    # Se alcanzó el umbral -> reiniciar ventana para esa IP y registrar amenaza
    hits_count = len(arr)
    _sliding_hits[key] = []

    action_taken = "blocked" if mode == "enforce" else "observed"
    storage.upsert_blocked_ip(
        ip=ip,
        reason=f"{reason_label} ({hits_count} eventos)",
        source=vector,
        duration_seconds=block_minutes * 60,
        hits=hits_count,
    )
    storage.insert_threat_event(
        ip=ip,
        vector=vector,
        severity="critical" if mode == "enforce" else "warning",
        target=target,
        action_taken=action_taken,
        detail=f"{reason_label}: {sample_detail}",
    )
    return True


def _scan_ssh_logs(policy: Dict[str, Any]) -> int:
    auth_path = "/hostfs/var/log/auth.log"
    lines = _read_new_lines(auth_path, initial_tail_bytes=0)
    triggered = 0
    win_sec = int(policy["window_minutes"]) * 60
    for ln in lines:
        if "sshd" not in ln:
            continue
        for pat in SSH_FAIL_PATTERNS:
            m = pat.search(ln)
            if m:
                user_tried, ip = m.group(1), m.group(2)
                if _record_hit_and_evaluate(
                    vector="ssh_bruteforce",
                    ip=ip,
                    threshold=int(policy["ssh_max_failures"]),
                    window_sec=win_sec,
                    block_minutes=int(policy["block_duration_minutes"]),
                    mode=policy["mode"],
                    target=f"ssh (user: {user_tried})",
                    reason_label="Fuerza bruta SSH",
                    sample_detail=f"Usuario '{user_tried}'",
                ):
                    triggered += 1
                break
    return triggered


def _scan_odoo_login_logs(policy: Dict[str, Any]) -> int:
    triggered = 0
    now_ts = int(time.time())
    win_sec = int(policy["window_minutes"]) * 60
    try:
        client = docker.from_env()
        for c in client.containers.list(filters={"status": "running"}):
            img = (c.image.tags[0] if c.image.tags else str(c.attrs.get("Config", {}).get("Image", ""))).lower()
            if "odoo" not in img and "odoo" not in c.name.lower():
                continue
            if c.name == os.environ.get("PANEL_CONTAINER_NAME", "sos_cloud_panel"):
                continue

            if c.name not in _odoo_log_cursors:
                _odoo_log_cursors[c.name] = now_ts
                continue

            since_ts = _odoo_log_cursors[c.name]
            _odoo_log_cursors[c.name] = now_ts
            raw = c.logs(since=since_ts, stdout=True, stderr=True).decode("utf-8", errors="replace")
            for ln in raw.splitlines():
                if "Login failed for db:" not in ln:
                    continue
                m = ODOO_FAIL_RE.search(ln)
                if m:
                    db_tried, login_tried, ip = m.group(1), m.group(2), m.group(3)
                    if _record_hit_and_evaluate(
                        vector="odoo_login",
                        ip=ip,
                        threshold=int(policy["odoo_max_failures"]),
                        window_sec=win_sec,
                        block_minutes=int(policy["block_duration_minutes"]),
                        mode=policy["mode"],
                        target=f"Odoo BD:{db_tried}",
                        reason_label=f"Fuerza bruta Login Odoo ({db_tried})",
                        sample_detail=f"login '{login_tried}' en {c.name}",
                    ):
                        triggered += 1
    except Exception as exc:
        _logger.debug("Aviso leyendo logs Odoo: %s", exc)
    return triggered


def _scan_nginx_honeypots(policy: Dict[str, Any]) -> int:
    if not policy.get("honeypot_enabled", True):
        return 0
    access_path = "/hostfs/var/log/nginx/access.log"
    lines = _read_new_lines(access_path, initial_tail_bytes=0)
    triggered = 0
    win_sec = int(policy["window_minutes"]) * 60

    for ln in lines:
        if "SOS-Cloud-" in ln:
            continue
        m = NGINX_LINE_RE.match(ln)
        if not m:
            continue
        ip, path, status_code, ua = m.group(1), m.group(2), m.group(3), m.group(4)
        low_path = path.lower()
        matched_hp = next((hp for hp in HONEYPOT_PREFIXES if low_path.startswith(hp)), None)
        if matched_hp:
            if _record_hit_and_evaluate(
                vector="web_honeypot",
                ip=ip,
                threshold=int(policy.get("honeypot_hits_threshold", 2)),
                window_sec=win_sec,
                block_minutes=int(policy["block_duration_minutes"]),
                mode=policy["mode"],
                target=path[:120],
                reason_label=f"Trampa Honeypot Web ({matched_hp})",
                sample_detail=f"HTTP {status_code} • UA: {ua[:70]}",
            ):
                triggered += 1
    return triggered


def run_threat_guard_cycle() -> Dict[str, Any]:
    """Ciclo principal ejecutado cada 30 segundos por APScheduler."""
    with _guard_lock:
        policy = get_guard_policy()
        c_ssh = _scan_ssh_logs(policy)
        c_odoo = _scan_odoo_login_logs(policy)
        c_web = _scan_nginx_honeypots(policy)
        fw_res = sync_firewall_rules()
        return {
            "ssh_triggers": c_ssh,
            "odoo_triggers": c_odoo,
            "web_triggers": c_web,
            "firewall": fw_res,
        }


# --- Vigilancia de Integridad del Host (SSH Keys, Crontabs, Sudoers, Passwd) ---

CRITICAL_HOST_PATTERNS = [
    "/hostfs/root/.ssh/authorized_keys",
    "/hostfs/home/*/.ssh/authorized_keys",
    "/hostfs/etc/crontab",
    "/hostfs/etc/cron.d/*",
    "/hostfs/var/spool/cron/crontabs/*",
    "/hostfs/etc/ssh/sshd_config",
    "/hostfs/etc/sudoers",
    "/hostfs/etc/passwd",
]


def _hash_small_file(path: str) -> Tuple[str, int, int]:
    st = os.stat(path)
    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read(2 * 1024 * 1024))
    return h.hexdigest(), int(st.st_mtime), int(st.st_size)


def run_host_integrity_check(approve_all_as_baseline: bool = False) -> Dict[str, Any]:
    existing = storage.get_integrity_baselines()
    is_initial_seed = len(existing) == 0 or approve_all_as_baseline

    discovered_files: Dict[str, Tuple[str, int, int]] = {}
    for pattern in CRITICAL_HOST_PATTERNS:
        for full_p in glob.glob(pattern):
            if not os.path.isfile(full_p) or os.path.islink(full_p):
                continue
            base_name = os.path.basename(full_p)
            if base_name.startswith(".placeholder") or base_name.endswith(".bak"):
                continue
            logical_path = full_p[len("/hostfs"):] if full_p.startswith("/hostfs") else full_p
            try:
                discovered_files[logical_path] = _hash_small_file(full_p)
            except Exception:
                continue

    alerts_count = 0
    for lpath, (sha, mtime, sz) in sorted(discovered_files.items()):
        if is_initial_seed:
            storage.upsert_integrity_record(lpath, sha, mtime, sz, status="ok", current_sha256=sha, detail="Línea base aprobada", approve_baseline=True)
            continue

        prev = existing.get(lpath)
        if not prev:
            alerts_count += 1
            detail = f"Nuevo archivo crítico detectado ({sz} bytes)"
            storage.upsert_integrity_record(lpath, sha, mtime, sz, status="added", current_sha256=sha, detail=detail)
            # Evitar duplicar evento si ya estaba reportado como added con el mismo hash
            notifications.report_incident(
                incident_key=f"integrity:{lpath}",
                kind="host_integrity",
                severity="critical",
                target=lpath,
                title=f"Nuevo archivo crítico en servidor: {lpath}",
                detail=detail,
            )
        elif prev["sha256"] != sha:
            alerts_count += 1
            detail = f"Hash SHA-256 cambió ({prev['sha256'][:10]}… → {sha[:10]}…)"
            storage.upsert_integrity_record(prev["filepath"], prev["sha256"], mtime, sz, status="modified", current_sha256=sha, detail=detail)
            if prev.get("current_sha256") != sha or prev.get("status") == "ok":
                storage.insert_threat_event(
                    ip="host",
                    vector="host_integrity",
                    severity="critical",
                    target=lpath,
                    action_taken="alerted",
                    detail=detail,
                )
            notifications.report_incident(
                incident_key=f"integrity:{lpath}",
                kind="host_integrity",
                severity="critical",
                target=lpath,
                title=f"Archivo crítico modificado: {lpath}",
                detail=detail,
            )
        else:
            storage.upsert_integrity_record(lpath, sha, mtime, sz, status="ok", current_sha256=sha, detail="Íntegro")
            notifications.resolve_incident_if_open(
                f"integrity:{lpath}",
                f"Integridad restablecida: {lpath}",
                "El archivo coincide nuevamente con la línea base aprobada.",
            )

    # Detectar archivos eliminados que estaban en la línea base
    if not is_initial_seed:
        for lpath, prev in existing.items():
            if lpath not in discovered_files:
                alerts_count += 1
                storage.upsert_integrity_record(
                    lpath, prev["sha256"], prev["mtime"], 0, status="deleted", current_sha256="", detail="Archivo eliminado del servidor"
                )

    all_records = list(storage.get_integrity_baselines().values())
    ok_files = sum(1 for r in all_records if r["status"] == "ok")
    return {
        "total_files": len(all_records),
        "ok_files": ok_files,
        "changed_files": len(all_records) - ok_files,
        "records": all_records,
    }


def approve_single_integrity_file(logical_path: str) -> bool:
    host_path = "/hostfs/" + logical_path.lstrip("/")
    if not os.path.isfile(host_path):
        # Si fue eliminado y el admin lo aprueba, retirarlo de la línea base
        storage.remove_integrity_record(logical_path)
        notifications.resolve_incident_if_open(f"integrity:{logical_path}", f"Eliminación aprobada: {logical_path}", "Aprobado por administrador")
        return True

    sha, mtime, sz = _hash_small_file(host_path)
    storage.upsert_integrity_record(logical_path, sha, mtime, sz, status="ok", current_sha256=sha, detail="Aprobado manualmente", approve_baseline=True)
    notifications.resolve_incident_if_open(f"integrity:{logical_path}", f"Cambio aprobado en línea base: {logical_path}", f"Nuevo hash {sha[:12]}…")
    return True
