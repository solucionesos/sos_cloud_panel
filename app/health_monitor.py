"""Monitoreo activo de Uptime HTTP/HTTPS (1 min), certificados SSL/TLS (6 h) y umbrales de disco del servidor."""
from concurrent.futures import ThreadPoolExecutor
import logging
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Tuple

import discovery
import monitoring
import notifications
import storage

_logger = logging.getLogger("sos_health")


def _clean_domain(raw: str) -> str:
    d = (raw or "").strip().lower()
    if "://" in d:
        d = urllib.parse.urlparse(d).hostname or ""
    d = d.split(":")[0].strip(".")
    if not d or d in ("localhost", "127.0.0.1", "_") or d.startswith("*.") or "." not in d:
        return ""
    return d


def discover_monitored_targets() -> List[Dict[str, Any]]:
    """Retorna la lista desduplicada de dominios reales activos en el servidor (Nginx + BDs Odoo)."""
    nginx_map = discovery.parse_nginx_domain_mapping()
    containers = discovery.discover_odoo_containers(nginx_map["port_to_domains"])
    databases = discovery.discover_odoo_databases(nginx_map["db_to_domain"])

    targets: Dict[str, Dict[str, Any]] = {}

    # 1. Dominios configurados explícitamente en Nginx (fuente primaria real)
    for port, doms in (nginx_map.get("port_to_domains") or {}).items():
        matched_c = next((c for c in containers if port in (c.get("host_ports") or [])), None)
        is_odoo = bool(matched_c and matched_c.get("is_odoo"))
        cname = matched_c["name"] if matched_c else ""
        for raw_d in doms:
            dom = _clean_domain(raw_d)
            if not dom:
                continue
            targets.setdefault(dom, {
                "domain": dom,
                "url": f"https://{dom}",
                "container_name": cname,
                "db_name": "",
                "company_name": "",
                "is_odoo": is_odoo,
            })

    # 2. Enriquecer con metadatos de bases de datos Odoo descubiertas
    for db in databases:
        if str(db.get("name", "")).startswith("Error"):
            continue
        dom = _clean_domain(db.get("base_url") or "")
        if not dom:
            continue
        if dom in targets:
            targets[dom]["is_odoo"] = True
            if not targets[dom]["db_name"]:
                targets[dom]["db_name"] = db["name"]
                targets[dom]["company_name"] = db.get("company_name") or db["name"]

    return sorted(targets.values(), key=lambda x: (not x["is_odoo"], x["domain"]))


def _probe_single_target(target: Dict[str, Any]) -> Dict[str, Any]:
    dom = target["domain"]
    probe_path = "/web/login" if target.get("is_odoo") else "/"
    url = f"https://{dom}{probe_path}"
    t0 = time.perf_counter()
    now_ts = int(time.time())

    ctx = ssl.create_default_context()
    # En uptime medimos disponibilidad HTTP del servicio; la validez estricta del SSL la audita run_ssl_checks
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(
        url,
        headers={"User-Agent": "SOS-Cloud-HealthMonitor/2.0"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=7, context=ctx) as resp:
            code = resp.status
            # Leer primeros bytes para confirmar respuesta real
            resp.read(256)
            ms = int((time.perf_counter() - t0) * 1000)
            is_up = 1 if code < 500 else 0
            return {
                "ts": now_ts,
                "domain": dom,
                "url": url,
                "is_up": is_up,
                "status_code": code,
                "latency_ms": ms,
                "error": "" if is_up else f"HTTP {code}",
            }
    except urllib.error.HTTPError as he:
        ms = int((time.perf_counter() - t0) * 1000)
        # Códigos 401/403/404 indican que el servidor web y upstream están vivos; >= 500 (502/503/504) es caída
        is_up = 1 if he.code < 500 else 0
        return {
            "ts": now_ts,
            "domain": dom,
            "url": url,
            "is_up": is_up,
            "status_code": he.code,
            "latency_ms": ms,
            "error": "" if is_up else f"HTTP {he.code} ({he.reason})",
        }
    except Exception as exc:
        ms = int((time.perf_counter() - t0) * 1000)
        return {
            "ts": now_ts,
            "domain": dom,
            "url": url,
            "is_up": 0,
            "status_code": 0,
            "latency_ms": ms,
            "error": str(exc)[:220],
        }


def run_uptime_checks() -> List[Dict[str, Any]]:
    targets = discover_monitored_targets()
    if not targets:
        return []

    with ThreadPoolExecutor(max_workers=min(12, len(targets))) as pool:
        results = list(pool.map(_probe_single_target, targets))

    storage.insert_uptime_batch(results)

    for res in results:
        dom = res["domain"]
        inc_key = f"uptime:{dom}"
        if res["is_up"] == 0:
            # Exigir 2 fallos seguidos para abrir incidente (evita falsos positivos durante un restart)
            fails = storage.get_domain_recent_failures(dom, limit=2)
            if fails >= 2:
                notifications.report_incident(
                    incident_key=inc_key,
                    kind="uptime_down",
                    severity="critical",
                    target=dom,
                    title=f"Servicio fuera de línea: {dom}",
                    detail=f"Fallo en {res['url']} — {res['error'] or ('HTTP ' + str(res['status_code']))}",
                )
        else:
            notifications.resolve_incident_if_open(
                incident_key=inc_key,
                resolution_title=f"Servicio restablecido: {dom}",
                resolution_detail=f"Respondiendo HTTP {res['status_code']} en {res['latency_ms']} ms",
            )

    return results


def _inspect_single_ssl(domain: str) -> Tuple[str, bool, int, str, str, str, str]:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                tls_ver = ssock.version() or ""
                not_after_str = cert.get("notAfter", "")
                exp_epoch = ssl.cert_time_to_seconds(not_after_str) if not_after_str else 0
                days_left = int((exp_epoch - time.time()) // 86400) if exp_epoch else -1

                issuer_parts = []
                for rdn in cert.get("issuer", ()):
                    for k, v in rdn:
                        if k in ("organizationName", "commonName") and v not in issuer_parts:
                            issuer_parts.append(v)
                issuer_str = " / ".join(issuer_parts) or "CA Desconocida"
                valid = days_left >= 0
                return domain, valid, days_left, not_after_str, issuer_str, tls_ver, ""
    except Exception as exc:
        return domain, False, -1, "", "", "", str(exc)[:240]


def run_ssl_checks() -> List[Dict[str, Any]]:
    targets = discover_monitored_targets()
    if not targets:
        return []
    domains = [t["domain"] for t in targets]
    out = []

    with ThreadPoolExecutor(max_workers=min(10, len(domains))) as pool:
        rows = list(pool.map(_inspect_single_ssl, domains))

    for dom, valid, days_left, not_after, issuer, tls_ver, err in rows:
        storage.upsert_ssl_status(
            domain=dom,
            valid=valid,
            days_left=days_left,
            not_after=not_after,
            issuer=issuer,
            tls_version=tls_ver,
            error=err,
        )
        inc_key = f"ssl:{dom}"
        if not valid:
            notifications.report_incident(
                incident_key=inc_key,
                kind="ssl_invalid",
                severity="critical",
                target=dom,
                title=f"Certificado SSL inválido o inaccesible en {dom}",
                detail=err or "El certificado TLS expiró o falló la validación.",
            )
        elif days_left <= 14:
            sev = "critical" if days_left <= 5 else "warning"
            notifications.report_incident(
                incident_key=inc_key,
                kind="ssl_expiring",
                severity=sev,
                target=dom,
                title=f"Certificado SSL por vencer en {dom} ({days_left} días)",
                detail=f"Expira: {not_after} • Emisor: {issuer}",
            )
        else:
            notifications.resolve_incident_if_open(
                incident_key=inc_key,
                resolution_title=f"Certificado SSL renovado en {dom}",
                resolution_detail=f"Vigencia actual: {days_left} días ({tls_ver})",
            )

        out.append({
            "domain": dom,
            "valid": valid,
            "days_left": days_left,
            "not_after": not_after,
            "issuer": issuer,
            "tls_version": tls_ver,
            "error": err,
        })
    return out


def run_host_threshold_checks() -> None:
    cfg = notifications.get_notify_config(mask_secrets=False)
    disk_limit = int(cfg.get("disk_alert_threshold") or 85)
    mounts = monitoring._get_storage_mounts()

    for m in mounts:
        mp = m.get("mountpoint") or "/"
        pct = float(m.get("percent") or 0.0)
        inc_key = f"disk:{mp}"
        if pct >= disk_limit:
            sev = "critical" if pct >= 92.0 else "warning"
            notifications.report_incident(
                incident_key=inc_key,
                kind="disk_space",
                severity=sev,
                target=mp,
                title=f"Espacio en disco crítico en {mp} ({pct}%)",
                detail=f"Usado: {m['used_gb']} GB de {m['total_gb']} GB (Libre: {m['free_gb']} GB)",
            )
        elif pct <= (disk_limit - 3):
            notifications.resolve_incident_if_open(
                incident_key=inc_key,
                resolution_title=f"Espacio en disco normalizado en {mp}",
                resolution_detail=f"Uso actual: {pct}% (Libre: {m['free_gb']} GB)",
            )
