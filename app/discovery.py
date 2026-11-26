from concurrent.futures import ThreadPoolExecutor
import glob
import os
import re
from typing import Any, Dict, List

import docker
import psycopg2
from psycopg2.extras import RealDictCursor

PG_HOST = os.environ.get("PG_HOST", "host.docker.internal")
PG_PORT = int(os.environ.get("PG_PORT", "5433"))
PG_USER = os.environ.get("PG_USER", "odoo")
PG_PASSWORD = os.environ.get("PG_PASSWORD", "odoo")
DEFAULT_BASE_DOMAIN = os.environ.get("DEFAULT_BASE_DOMAIN", "solucionesos.com")
NGINX_SITES_PATH = os.environ.get("NGINX_SITES_PATH", "/host_nginx/sites-enabled")


def _get_pg_conn(dbname: str = "postgres"):
    return psycopg2.connect(
        host=PG_HOST,
        port=PG_PORT,
        user=PG_USER,
        password=PG_PASSWORD,
        dbname=dbname,
        connect_timeout=4,
    )


def parse_nginx_domain_mapping() -> Dict[str, Any]:
    port_to_domains: Dict[int, List[str]] = {}
    db_to_domain: Dict[str, str] = {}
    if not os.path.isdir(NGINX_SITES_PATH):
        return {"port_to_domains": port_to_domains, "db_to_domain": db_to_domain}

    for filepath in glob.glob(os.path.join(NGINX_SITES_PATH, "*")):
        if os.path.isdir(filepath):
            continue
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            server_blocks = re.findall(r"server\s*\{(.*?)(?=\nserver\s*\{|\Z)", content, re.DOTALL) or [content]
            for block in server_blocks:
                server_names = re.findall(r"server_name\s+([^;]+);", block)
                domains = []
                for sn in server_names:
                    for d in sn.split():
                        d = d.strip()
                        if d and d != "_" and not d.startswith("#"):
                            domains.append(d)
                ports = re.findall(r"proxy_pass\s+https?://[^:;]+:(\d+)", block)
                for p_str in ports:
                    port = int(p_str)
                    port_to_domains.setdefault(port, [])
                    for d in domains:
                        if d not in port_to_domains[port]:
                            port_to_domains[port].append(d)
                for d in domains:
                    sub = d.split(".")[0].lower()
                    if sub and sub not in ("www", "cloud", "panel"):
                        db_to_domain[sub] = f"https://{d}"
        except Exception:
            continue
    return {"port_to_domains": port_to_domains, "db_to_domain": db_to_domain}


def discover_odoo_containers(port_to_domains: Dict[int, List[str]]) -> List[Dict[str, Any]]:
    containers_info = []
    try:
        client = docker.from_env()
        for c in client.containers.list(all=True):
            image_tags = c.image.tags if c.image.tags else [c.attrs.get("Config", {}).get("Image", "")]
            image_name = image_tags[0] if image_tags else ""
            name_lower = c.name.lower()
            ports_map = c.attrs.get("NetworkSettings", {}).get("Ports") or {}
            host_ports = []
            for _, bindings in ports_map.items():
                if bindings:
                    for b in bindings:
                        hp = b.get("HostPort")
                        if hp and hp.isdigit():
                            host_ports.append(int(hp))
            matched_domains = []
            for hp in host_ports:
                for dom in port_to_domains.get(hp, []):
                    if dom not in matched_domains:
                        matched_domains.append(dom)
            containers_info.append({
                "id": c.short_id,
                "name": c.name,
                "image": image_name,
                "status": c.status,
                "is_running": c.status == "running",
                "is_odoo": "odoo" in image_name.lower() or "odoo" in name_lower,
                "host_ports": sorted(list(set(host_ports))),
                "domains": matched_domains,
            })
    except Exception as e:
        containers_info.append({
            "id": "error",
            "name": "Error conectando a Docker Socket",
            "image": str(e),
            "status": "error",
            "is_running": False,
            "is_odoo": False,
            "host_ports": [],
            "domains": [],
        })
    return sorted(containers_info, key=lambda x: (not x["is_odoo"], x["name"]))

def _read_single_container_stats(container) -> Dict[str, Any]:
    try:
        st = container.stats(stream=False)
        cpu_stats = st.get("cpu_stats") or {}
        precpu_stats = st.get("precpu_stats") or {}
        cpu_delta = (cpu_stats.get("cpu_usage") or {}).get("total_usage", 0) - (
            (precpu_stats.get("cpu_usage") or {}).get("total_usage", 0)
        )
        sys_delta = cpu_stats.get("system_cpu_usage", 0) - precpu_stats.get("system_cpu_usage", 0)
        online_cpus = (
            cpu_stats.get("online_cpus")
            or len((cpu_stats.get("cpu_usage") or {}).get("percpu_usage") or [])
            or 1
        )
        cpu_pct = round((cpu_delta / sys_delta) * online_cpus * 100.0, 2) if (sys_delta > 0 and cpu_delta > 0) else 0.0

        mem_stats = st.get("memory_stats") or {}
        mem_usage = mem_stats.get("usage", 0)
        mem_sub = mem_stats.get("stats") or {}
        mem_cache = mem_sub.get("inactive_file") or mem_sub.get("cache") or 0
        mem_used = max(0, mem_usage - mem_cache)
        mem_limit = mem_stats.get("limit", 0)
        mem_used_mb = round(mem_used / (1024 ** 2), 1)
        mem_limit_mb = round(mem_limit / (1024 ** 2), 0)
        mem_pct = round((mem_used / mem_limit) * 100.0, 1) if mem_limit > 0 else 0.0

        blkio = (st.get("blkio_stats") or {}).get("io_service_bytes_recursive") or []
        io_read = sum(x.get("value", 0) for x in blkio if str(x.get("op", "")).lower() == "read")
        io_write = sum(x.get("value", 0) for x in blkio if str(x.get("op", "")).lower() == "write")

        return {
            "cpu_percent": cpu_pct,
            "mem_used_mb": mem_used_mb,
            "mem_limit_mb": mem_limit_mb,
            "mem_percent": mem_pct,
            "io_read_mb": round(io_read / (1024 ** 2), 1),
            "io_write_mb": round(io_write / (1024 ** 2), 1),
        }
    except Exception:
        return {"cpu_percent": 0.0, "mem_used_mb": 0.0, "mem_limit_mb": 0.0, "mem_percent": 0.0, "io_read_mb": 0.0, "io_write_mb": 0.0}


def get_containers_stats() -> Dict[str, Dict[str, Any]]:
    result: Dict[str, Dict[str, Any]] = {}
    try:
        client = docker.from_env()
        running = client.containers.list(filters={"status": "running"})
        if not running:
            return result
        with ThreadPoolExecutor(max_workers=min(12, len(running))) as pool:
            futures = {pool.submit(_read_single_container_stats, c): c.name for c in running}
            for fut, cname in futures.items():
                result[cname] = fut.result()
    except Exception:
        pass
    return result



def discover_odoo_databases(db_to_domain: Dict[str, str]) -> List[Dict[str, Any]]:
    databases = []
    try:
        conn = _get_pg_conn("postgres")
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT d.datname AS name,
                       pg_size_pretty(pg_database_size(d.datname)) AS size_pretty,
                       pg_database_size(d.datname) AS size_bytes
                FROM pg_database d
                WHERE d.datistemplate = false AND d.datname NOT IN ('postgres')
                ORDER BY d.datname;
            """)
            rows = cur.fetchall()
        conn.close()
    except Exception as e:
        return [{
            "name": "Error conectando a PostgreSQL",
            "company_name": str(e),
            "version": "Error",
            "size_pretty": "0 MB",
            "base_url": "#",
            "active_users_count": 0,
            "users": [],
            "admin_uid": 2,
        }]

    for row in rows:
        dbname = row["name"]
        db_info = {
            "name": dbname,
            "size_pretty": row["size_pretty"],
            "size_bytes": row["size_bytes"],
            "version": "Odoo",
            "base_url": db_to_domain.get(dbname.lower(), f"https://{dbname}.{DEFAULT_BASE_DOMAIN}"),
            "active_users_count": 0,
            "users": [],
            "admin_uid": 2,
            "company_name": dbname,
        }
        try:
            db_conn = _get_pg_conn(dbname)
            with db_conn.cursor(cursor_factory=RealDictCursor) as db_cur:
                db_cur.execute("""
                    SELECT EXISTS (
                        SELECT 1 FROM information_schema.tables
                        WHERE table_schema = 'public' AND table_name = 'ir_config_parameter'
                    ) AS is_odoo;
                """)
                check = db_cur.fetchone()
                if not check or not check["is_odoo"]:
                    db_conn.close()
                    continue

                db_cur.execute("SELECT value FROM ir_config_parameter WHERE key = 'web.base.url' LIMIT 1;")
                url_row = db_cur.fetchone()
                if url_row and url_row["value"]:
                    val = url_row["value"].strip().rstrip("/")
                    if "localhost" not in val and "127.0.0.1" not in val and ":8069" not in val:
                        if val.startswith("http://") and DEFAULT_BASE_DOMAIN in val:
                            val = "https://" + val[len("http://"):]
                        db_info["base_url"] = val

                if dbname.lower() in db_to_domain:
                    db_info["base_url"] = db_to_domain[dbname.lower()]

                db_cur.execute("SELECT latest_version FROM ir_module_module WHERE name = 'base' LIMIT 1;")
                ver_row = db_cur.fetchone()
                if ver_row and ver_row["latest_version"]:
                    major = ".".join(ver_row["latest_version"].split(".")[:2])
                    db_info["version"] = f"Odoo {major}"

                db_cur.execute("SELECT name FROM res_company ORDER BY id ASC LIMIT 1;")
                comp_row = db_cur.fetchone()
                if comp_row and comp_row["name"]:
                    db_info["company_name"] = comp_row["name"]

                db_cur.execute("""
                    SELECT u.id, u.login, COALESCE(p.name, u.login) AS name
                    FROM res_users u
                    LEFT JOIN res_partner p ON u.partner_id = p.id
                    WHERE u.active = true AND (u.share = false OR u.share IS NULL)
                    ORDER BY CASE WHEN u.id = 2 THEN 0 ELSE 1 END, u.id ASC
                    LIMIT 25;
                """)
                users = db_cur.fetchall()
                db_info["users"] = users
                db_info["active_users_count"] = len(users)
                if users:
                    db_info["admin_uid"] = users[0]["id"]
            db_conn.close()
            databases.append(db_info)
        except Exception:
            continue
    return databases
