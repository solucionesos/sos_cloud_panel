from concurrent.futures import ThreadPoolExecutor
import glob
import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

import docker
import psycopg2
from psycopg2.extras import RealDictCursor

PG_HOST = os.environ.get("PG_HOST", "host.docker.internal")
PG_PORT = int(os.environ.get("PG_PORT", "5433"))
PG_USER = os.environ.get("PG_USER", "odoo")
PG_PASSWORD = os.environ.get("PG_PASSWORD", "odoo")
PG_DISCOVERY_MODE = os.environ.get("PG_DISCOVERY_MODE", "auto").strip().lower()
DEFAULT_BASE_DOMAIN = os.environ.get("DEFAULT_BASE_DOMAIN", "solucionesos.com")
NGINX_SITES_PATH = os.environ.get("NGINX_SITES_PATH", "/host_nginx/sites-enabled")


def _get_pg_conn(
    dbname: str = "postgres",
    host: Optional[str] = None,
    port: Optional[int] = None,
    user: Optional[str] = None,
    password: Optional[str] = None,
):
    return psycopg2.connect(
        host=host or PG_HOST,
        port=port or PG_PORT,
        user=user or PG_USER,
        password=password if password is not None else PG_PASSWORD,
        dbname=dbname,
        connect_timeout=3,
    )


def _parse_container_env(container) -> Dict[str, str]:
    env_dict: Dict[str, str] = {}
    for item in (container.attrs.get("Config", {}).get("Env") or []):
        if "=" in item:
            k, v = item.split("=", 1)
            env_dict[k] = v
    return env_dict


def _get_self_networks(client: docker.DockerClient) -> set:
    hostname = os.environ.get("HOSTNAME", "")
    if not hostname:
        return set()
    try:
        me = client.containers.get(hostname)
        return set((me.attrs.get("NetworkSettings", {}).get("Networks") or {}).keys())
    except Exception:
        return set()


def discover_postgres_instances() -> List[Dict[str, Any]]:
    """Descubre instancias PostgreSQL activas en Docker (o usa PG_HOST único si aplica)."""
    default_instance = {
        "container_name": "",
        "compose_project": "",
        "host": PG_HOST,
        "port": PG_PORT,
        "user": PG_USER,
        "password": PG_PASSWORD,
        "can_tcp": True,
        "networks": set(),
    }

    if PG_DISCOVERY_MODE == "single":
        return [default_instance]

    instances: List[Dict[str, Any]] = []
    try:
        client = docker.from_env()
        self_nets = _get_self_networks(client)

        for c in client.containers.list(filters={"status": "running"}):
            image_tags = c.image.tags if c.image.tags else [c.attrs.get("Config", {}).get("Image", "")]
            image_str = (image_tags[0] if image_tags else "").lower()
            name_lower = c.name.lower()

            if ("postgres" not in image_str and "postgres" not in name_lower) or "pgadmin" in image_str or "pgadmin" in name_lower:
                continue

            env = _parse_container_env(c)
            pg_user = env.get("POSTGRES_USER") or PG_USER
            pg_password = env.get("POSTGRES_PASSWORD") if "POSTGRES_PASSWORD" in env else PG_PASSWORD
            labels = c.attrs.get("Config", {}).get("Labels") or {}
            compose_project = labels.get("com.docker.compose.project", "")

            nets_dict = c.attrs.get("NetworkSettings", {}).get("Networks") or {}
            c_nets = set(nets_dict.keys())

            # Determinar mejor host/puerto TCP si es alcanzable directamente
            ports_map = c.attrs.get("NetworkSettings", {}).get("Ports") or {}
            host_port = None
            for container_port, bindings in ports_map.items():
                if container_port.startswith("5432/") and bindings:
                    hp = bindings[0].get("HostPort")
                    if hp and hp.isdigit():
                        host_port = int(hp)
                        break

            shared_nets = self_nets & c_nets
            if c.name == PG_HOST:
                tcp_host, tcp_port, can_tcp = PG_HOST, PG_PORT, True
            elif shared_nets:
                first_net = next(iter(shared_nets))
                ip_addr = (nets_dict.get(first_net) or {}).get("IPAddress") or c.name
                tcp_host, tcp_port, can_tcp = ip_addr, 5432, True
            elif host_port:
                tcp_host, tcp_port, can_tcp = "host.docker.internal", host_port, True
            else:
                tcp_host, tcp_port, can_tcp = c.name, 5432, False

            instances.append({
                "container_name": c.name,
                "compose_project": compose_project,
                "host": tcp_host,
                "port": tcp_port,
                "user": pg_user,
                "password": pg_password,
                "can_tcp": can_tcp,
                "networks": c_nets,
            })
    except Exception:
        return [default_instance]

    if not instances:
        return [default_instance]

    return sorted(instances, key=lambda x: x["container_name"])


def _exec_psql_json(client: docker.DockerClient, container_name: str, user: str, password: str, dbname: str, query_sql: str) -> List[Dict[str, Any]]:
    """Ejecuta una consulta SQL dentro del contenedor PostgreSQL y retorna filas como dicts."""
    wrapped = f"SELECT COALESCE(json_agg(t), '[]'::json) FROM ({query_sql.rstrip(';')}) t;"
    cmd = ["psql", "-U", user, "-d", dbname, "-t", "-A", "-c", wrapped]
    exec_id = client.api.exec_create(
        container_name,
        cmd,
        environment={"PGPASSWORD": password} if password else {},
        stdout=True,
        stderr=True,
    )["Id"]
    out_chunks = []
    for stdout_chunk, _stderr_chunk in client.api.exec_start(exec_id, stream=True, demux=True):
        if stdout_chunk:
            out_chunks.append(stdout_chunk.decode("utf-8", errors="replace"))
    exit_code = client.api.exec_inspect(exec_id).get("ExitCode")
    if exit_code != 0:
        raise RuntimeError(f"psql exited with {exit_code}")
    raw = "".join(out_chunks).strip()
    if not raw:
        return []
    return json.loads(raw)


def _query_pg(
    inst: Dict[str, Any],
    dbname: str,
    sql_query: str,
    client: Optional[docker.DockerClient] = None,
) -> List[Dict[str, Any]]:
    """Consulta PostgreSQL por TCP si es alcanzable, o vía docker exec si está en red aislada."""
    if inst.get("can_tcp"):
        try:
            conn = _get_pg_conn(
                dbname=dbname,
                host=inst["host"],
                port=inst["port"],
                user=inst["user"],
                password=inst["password"],
            )
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(sql_query)
                rows = [dict(r) for r in cur.fetchall()]
            conn.close()
            return rows
        except Exception:
            if not inst.get("container_name"):
                raise

    if inst.get("container_name"):
        if client is None:
            client = docker.from_env()
        return _exec_psql_json(
            client,
            inst["container_name"],
            inst["user"],
            inst["password"],
            dbname,
            sql_query,
        )
    raise RuntimeError("No se pudo conectar a la instancia PostgreSQL.")


def _extract_nginx_blocks(content: str, keyword: str) -> List[Tuple[str, str]]:
    """Extrae bloques '<keyword> <header> { ... }' respetando llaves anidadas."""
    results: List[Tuple[str, str]] = []
    pattern = re.compile(rf"(?:^|\s){keyword}\s*([^{{;]*)\{{", re.MULTILINE)
    idx = 0
    n = len(content)
    while idx < n:
        m = pattern.search(content, idx)
        if not m:
            break
        header = m.group(1).strip()
        brace_start = m.end() - 1
        depth = 0
        pos = brace_start
        while pos < n:
            ch = content[pos]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    results.append((header, content[brace_start + 1 : pos]))
                    idx = pos + 1
                    break
            pos += 1
        else:
            break
    return results


def _read_nginx_file_following_hostfs(filepath: str) -> str:
    target = filepath
    if os.path.islink(filepath) and not os.path.exists(filepath):
        link_dest = os.readlink(filepath)
        if link_dest.startswith("/"):
            candidate = os.path.join("/hostfs", link_dest.lstrip("/"))
            if os.path.isfile(candidate):
                target = candidate
    if not os.path.isfile(target):
        return ""
    with open(target, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()


def parse_nginx_domain_mapping() -> Dict[str, Any]:
    port_to_domains: Dict[int, List[str]] = {}
    db_to_domain: Dict[str, str] = {}
    all_domains: List[str] = []

    search_dirs = []
    for d in (NGINX_SITES_PATH, "/hostfs/etc/nginx/sites-enabled", "/hostfs/etc/nginx/conf.d"):
        if d and d not in search_dirs and os.path.isdir(d):
            search_dirs.append(d)

    if not search_dirs:
        return {"port_to_domains": port_to_domains, "db_to_domain": db_to_domain, "all_domains": all_domains}

    seen_realpaths = set()
    contents: List[str] = []
    upstream_ports: Dict[str, int] = {}

    for sdir in search_dirs:
        for entry in sorted(os.listdir(sdir)):
            filepath = os.path.join(sdir, entry)
            real_key = os.readlink(filepath) if os.path.islink(filepath) else filepath
            if real_key in seen_realpaths:
                continue
            seen_realpaths.add(real_key)
            try:
                text = _read_nginx_file_following_hostfs(filepath)
                if not text:
                    continue
                # Ignorar líneas comentadas
                clean_lines = [ln for ln in text.splitlines() if not ln.lstrip().startswith("#")]
                clean_text = "\n".join(clean_lines)
                contents.append(clean_text)
                for up_name, up_body in _extract_nginx_blocks(clean_text, "upstream"):
                    if up_name:
                        m_srv = re.search(r"server\s+[^:;]+:(\d+)", up_body)
                        if m_srv:
                            upstream_ports[up_name.split()[0].strip()] = int(m_srv.group(1))
            except Exception:
                continue

    for clean_text in contents:
        try:
            server_blocks = [b for hdr, b in _extract_nginx_blocks(clean_text, "server") if not hdr]
            if not server_blocks:
                server_blocks = [clean_text]
            for block in server_blocks:
                server_names = re.findall(r"server_name\s+([^;]+);", block)
                domains = []
                for sn in server_names:
                    for d in sn.split():
                        d = d.strip()
                        if d and d != "_" and not d.startswith("#"):
                            domains.append(d)
                            if not d.startswith("*.") and d.lower() not in all_domains:
                                all_domains.append(d.lower())

                ports: List[int] = []
                for p_str in re.findall(r"proxy_pass\s+https?://[^:;/\s]+:(\d+)", block):
                    p = int(p_str)
                    if p not in ports:
                        ports.append(p)
                for up_ref in re.findall(r"proxy_pass\s+https?://([A-Za-z0-9_.\-]+)\s*[;/]", block):
                    if up_ref in upstream_ports and upstream_ports[up_ref] not in ports:
                        ports.append(upstream_ports[up_ref])

                # Ignorar puerto secundario de longpolling 8072 si hay un puerto principal HTTP en el mismo server block
                primary_ports = [p for p in ports if p != 8072] or ports

                for port in primary_ports:
                    port_to_domains.setdefault(port, [])
                    for d in domains:
                        if d not in port_to_domains[port]:
                            port_to_domains[port].append(d)
                for d in domains:
                    if d.startswith("*."):
                        continue
                    sub = d.split(".")[0].lower()
                    if sub and sub not in ("www", "cloud", "panel"):
                        db_to_domain[sub] = f"https://{d}"
        except Exception:
            continue
    return {"port_to_domains": port_to_domains, "db_to_domain": db_to_domain, "all_domains": all_domains}


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


def _discover_instance_databases(inst: Dict[str, Any], db_to_domain: Dict[str, str]) -> List[Dict[str, Any]]:
    databases: List[Dict[str, Any]] = []
    client = docker.from_env() if inst.get("container_name") else None
    pg_container = inst.get("container_name") or ""

    try:
        rows = _query_pg(
            inst,
            "postgres",
            """
            SELECT d.datname AS name,
                   pg_size_pretty(pg_database_size(d.datname)) AS size_pretty,
                   pg_database_size(d.datname) AS size_bytes
            FROM pg_database d
            WHERE d.datistemplate = false AND d.datname NOT IN ('postgres') AND d.datname NOT LIKE '_sos_verify_%'
            ORDER BY d.datname
            """,
            client=client,
        )
    except Exception as e:
        return [{
            "name": f"Error conectando a PostgreSQL ({pg_container or inst['host']})",
            "company_name": str(e),
            "version": "Error",
            "size_pretty": "0 MB",
            "base_url": "#",
            "active_users_count": 0,
            "users": [],
            "admin_uid": 2,
            "pg_container": pg_container,
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
            "pg_container": pg_container,
        }
        try:
            check = _query_pg(
                inst,
                dbname,
                """
                SELECT EXISTS (
                    SELECT 1 FROM information_schema.tables
                    WHERE table_schema = 'public' AND table_name = 'ir_config_parameter'
                ) AS is_odoo
                """,
                client=client,
            )
            if not check or not check[0].get("is_odoo"):
                continue

            url_rows = _query_pg(
                inst,
                dbname,
                "SELECT value FROM ir_config_parameter WHERE key = 'web.base.url' LIMIT 1",
                client=client,
            )
            if url_rows and url_rows[0].get("value"):
                val = str(url_rows[0]["value"]).strip().rstrip("/")
                if "localhost" not in val and "127.0.0.1" not in val and ":8069" not in val:
                    if val.startswith("http://") and DEFAULT_BASE_DOMAIN in val:
                        val = "https://" + val[len("http://"):]
                    db_info["base_url"] = val

            if dbname.lower() in db_to_domain:
                db_info["base_url"] = db_to_domain[dbname.lower()]

            ver_rows = _query_pg(
                inst,
                dbname,
                "SELECT latest_version FROM ir_module_module WHERE name = 'base' LIMIT 1",
                client=client,
            )
            if ver_rows and ver_rows[0].get("latest_version"):
                major = ".".join(str(ver_rows[0]["latest_version"]).split(".")[:2])
                db_info["version"] = f"Odoo {major}"

            comp_rows = _query_pg(
                inst,
                dbname,
                "SELECT name FROM res_company ORDER BY id ASC LIMIT 1",
                client=client,
            )
            if comp_rows and comp_rows[0].get("name"):
                db_info["company_name"] = comp_rows[0]["name"]

            users = _query_pg(
                inst,
                dbname,
                """
                SELECT u.id, u.login, COALESCE(p.name, u.login) AS name
                FROM res_users u
                LEFT JOIN res_partner p ON u.partner_id = p.id
                WHERE u.active = true AND (u.share = false OR u.share IS NULL)
                ORDER BY CASE WHEN u.id = 2 THEN 0 ELSE 1 END, u.id ASC
                LIMIT 25
                """,
                client=client,
            )
            db_info["users"] = users
            db_info["active_users_count"] = len(users)
            if users:
                db_info["admin_uid"] = users[0]["id"]
            databases.append(db_info)
        except Exception:
            continue
    return databases


def discover_odoo_databases(db_to_domain: Dict[str, str]) -> List[Dict[str, Any]]:
    instances = discover_postgres_instances()
    if len(instances) == 1:
        return _discover_instance_databases(instances[0], db_to_domain)

    all_dbs: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=min(8, len(instances))) as pool:
        futures = [pool.submit(_discover_instance_databases, inst, db_to_domain) for inst in instances]
        for fut in futures:
            all_dbs.extend(fut.result())

    return sorted(all_dbs, key=lambda d: (d["name"].startswith("Error"), d["name"].lower(), d.get("pg_container", "").lower()))
