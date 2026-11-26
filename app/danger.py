"""Acciones administrativas sensibles del panel: eliminar BD y parar/borrar contenedores.

Cada operación exige reenviar la clave maestra del panel (PANEL_ADMIN_PASSWORD),
aunque ya exista sesión iniciada. Incluye bloqueo temporal por intentos fallidos
y una lista de recursos protegidos.
"""
import hmac
import logging
import os
import re
import time
from typing import Any, Dict, Optional, Tuple

import docker
import psycopg2
from psycopg2 import sql
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

import audit
import discovery

router = APIRouter()
_logger = logging.getLogger("sos_admin_actions")

PANEL_ADMIN_PASSWORD = os.environ.get("PANEL_ADMIN_PASSWORD", "admin")
PROTECTED_CONTAINERS = {
    c.strip()
    for c in os.environ.get("PROTECTED_CONTAINERS", "sos_cloud_panel,postgres16_central").split(",")
    if c.strip()
}
PROTECTED_DATABASES = {"postgres", "template0", "template1"}
DB_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,63}$")

MAX_ATTEMPTS = 5
LOCK_SECONDS = 300
_attempts: Dict[str, Tuple[int, float]] = {}


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _authorize(request: Request, data: dict) -> None:
    """Valida la sesión y la clave maestra reenviada; lanza HTTPException si falla."""
    from main import is_authenticated  # import tardío para evitar ciclo

    if not is_authenticated(request):
        raise HTTPException(status_code=401, detail="No autorizado")

    ip = _client_ip(request)
    count, until = _attempts.get(ip, (0, 0.0))
    now = time.time()
    if until > now:
        raise HTTPException(status_code=429, detail=f"Demasiados intentos. Reintente en {int(until - now)} s.")

    supplied = str(data.get("admin_password") or "")
    if not hmac.compare_digest(supplied, PANEL_ADMIN_PASSWORD):
        count += 1
        if count >= MAX_ATTEMPTS:
            _attempts[ip] = (0, now + LOCK_SECONDS)
        else:
            _attempts[ip] = (count, 0.0)
        _logger.warning("Clave maestra incorrecta en acción sensible desde %s", ip)
        audit.log_event(request, "security.master_key", target=request.url.path, status="denied", detail="Clave maestra incorrecta")
        raise HTTPException(status_code=403, detail="Clave maestra del panel incorrecta.")

    _attempts.pop(ip, None)


async def _json(request: Request) -> dict:
    try:
        data = await request.json()
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _resolve_pg_instance(db_name: str, pg_container: str = "") -> Optional[Dict[str, Any]]:
    instances = discovery.discover_postgres_instances()
    if pg_container:
        for inst in instances:
            if inst.get("container_name") == pg_container:
                return inst
        return None
    if len(instances) == 1:
        return instances[0]
    safe_db = db_name.replace("'", "''")
    for inst in instances:
        try:
            if discovery._query_pg(inst, "postgres", f"SELECT 1 AS ok FROM pg_database WHERE datname = '{safe_db}'"):
                return inst
        except Exception:
            continue
    return instances[0] if instances else None


def _drop_via_docker_exec(container_name: str, user: str, password: str, db_name: str) -> None:
    client = docker.from_env()
    safe_lit = db_name.replace("'", "''")
    safe_ident = '"' + db_name.replace('"', '""') + '"'
    term_sql = (
        f"SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
        f"WHERE datname = '{safe_lit}' AND pid <> pg_backend_pid();"
    )
    drop_sql = f"DROP DATABASE IF EXISTS {safe_ident};"
    cmd = ["psql", "-U", user, "-d", "postgres", "-v", "ON_ERROR_STOP=1", "-c", term_sql, "-c", drop_sql]
    exec_id = client.api.exec_create(
        container_name, cmd, environment={"PGPASSWORD": password} if password else {}, stdout=True, stderr=True
    )["Id"]
    stderr_chunks = []
    for _out, err in client.api.exec_start(exec_id, stream=True, demux=True):
        if err:
            stderr_chunks.append(err.decode("utf-8", errors="replace"))
    exit_code = client.api.exec_inspect(exec_id).get("ExitCode")
    if exit_code != 0:
        raise RuntimeError("".join(stderr_chunks).strip() or f"psql finalizó con código {exit_code}")


@router.post("/api/databases/{db_name}/drop")
async def drop_database(request: Request, db_name: str):
    data = await _json(request)
    _authorize(request, data)

    if not DB_NAME_RE.match(db_name) or db_name in PROTECTED_DATABASES:
        return JSONResponse({"ok": False, "message": "Base de datos protegida o con nombre inválido."}, status_code=400)

    if str(data.get("confirm_name") or "") != db_name:
        return JSONResponse({"ok": False, "message": "El nombre escrito no coincide con la base de datos."}, status_code=400)

    pg_container = str(data.get("pg_container") or "").strip()
    inst = _resolve_pg_instance(db_name, pg_container)
    if not inst:
        return JSONResponse({"ok": False, "message": "No se encontró la instancia PostgreSQL."}, status_code=404)

    conn = None
    try:
        if inst.get("can_tcp"):
            try:
                conn = discovery._get_pg_conn(
                    "postgres",
                    host=inst["host"],
                    port=inst["port"],
                    user=inst["user"],
                    password=inst["password"],
                )
                conn.autocommit = True
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                        "WHERE datname = %s AND pid <> pg_backend_pid();",
                        (db_name,),
                    )
                    cur.execute(sql.SQL("DROP DATABASE IF EXISTS {};").format(sql.Identifier(db_name)))
            except Exception:
                if not inst.get("container_name"):
                    raise
                _drop_via_docker_exec(inst["container_name"], inst["user"], inst["password"], db_name)
        elif inst.get("container_name"):
            _drop_via_docker_exec(inst["container_name"], inst["user"], inst["password"], db_name)
        else:
            return JSONResponse({"ok": False, "message": "Instancia PostgreSQL inaccesible."}, status_code=500)

        _logger.warning("BD '%s' (%s) eliminada desde el panel (IP %s)", db_name, inst.get("container_name") or inst["host"], _client_ip(request))
        audit.log_event(request, "database.drop", target=db_name, status="ok", detail=f"PostgreSQL: {inst.get('container_name') or inst['host']}")
        return JSONResponse({
            "ok": True,
            "message": f"Base de datos '{db_name}' eliminada. El filestore (adjuntos) no se borra automáticamente.",
        })
    except psycopg2.Error as e:
        audit.log_event(request, "database.drop", target=db_name, status="error", detail=str(e))
        return JSONResponse({"ok": False, "message": f"Error PostgreSQL: {e.pgerror or e}"}, status_code=500)
    except Exception as e:
        audit.log_event(request, "database.drop", target=db_name, status="error", detail=str(e))
        return JSONResponse({"ok": False, "message": f"Error eliminando BD: {e}"}, status_code=500)
    finally:
        if conn:
            conn.close()


def _get_container(name: str):
    client = docker.from_env()
    return client.containers.get(name)


@router.post("/api/containers/{container_name}/stop")
async def stop_container(request: Request, container_name: str):
    data = await _json(request)
    _authorize(request, data)

    if container_name in PROTECTED_CONTAINERS:
        return JSONResponse({"ok": False, "message": f"'{container_name}' es un contenedor protegido."}, status_code=400)
    try:
        _get_container(container_name).stop(timeout=15)
        _logger.warning("Contenedor '%s' detenido desde el panel (IP %s)", container_name, _client_ip(request))
        audit.log_event(request, "container.stop", target=container_name, status="ok")
        return JSONResponse({"ok": True, "message": f"Contenedor '{container_name}' detenido."})
    except Exception as e:
        audit.log_event(request, "container.stop", target=container_name, status="error", detail=str(e))
        return JSONResponse({"ok": False, "message": str(e)}, status_code=500)


@router.post("/api/containers/{container_name}/start")
async def start_container(request: Request, container_name: str):
    data = await _json(request)
    _authorize(request, data)

    try:
        _get_container(container_name).start()
        _logger.warning("Contenedor '%s' iniciado desde el panel (IP %s)", container_name, _client_ip(request))
        audit.log_event(request, "container.start", target=container_name, status="ok")
        return JSONResponse({"ok": True, "message": f"Contenedor '{container_name}' iniciado."})
    except Exception as e:
        audit.log_event(request, "container.start", target=container_name, status="error", detail=str(e))
        return JSONResponse({"ok": False, "message": str(e)}, status_code=500)


@router.post("/api/containers/{container_name}/remove")
async def remove_container(request: Request, container_name: str):
    data = await _json(request)
    _authorize(request, data)

    if container_name in PROTECTED_CONTAINERS:
        return JSONResponse({"ok": False, "message": f"'{container_name}' es un contenedor protegido."}, status_code=400)

    if str(data.get("confirm_name") or "") != container_name:
        return JSONResponse({"ok": False, "message": "El nombre escrito no coincide con el contenedor."}, status_code=400)

    try:
        container = _get_container(container_name)
        if container.status == "running":
            container.stop(timeout=15)
        # v=False: los volúmenes con datos NO se eliminan
        container.remove(v=False, force=True)
        _logger.warning("Contenedor '%s' eliminado desde el panel (IP %s)", container_name, _client_ip(request))
        audit.log_event(request, "container.remove", target=container_name, status="ok", detail="Volúmenes conservados (v=False)")
        return JSONResponse({
            "ok": True,
            "message": f"Contenedor '{container_name}' detenido y eliminado. Sus volúmenes no se borraron.",
        })
    except Exception as e:
        audit.log_event(request, "container.remove", target=container_name, status="error", detail=str(e))
        return JSONResponse({"ok": False, "message": str(e)}, status_code=500)
