"""Generación de backups de bases de datos Odoo (con o sin Filestore)."""
import glob
import json
import os
import re
import shutil
import tempfile
import zipfile
from datetime import datetime
from typing import Any, Dict, Optional

import docker
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse
from starlette.background import BackgroundTask

import audit
import discovery

router = APIRouter()

DB_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,63}$")
PROTECTED_DATABASES = {"postgres", "template0", "template1"}


def _resolve_pg_instance(db_name: str, pg_container: str = "") -> Optional[Dict[str, Any]]:
    instances = discovery.discover_postgres_instances()
    if pg_container:
        for inst in instances:
            if inst.get("container_name") == pg_container:
                return inst
        return None

    if len(instances) == 1:
        return instances[0]

    # Buscar automáticamente en qué instancia existe la base de datos
    safe_db = db_name.replace("'", "''")
    for inst in instances:
        try:
            rows = discovery._query_pg(
                inst,
                "postgres",
                f"SELECT 1 AS ok FROM pg_database WHERE datname = '{safe_db}'",
            )
            if rows:
                return inst
        except Exception:
            continue
    return instances[0] if instances else None


def _find_postgres_container(client: docker.DockerClient, preferred_name: str = ""):
    if preferred_name:
        try:
            c = client.containers.get(preferred_name)
            if c.status == "running":
                return c
        except Exception:
            pass
    try:
        c = client.containers.get(discovery.PG_HOST)
        if c.status == "running":
            return c
    except Exception:
        pass
    candidates = []
    for c in client.containers.list(filters={"status": "running"}):
        image_tags = c.image.tags if c.image.tags else [c.attrs.get("Config", {}).get("Image", "")]
        image_str = (image_tags[0] if image_tags else "").lower()
        if ("postgres" in image_str or "postgres" in c.name.lower()) and "pgadmin" not in image_str:
            candidates.append(c)
    for c in candidates:
        if "central" in c.name.lower() or "16" in c.name.lower():
            return c
    return candidates[0] if candidates else None


def _find_filestore_dir(client: docker.DockerClient, db_name: str, inst: Optional[Dict[str, Any]] = None) -> Optional[str]:
    checked = set()
    target_project = (inst or {}).get("compose_project") or ""
    target_nets = (inst or {}).get("networks") or set()

    def _container_priority(c) -> int:
        labels = c.attrs.get("Config", {}).get("Labels") or {}
        if target_project and labels.get("com.docker.compose.project") == target_project:
            return 0
        c_nets = set((c.attrs.get("NetworkSettings", {}).get("Networks") or {}).keys())
        if target_nets and (target_nets & c_nets):
            return 1
        return 2

    try:
        containers = sorted(client.containers.list(all=True), key=_container_priority)
        for c in containers:
            for m in (c.attrs.get("Mounts") or []):
                src = m.get("Source") or ""
                dest = m.get("Destination") or ""
                if not src or ("odoo" not in dest.lower() and "filestore" not in dest.lower()):
                    continue
                host_src = os.path.join("/hostfs", src.lstrip("/"))
                for candidate in (
                    os.path.join(host_src, "filestore", db_name),
                    os.path.join(host_src, db_name),
                ):
                    if candidate in checked:
                        continue
                    checked.add(candidate)
                    if os.path.isdir(candidate):
                        return candidate
    except Exception:
        pass
    for pattern in (
        f"/hostfs/var/lib/docker/volumes/*/_data/filestore/{db_name}",
        f"/hostfs/var/lib/docker/volumes/*/_data/{db_name}",
    ):
        for path in glob.glob(pattern):
            if os.path.isdir(path):
                return path
    return None


def _build_odoo_manifest(db_name: str, inst: Optional[Dict[str, Any]] = None) -> dict:
    version, major_version, pg_version, modules = "18.0", "18.0", "16", {}
    if inst is None:
        inst = {
            "container_name": "",
            "host": discovery.PG_HOST,
            "port": discovery.PG_PORT,
            "user": discovery.PG_USER,
            "password": discovery.PG_PASSWORD,
            "can_tcp": True,
        }
    try:
        ver_rows = discovery._query_pg(inst, db_name, "SELECT version() AS ver")
        if ver_rows and ver_rows[0].get("ver"):
            m = re.search(r"PostgreSQL\s+([0-9.]+)", str(ver_rows[0]["ver"]))
            if m:
                pg_version = m.group(1)

        base_rows = discovery._query_pg(
            inst, db_name, "SELECT latest_version FROM ir_module_module WHERE name = 'base' LIMIT 1"
        )
        if base_rows and base_rows[0].get("latest_version"):
            version = str(base_rows[0]["latest_version"])
            major_version = ".".join(version.split(".")[:2])

        mod_rows = discovery._query_pg(
            inst, db_name, "SELECT name, latest_version FROM ir_module_module WHERE state = 'installed'"
        )
        for mr in mod_rows:
            modules[mr["name"]] = mr.get("latest_version") or version
    except Exception:
        pass

    return {
        "odoo_dump": "1",
        "db_name": db_name,
        "version": version,
        "version_info": [int(x) if x.isdigit() else x for x in major_version.split(".")],
        "major_version": major_version,
        "pg_version": pg_version,
        "modules": modules,
    }


def _run_pg_dump_to_file(
    client: docker.DockerClient,
    pg_container,
    db_name: str,
    fmt_flag: str,
    dest_path: str,
    pg_user: str = "",
    pg_password: str = "",
) -> None:
    user = pg_user or discovery.PG_USER
    pwd = pg_password if pg_password != "" else discovery.PG_PASSWORD
    cmd = ["pg_dump", "-U", user, "--no-owner", fmt_flag, db_name]
    exec_id = client.api.exec_create(
        pg_container.id, cmd, environment={"PGPASSWORD": pwd} if pwd else {}, stdout=True, stderr=True
    )["Id"]
    stderr_chunks = []
    with open(dest_path, "wb") as out_f:
        for stdout_chunk, stderr_chunk in client.api.exec_start(exec_id, stream=True, demux=True):
            if stdout_chunk:
                out_f.write(stdout_chunk)
            if stderr_chunk and len(stderr_chunks) < 32:
                stderr_chunks.append(stderr_chunk.decode("utf-8", errors="replace"))
    exit_code = client.api.exec_inspect(exec_id).get("ExitCode")
    if exit_code != 0:
        raise RuntimeError("".join(stderr_chunks).strip() or f"pg_dump finalizó con código {exit_code}")


@router.get("/api/databases/{db_name}/backup")
def download_database_backup(request: Request, db_name: str, fmt: str = "zip", pg_container: str = ""):
    from main import is_authenticated
    if not is_authenticated(request):
        raise HTTPException(status_code=401, detail="No autorizado")
    if not DB_NAME_RE.match(db_name) or db_name in PROTECTED_DATABASES:
        raise HTTPException(status_code=400, detail="Nombre de base de datos inválido o protegido.")
    if fmt not in ("zip", "dump"):
        raise HTTPException(status_code=400, detail="Formato inválido. Use 'zip' o 'dump'.")

    inst = _resolve_pg_instance(db_name, pg_container.strip())
    client = docker.from_env()
    target_cname = (inst or {}).get("container_name") or pg_container.strip()
    pg_container_obj = _find_postgres_container(client, target_cname)
    if not pg_container_obj:
        raise HTTPException(status_code=500, detail="No se encontró un contenedor PostgreSQL activo para ejecutar pg_dump.")

    pg_user = (inst or {}).get("user") or discovery.PG_USER
    pg_password = (inst or {}).get("password") if inst is not None else discovery.PG_PASSWORD

    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    tmp_dir = tempfile.mkdtemp(prefix="sos_backup_")
    try:
        if fmt == "dump":
            filename = f"{db_name}_{ts}.dump"
            dump_path = os.path.join(tmp_dir, filename)
            _run_pg_dump_to_file(client, pg_container_obj, db_name, "-Fc", dump_path, pg_user, pg_password)
            audit.log_event(request, "database.backup", target=db_name, status="ok", detail=f"Formato=dump • PG={pg_container_obj.name}")
            return FileResponse(
                path=dump_path, media_type="application/octet-stream", filename=filename,
                background=BackgroundTask(shutil.rmtree, tmp_dir, True),
            )
        dump_sql_path = os.path.join(tmp_dir, "dump.sql")
        _run_pg_dump_to_file(client, pg_container_obj, db_name, "-Fp", dump_sql_path, pg_user, pg_password)
        manifest = _build_odoo_manifest(db_name, inst)
        filestore_dir = _find_filestore_dir(client, db_name, inst)
        filename = f"{db_name}_{ts}.zip"
        zip_path = os.path.join(tmp_dir, filename)
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
            zf.write(dump_sql_path, "dump.sql")
            zf.writestr("manifest.json", json.dumps(manifest, indent=4, ensure_ascii=False))
            if filestore_dir and os.path.isdir(filestore_dir):
                for root, _dirs, files in os.walk(filestore_dir):
                    for fname in files:
                        full_path = os.path.join(root, fname)
                        rel_path = os.path.relpath(full_path, filestore_dir).replace("\\", "/")
                        zf.write(full_path, f"filestore/{rel_path}")
        try:
            os.remove(dump_sql_path)
        except OSError:
            pass
        audit.log_event(
            request,
            "database.backup",
            target=db_name,
            status="ok",
            detail=f"Formato=zip • Filestore={'sí' if filestore_dir else 'no'} • PG={pg_container_obj.name}",
        )
        return FileResponse(
            path=zip_path, media_type="application/zip", filename=filename,
            background=BackgroundTask(shutil.rmtree, tmp_dir, True),
        )
    except HTTPException:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise
    except Exception as e:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        audit.log_event(request, "database.backup", target=db_name, status="error", detail=str(e))
        raise HTTPException(status_code=500, detail=f"Error generando backup: {e}")
