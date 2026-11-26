"""Generación de backups de bases de datos Odoo (con o sin Filestore)."""
import glob
import json
import os
import re
import shutil
import tempfile
import zipfile
from datetime import datetime
from typing import Optional

import docker
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse
from starlette.background import BackgroundTask

import discovery

router = APIRouter()

DB_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,63}$")
PROTECTED_DATABASES = {"postgres", "template0", "template1"}


def _find_postgres_container(client: docker.DockerClient):
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
        if "postgres" in image_str or "postgres" in c.name.lower():
            candidates.append(c)
    for c in candidates:
        if "central" in c.name.lower() or "16" in c.name.lower():
            return c
    return candidates[0] if candidates else None


def _find_filestore_dir(client: docker.DockerClient, db_name: str) -> Optional[str]:
    checked = set()
    try:
        for c in client.containers.list(all=True):
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


def _build_odoo_manifest(db_name: str) -> dict:
    version, major_version, pg_version, modules = "18.0", "18.0", "16", {}
    conn = None
    try:
        conn = discovery._get_pg_conn(db_name)
        with conn.cursor() as cur:
            cur.execute("SELECT version();")
            row = cur.fetchone()
            if row and row[0]:
                m = re.search(r"PostgreSQL\s+([0-9.]+)", row[0])
                if m:
                    pg_version = m.group(1)
            cur.execute("SELECT latest_version FROM ir_module_module WHERE name = 'base' LIMIT 1;")
            base_row = cur.fetchone()
            if base_row and base_row[0]:
                version = base_row[0]
                major_version = ".".join(version.split(".")[:2])
            cur.execute("SELECT name, latest_version FROM ir_module_module WHERE state = 'installed';")
            for mod_name, mod_ver in cur.fetchall():
                modules[mod_name] = mod_ver or version
    except Exception:
        pass
    finally:
        if conn:
            conn.close()
    return {
        "odoo_dump": "1",
        "db_name": db_name,
        "version": version,
        "version_info": [int(x) if x.isdigit() else x for x in major_version.split(".")],
        "major_version": major_version,
        "pg_version": pg_version,
        "modules": modules,
    }


def _run_pg_dump_to_file(client: docker.DockerClient, pg_container, db_name: str, fmt_flag: str, dest_path: str) -> None:
    cmd = ["pg_dump", "-U", discovery.PG_USER, "--no-owner", fmt_flag, db_name]
    exec_id = client.api.exec_create(
        pg_container.id, cmd, environment={"PGPASSWORD": discovery.PG_PASSWORD}, stdout=True, stderr=True
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
def download_database_backup(request: Request, db_name: str, fmt: str = "zip"):
    from main import is_authenticated
    if not is_authenticated(request):
        raise HTTPException(status_code=401, detail="No autorizado")
    if not DB_NAME_RE.match(db_name) or db_name in PROTECTED_DATABASES:
        raise HTTPException(status_code=400, detail="Nombre de base de datos inválido o protegido.")
    if fmt not in ("zip", "dump"):
        raise HTTPException(status_code=400, detail="Formato inválido. Use 'zip' o 'dump'.")

    client = docker.from_env()
    pg_container = _find_postgres_container(client)
    if not pg_container:
        raise HTTPException(status_code=500, detail="No se encontró un contenedor PostgreSQL activo para ejecutar pg_dump.")

    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    tmp_dir = tempfile.mkdtemp(prefix="sos_backup_")
    try:
        if fmt == "dump":
            filename = f"{db_name}_{ts}.dump"
            dump_path = os.path.join(tmp_dir, filename)
            _run_pg_dump_to_file(client, pg_container, db_name, "-Fc", dump_path)
            return FileResponse(
                path=dump_path, media_type="application/octet-stream", filename=filename,
                background=BackgroundTask(shutil.rmtree, tmp_dir, True),
            )
        dump_sql_path = os.path.join(tmp_dir, "dump.sql")
        _run_pg_dump_to_file(client, pg_container, db_name, "-Fp", dump_sql_path)
        manifest = _build_odoo_manifest(db_name)
        filestore_dir = _find_filestore_dir(client, db_name)
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
        return FileResponse(
            path=zip_path, media_type="application/zip", filename=filename,
            background=BackgroundTask(shutil.rmtree, tmp_dir, True),
        )
    except HTTPException:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise
    except Exception as e:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise HTTPException(status_code=500, detail=f"Error generando backup: {e}")
