"""Motor de Respaldos Gestionados (Fase 3):
- Programación automática y ejecución en segundo plano.
- Verificación real de restauración (Restore-Test) en base temporal PostgreSQL.
- Cifrado asimétrico streaming con 'age' + manifiesto firmado SHA-256 / HMAC.
- Destinos combinables: Copia Local + rclone (Google Drive, etc.) + S3 / Cloudflare R2 / B2.
"""
from datetime import datetime, timezone
import glob
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import shutil
import socket as pysocket
import subprocess
import tempfile
import threading
import time
import zipfile
from typing import Any, Dict, List, Optional, Tuple

import boto3
from botocore.config import Config as BotoConfig
import docker

import backups as legacy_backups
import discovery
import notifications
import storage

_logger = logging.getLogger("sos_backup_mgr")
_run_lock = threading.Lock()

POLICY_KEY = "backup_policy_config"
LOCAL_BACKUPS_ROOT = os.environ.get("PANEL_BACKUPS_DIR", "/app/backups" if os.path.isdir("/app") else os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backups")))
SIGNING_SECRET = os.environ.get("SOS_SSO_SECRET") or os.environ.get("PANEL_SESSION_SECRET") or "sos_manifest_key"

DEFAULT_POLICY: Dict[str, Any] = {
    "schedule_enabled": False,
    "schedule_hour": 2,
    "schedule_minute": 0,
    "target_databases": [],  # vacío = todas las BDs reales (no tmp_)
    "backup_format": "zip",  # 'zip' (con filestore) | 'dump' (solo SQL -Fc)
    "verify_restore": True,
    "encryption_enabled": False,
    "age_public_key": "",
    # Destino 1: Local
    "local_enabled": True,
    "local_retention_count": 2,
    # Destino 2: rclone
    "rclone_enabled": False,
    "rclone_remote": "",
    "rclone_base_path": "Backup/sos_cloud_panel",
    "rclone_retention_days": 14,
    # Destino 3: S3 / R2 / B2
    "s3_enabled": False,
    "s3_endpoint_url": "",
    "s3_region": "auto",
    "s3_bucket": "",
    "s3_prefix": "sos_cloud_panel",
    "s3_access_key": "",
    "s3_secret_key": "",
    "s3_retention_days": 14,
}


def get_backup_policy(mask_secrets: bool = False) -> Dict[str, Any]:
    os.makedirs(LOCAL_BACKUPS_ROOT, exist_ok=True)
    cfg = dict(DEFAULT_POLICY)
    raw = storage.get_setting(POLICY_KEY, "")
    if raw:
        try:
            saved = json.loads(raw)
            if isinstance(saved, dict):
                cfg.update(saved)
        except Exception:
            pass
    # Autocompletar primer remoto rclone disponible si no se ha definido uno aún
    if not cfg.get("rclone_remote"):
        remotes = list_rclone_remotes()
        if remotes:
            cfg["rclone_remote"] = remotes[0]
    if mask_secrets:
        sk = str(cfg.get("s3_secret_key") or "")
        if sk:
            cfg["s3_secret_key"] = ("••••••••" + sk[-4:]) if len(sk) > 6 else "••••••••"
    return cfg


def save_backup_policy(incoming: Dict[str, Any]) -> Dict[str, Any]:
    current = get_backup_policy(mask_secrets=False)
    for k in DEFAULT_POLICY:
        if k not in incoming:
            continue
        val = incoming[k]
        if k == "s3_secret_key" and isinstance(val, str) and val.startswith("••••"):
            continue
        if isinstance(DEFAULT_POLICY[k], bool):
            current[k] = bool(val)
        elif isinstance(DEFAULT_POLICY[k], int):
            try:
                current[k] = int(val)
            except (ValueError, TypeError):
                pass
        elif isinstance(DEFAULT_POLICY[k], list):
            if isinstance(val, list):
                current[k] = [str(x).strip() for x in val if str(x).strip()]
        else:
            current[k] = str(val or "").strip()

    current["schedule_hour"] = max(0, min(23, int(current["schedule_hour"])))
    current["schedule_minute"] = max(0, min(59, int(current["schedule_minute"])))
    current["local_retention_count"] = max(0, min(60, int(current["local_retention_count"])))
    current["rclone_retention_days"] = max(0, min(3650, int(current["rclone_retention_days"])))
    current["s3_retention_days"] = max(0, min(3650, int(current["s3_retention_days"])))
    if current["backup_format"] not in ("zip", "dump"):
        current["backup_format"] = "zip"

    if current["encryption_enabled"] and not current["age_public_key"].startswith("age1"):
        raise ValueError("Para activar el cifrado debe ingresar o generar una llave pública 'age1...' válida.")

    storage.set_setting(POLICY_KEY, json.dumps(current))
    return get_backup_policy(mask_secrets=True)


# --- rclone & age helpers ---

def _resolve_rclone_cmd_base() -> List[str]:
    primary_conf = "/root/.config/rclone/rclone.conf"
    if os.path.isfile(primary_conf) and os.path.getsize(primary_conf) > 0:
        return ["rclone", "--config", primary_conf]

    fallback_conf = os.path.join(os.path.dirname(storage.DB_PATH), "rclone.conf")
    if not os.path.isfile(fallback_conf):
        for candidate in glob.glob("/hostfs/home/*/.config/rclone/rclone.conf"):
            if os.path.isfile(candidate) and os.path.getsize(candidate) > 0:
                shutil.copy2(candidate, fallback_conf)
                break
    if os.path.isfile(fallback_conf):
        return ["rclone", "--config", fallback_conf]
    return ["rclone"]


def list_rclone_remotes() -> List[str]:
    if not shutil.which("rclone"):
        return []
    try:
        res = subprocess.run(
            _resolve_rclone_cmd_base() + ["listremotes"],
            capture_output=True,
            text=True,
            timeout=6,
            check=False,
        )
        if res.returncode == 0:
            return [ln.strip() for ln in res.stdout.splitlines() if ln.strip()]
    except Exception:
        pass
    return []


def generate_age_keypair() -> Dict[str, str]:
    if not shutil.which("age-keygen"):
        raise RuntimeError("El binario 'age-keygen' no está disponible en el contenedor.")
    res = subprocess.run(["age-keygen"], capture_output=True, text=True, timeout=5, check=True)
    combined = (res.stdout or "") + "\n" + (res.stderr or "")
    pub_m = re.search(r"(age1[a-z0-9]{50,})", combined)
    sec_m = re.search(r"(AGE-SECRET-KEY-1[A-Z0-9]{50,})", combined)
    if not pub_m or not sec_m:
        raise RuntimeError("No se pudo extraer el par de llaves age.")
    return {"public_key": pub_m.group(1), "private_key": sec_m.group(1)}


def _encrypt_file_with_age(src_path: str, public_key: str) -> str:
    dest_path = src_path + ".age"
    res = subprocess.run(
        ["age", "-r", public_key.strip(), "-o", dest_path, src_path],
        capture_output=True,
        text=True,
        timeout=1800,
        check=False,
    )
    if res.returncode != 0 or not os.path.isfile(dest_path) or os.path.getsize(dest_path) == 0:
        raise RuntimeError(f"Fallo cifrado age: {(res.stderr or '').strip()}")
    return dest_path


def _sha256_file(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(524288)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


# --- Verificación real de restauración en PostgreSQL (Restore-Test) ---

def _exec_pg_simple(client: docker.DockerClient, container_id: str, user: str, password: str, dbname: str, sql_cmd: str) -> Tuple[int, str]:
    cmd = ["psql", "-U", user, "-d", dbname, "-t", "-A", "-c", sql_cmd]
    exec_id = client.api.exec_create(
        container_id,
        cmd,
        environment={"PGPASSWORD": password} if password else {},
        stdout=True,
        stderr=True,
    )["Id"]
    out_chunks = []
    for out_c, err_c in client.api.exec_start(exec_id, stream=True, demux=True):
        if out_c:
            out_chunks.append(out_c.decode("utf-8", errors="replace"))
        if err_c:
            out_chunks.append(err_c.decode("utf-8", errors="replace"))
    code = client.api.exec_inspect(exec_id).get("ExitCode") or 0
    return code, "".join(out_chunks).strip()


def _stream_file_to_pg_exec(
    client: docker.DockerClient,
    container_id: str,
    cmd: List[str],
    password: str,
    filepath: str,
) -> int:
    exec_id = client.api.exec_create(
        container_id,
        cmd,
        stdin=True,
        stdout=True,
        stderr=True,
        environment={"PGPASSWORD": password} if password else {},
    )["Id"]
    sock = client.api.exec_start(exec_id, detach=False, tty=False, stream=False, socket=True)
    raw_sock = getattr(sock, "_sock", sock)
    try:
        with open(filepath, "rb") as f:
            while True:
                buf = f.read(262144)
                if not buf:
                    break
                raw_sock.sendall(buf)
        try:
            raw_sock.shutdown(pysocket.SHUT_WR)
        except OSError:
            pass
        while True:
            data = raw_sock.recv(65536)
            if not data:
                break
    finally:
        try:
            sock.close()
        except Exception:
            pass
    return int(client.api.exec_inspect(exec_id).get("ExitCode") or 0)


def _verify_restore_in_temp_db(
    client: docker.DockerClient,
    pg_container_obj,
    pg_user: str,
    pg_password: str,
    db_name: str,
    dump_path: str,
    is_custom_format: bool,
) -> Tuple[bool, str]:
    slug = re.sub(r"[^a-z0-9]", "", db_name.lower())[:18] or "db"
    temp_db = f"_sos_verify_{slug}_{secrets.token_hex(3)}"
    t0 = time.perf_counter()

    code_c, out_c = _exec_pg_simple(
        client, pg_container_obj.id, pg_user, pg_password, "postgres", f'CREATE DATABASE "{temp_db}";'
    )
    if code_c != 0:
        return False, f"No se pudo crear BD temporal: {out_c[:160]}"

    try:
        if is_custom_format:
            cmd = ["pg_restore", "-U", pg_user, "-d", temp_db, "--no-owner", "--no-privileges"]
        else:
            cmd = ["psql", "-U", pg_user, "-d", temp_db, "-q"]

        _stream_file_to_pg_exec(client, pg_container_obj.id, cmd, pg_password, dump_path)

        check_sql = (
            "SELECT json_build_object("
            "'mods', (SELECT COUNT(*) FROM ir_module_module WHERE state='installed'),"
            "'users', (SELECT COUNT(*) FROM res_users WHERE active=true),"
            "'companies', (SELECT COUNT(*) FROM res_company)"
            ");"
        )
        v_code, v_out = _exec_pg_simple(client, pg_container_obj.id, pg_user, pg_password, temp_db, check_sql)
        elapsed = round(time.perf_counter() - t0, 1)
        if v_code != 0 or not v_out:
            return False, f"Fallo validación de tablas Odoo tras restaurar ({elapsed}s): {v_out[:140]}"

        # Tomar última línea JSON válida
        stats = json.loads(v_out.splitlines()[-1])
        mods = int(stats.get("mods") or 0)
        users = int(stats.get("users") or 0)
        comps = int(stats.get("companies") or 0)
        if mods <= 0 or comps <= 0:
            return False, f"BD restaurada incompleta (mods={mods}, companies={comps})"

        return True, f"Restore-Test OK en {elapsed}s ({mods} módulos, {users} usuarios, {comps} empresa{'s' if comps != 1 else ''})"
    except Exception as exc:
        return False, f"Excepción en Restore-Test: {str(exc)[:180]}"
    finally:
        _exec_pg_simple(
            client,
            pg_container_obj.id,
            pg_user,
            pg_password,
            "postgres",
            f"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{temp_db}' AND pid <> pg_backend_pid();",
        )
        _exec_pg_simple(
            client,
            pg_container_obj.id,
            pg_user,
            pg_password,
            "postgres",
            f'DROP DATABASE IF EXISTS "{temp_db}";',
        )


# --- Destinos de almacenamiento ---

def _store_local(db_name: str, final_file: str, manifest_file: str, retention_count: int) -> Dict[str, Any]:
    if retention_count <= 0:
        return {"ok": True, "skipped": True, "detail": "Retención local en 0 (solo nube)"}

    dest_dir = os.path.join(LOCAL_BACKUPS_ROOT, db_name)
    os.makedirs(dest_dir, exist_ok=True)
    dest_file = os.path.join(dest_dir, os.path.basename(final_file))
    dest_manifest = os.path.join(dest_dir, os.path.basename(manifest_file))
    shutil.copy2(final_file, dest_file)
    shutil.copy2(manifest_file, dest_manifest)

    # Aplicar rotación local por cantidad
    backups_in_dir = sorted(
        [
            os.path.join(dest_dir, f)
            for f in os.listdir(dest_dir)
            if not f.endswith(".manifest.json") and os.path.isfile(os.path.join(dest_dir, f))
        ],
        key=lambda p: os.path.getmtime(p),
        reverse=True,
    )
    for old_path in backups_in_dir[retention_count:]:
        try:
            os.remove(old_path)
            mf = old_path + ".manifest.json"
            if os.path.isfile(mf):
                os.remove(mf)
        except OSError:
            pass

    return {"ok": True, "path": f"{db_name}/{os.path.basename(final_file)}"}


def _upload_rclone(policy: Dict[str, Any], db_name: str, final_file: str, manifest_file: str) -> Dict[str, Any]:
    remote = (policy.get("rclone_remote") or "").strip()
    if not remote:
        raise RuntimeError("No se configuró el nombre del remoto rclone.")
    if not remote.endswith(":"):
        remote += ":"
    base_path = (policy.get("rclone_base_path") or "Backup/sos_cloud_panel").strip("/")
    server_slug = re.sub(r"[^A-Za-z0-9_.\-]", "_", discovery.DEFAULT_BASE_DOMAIN)
    remote_target = f"{remote}{base_path}/{server_slug}/{db_name}"

    cmd_base = _resolve_rclone_cmd_base()
    for fpath in (final_file, manifest_file):
        res = subprocess.run(
            cmd_base + ["copy", fpath, remote_target],
            capture_output=True,
            text=True,
            timeout=3600,
            check=False,
        )
        if res.returncode != 0:
            raise RuntimeError(f"rclone error: {(res.stderr or res.stdout or '').strip()[:220]}")

    ret_days = int(policy.get("rclone_retention_days") or 0)
    if ret_days > 0:
        subprocess.run(
            cmd_base + ["delete", remote_target, "--min-age", f"{ret_days}d"],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )

    return {"ok": True, "remote_path": f"{remote_target}/{os.path.basename(final_file)}"}


def _build_s3_client(policy: Dict[str, Any]):
    endpoint = (policy.get("s3_endpoint_url") or "").strip() or None
    region = (policy.get("s3_region") or "us-east-1").strip() or "us-east-1"
    ak = (policy.get("s3_access_key") or "").strip()
    sk = (policy.get("s3_secret_key") or "").strip()
    if not ak or not sk or not policy.get("s3_bucket"):
        raise RuntimeError("Configuración S3/R2 incompleta (bucket, access_key o secret_key).")
    return boto3.client(
        "s3",
        endpoint_url=endpoint,
        region_name=region,
        aws_access_key_id=ak,
        aws_secret_access_key=sk,
        config=BotoConfig(signature_version="s3v4", connect_timeout=10, read_timeout=120),
    )


def _upload_s3(policy: Dict[str, Any], db_name: str, final_file: str, manifest_file: str) -> Dict[str, Any]:
    s3 = _build_s3_client(policy)
    bucket = policy["s3_bucket"].strip()
    prefix = (policy.get("s3_prefix") or "sos_cloud_panel").strip("/")
    server_slug = re.sub(r"[^A-Za-z0-9_.\-]", "_", discovery.DEFAULT_BASE_DOMAIN)
    dir_prefix = f"{prefix}/{server_slug}/{db_name}"

    key_main = f"{dir_prefix}/{os.path.basename(final_file)}"
    key_manifest = f"{dir_prefix}/{os.path.basename(manifest_file)}"
    s3.upload_file(final_file, bucket, key_main)
    s3.upload_file(manifest_file, bucket, key_manifest)

    ret_days = int(policy.get("s3_retention_days") or 0)
    if ret_days > 0:
        cutoff_ts = time.time() - (ret_days * 86400)
        try:
            resp = s3.list_objects_v2(Bucket=bucket, Prefix=dir_prefix + "/")
            for obj in resp.get("Contents") or []:
                lm = obj.get("LastModified")
                if lm and lm.timestamp() < cutoff_ts:
                    s3.delete_object(Bucket=bucket, Key=obj["Key"])
        except Exception as exc:
            _logger.warning("Aviso aplicando retención S3 en %s: %s", dir_prefix, exc)

    return {"ok": True, "s3_uri": f"s3://{bucket}/{key_main}"}


def test_destination_connection(dest_type: str) -> Tuple[bool, str]:
    policy = get_backup_policy(mask_secrets=False)
    if dest_type == "rclone":
        remote = (policy.get("rclone_remote") or "").strip()
        if not remote:
            return False, "Configure primero el nombre del remoto rclone."
        if not remote.endswith(":"):
            remote += ":"
        res = subprocess.run(
            _resolve_rclone_cmd_base() + ["lsd", remote],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if res.returncode == 0:
            return True, f"Conexión exitosa con '{remote}'."
        return False, f"Error en '{remote}': {(res.stderr or res.stdout or '').strip()[:220]}"

    if dest_type == "s3":
        try:
            s3 = _build_s3_client(policy)
            bucket = policy["s3_bucket"].strip()
            s3.list_objects_v2(Bucket=bucket, MaxKeys=1)
            return True, f"Conexión exitosa al bucket S3/R2 '{bucket}'."
        except Exception as exc:
            return False, f"Error conectando a S3/R2: {str(exc)[:220]}"

    return False, "Tipo de destino desconocido."


# --- Ejecución principal de un Backup Verificado ---

def execute_single_backup(
    db_name: str,
    pg_container: str = "",
    trigger_type: str = "manual",
    override_policy: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    policy = override_policy or get_backup_policy(mask_secrets=False)
    fmt = policy.get("backup_format", "zip")
    inst = legacy_backups._resolve_pg_instance(db_name, pg_container)
    target_cname = (inst or {}).get("container_name") or pg_container

    run_id = storage.create_backup_run(db_name=db_name, pg_container=target_cname, fmt=fmt, trigger_type=trigger_type)
    tmp_dir = tempfile.mkdtemp(prefix="sos_managed_bkp_")

    try:
        if not any([policy.get("local_enabled"), policy.get("rclone_enabled"), policy.get("s3_enabled")]):
            raise RuntimeError("Debe habilitar al menos un destino de almacenamiento (Local, rclone o S3/R2).")

        client = docker.from_env()
        pg_container_obj = legacy_backups._find_postgres_container(client, target_cname)
        if not pg_container_obj:
            raise RuntimeError("No se encontró contenedor PostgreSQL activo para ejecutar el respaldo.")

        pg_user = (inst or {}).get("user") or discovery.PG_USER
        pg_password = (inst or {}).get("password") if inst is not None else discovery.PG_PASSWORD
        ts_str = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")

        restore_tested = False
        restore_ok = False
        restore_detail = "Omitido por configuración"

        if fmt == "dump":
            base_filename = f"{db_name}_{ts_str}.dump"
            archive_path = os.path.join(tmp_dir, base_filename)
            legacy_backups._run_pg_dump_to_file(client, pg_container_obj, db_name, "-Fc", archive_path, pg_user, pg_password)
            if policy.get("verify_restore", True):
                restore_tested = True
                restore_ok, restore_detail = _verify_restore_in_temp_db(
                    client, pg_container_obj, pg_user, pg_password, db_name, archive_path, is_custom_format=True
                )
        else:
            dump_sql_path = os.path.join(tmp_dir, "dump.sql")
            legacy_backups._run_pg_dump_to_file(client, pg_container_obj, db_name, "-Fp", dump_sql_path, pg_user, pg_password)
            if policy.get("verify_restore", True):
                restore_tested = True
                restore_ok, restore_detail = _verify_restore_in_temp_db(
                    client, pg_container_obj, pg_user, pg_password, db_name, dump_sql_path, is_custom_format=False
                )

            manifest_odoo = legacy_backups._build_odoo_manifest(db_name, inst)
            filestore_dir = legacy_backups._find_filestore_dir(client, db_name, inst)
            base_filename = f"{db_name}_{ts_str}.zip"
            archive_path = os.path.join(tmp_dir, base_filename)
            with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
                zf.write(dump_sql_path, "dump.sql")
                zf.writestr("manifest.json", json.dumps(manifest_odoo, indent=4, ensure_ascii=False))
                if filestore_dir and os.path.isdir(filestore_dir):
                    for root, _dirs, files in os.walk(filestore_dir):
                        for fname in files:
                            full_p = os.path.join(root, fname)
                            rel_p = os.path.relpath(full_p, filestore_dir).replace("\\", "/")
                            zf.write(full_p, f"filestore/{rel_p}")
            try:
                os.remove(dump_sql_path)
            except OSError:
                pass

        if restore_tested and not restore_ok:
            raise RuntimeError(f"Verificación de restauración fallida: {restore_detail}")

        encrypted = False
        final_path = archive_path
        if policy.get("encryption_enabled") and policy.get("age_public_key"):
            final_path = _encrypt_file_with_age(archive_path, policy["age_public_key"])
            encrypted = True

        final_filename = os.path.basename(final_path)
        size_bytes = os.path.getsize(final_path)
        sha256_hex = _sha256_file(final_path)

        # Construir manifiesto criptográfico firmado
        manifest_payload = {
            "sos_backup_manifest": "1.0",
            "db_name": db_name,
            "pg_container": pg_container_obj.name,
            "filename": final_filename,
            "format": fmt,
            "encrypted_age": encrypted,
            "size_bytes": size_bytes,
            "sha256": sha256_hex,
            "restore_tested": restore_tested,
            "restore_ok": restore_ok,
            "restore_detail": restore_detail,
            "created_at_utc": ts_str,
        }
        canonical = json.dumps(manifest_payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
        manifest_payload["signature_hmac_sha256"] = hmac.new(
            SIGNING_SECRET.encode("utf-8"), canonical, hashlib.sha256
        ).hexdigest()

        manifest_path = final_path + ".manifest.json"
        with open(manifest_path, "w", encoding="utf-8") as mf:
            json.dump(manifest_payload, mf, indent=2, ensure_ascii=False)

        # Enviar a destinos habilitados
        destinations_res: Dict[str, Any] = {}
        dest_errors = []

        if policy.get("rclone_enabled"):
            try:
                destinations_res["rclone"] = _upload_rclone(policy, db_name, final_path, manifest_path)
            except Exception as e:
                destinations_res["rclone"] = {"ok": False, "error": str(e)}
                dest_errors.append(f"rclone: {e}")

        if policy.get("s3_enabled"):
            try:
                destinations_res["s3"] = _upload_s3(policy, db_name, final_path, manifest_path)
            except Exception as e:
                destinations_res["s3"] = {"ok": False, "error": str(e)}
                dest_errors.append(f"S3: {e}")

        if policy.get("local_enabled"):
            try:
                destinations_res["local"] = _store_local(
                    db_name, final_path, manifest_path, int(policy.get("local_retention_count") or 0)
                )
            except Exception as e:
                destinations_res["local"] = {"ok": False, "error": str(e)}
                dest_errors.append(f"local: {e}")

        any_ok = any(v.get("ok") and not v.get("skipped") for v in destinations_res.values())
        if dest_errors and not any_ok:
            raise RuntimeError("Fallaron todos los destinos: " + " | ".join(dest_errors))

        final_status = "partial" if dest_errors else "ok"
        err_msg = " | ".join(dest_errors)

        storage.finish_backup_run(
            run_id=run_id,
            status=final_status,
            filename=final_filename,
            size_bytes=size_bytes,
            sha256=sha256_hex,
            encrypted=encrypted,
            restore_tested=restore_tested,
            restore_ok=restore_ok,
            restore_detail=restore_detail,
            destinations_json=json.dumps(destinations_res, ensure_ascii=False),
            error=err_msg,
        )

        inc_key = f"backup:{db_name}"
        if final_status == "ok":
            notifications.resolve_incident_if_open(
                inc_key,
                f"Respaldo verificado restablecido: {db_name}",
                f"{final_filename} ({round(size_bytes / (1024*1024), 2)} MB) • {restore_detail}",
            )
        else:
            notifications.report_incident(
                inc_key,
                "backup_partial",
                "warning",
                db_name,
                f"Respaldo parcial en {db_name}",
                err_msg,
            )

        return {"ok": True, "run_id": run_id, "status": final_status, "filename": final_filename, "restore_detail": restore_detail}

    except Exception as exc:
        err_str = str(exc)
        _logger.error("Fallo en respaldo gestionado de '%s': %s", db_name, err_str)
        storage.finish_backup_run(
            run_id=run_id,
            status="failed",
            error=err_str,
        )
        notifications.report_incident(
            incident_key=f"backup:{db_name}",
            kind="backup_failed",
            severity="critical",
            target=db_name,
            title=f"Fallo en respaldo automático de {db_name}",
            detail=err_str[:300],
        )
        return {"ok": False, "run_id": run_id, "status": "failed", "error": err_str}
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def run_batch_backups(targets: Optional[List[Tuple[str, str]]] = None, trigger_type: str = "scheduled") -> List[Dict[str, Any]]:
    if not _run_lock.acquire(blocking=False):
        _logger.info("Ya hay un lote de respaldos en ejecución; omitiendo disparo duplicado.")
        return []
    try:
        policy = get_backup_policy(mask_secrets=False)
        if targets is None:
            all_dbs = discovery.discover_odoo_databases({})
            selected_names = set(policy.get("target_databases") or [])
            targets = []
            for d in all_dbs:
                name = str(d.get("name") or "")
                if not name or name.startswith("Error") or name.lower().startswith("tmp_") or name.startswith("_sos_verify_"):
                    continue
                if selected_names and name not in selected_names:
                    continue
                targets.append((name, d.get("pg_container") or ""))

        results = []
        for db_name, pg_cont in targets:
            results.append(execute_single_backup(db_name, pg_cont, trigger_type=trigger_type, override_policy=policy))
        return results
    finally:
        _run_lock.release()


def trigger_async_backup(targets: Optional[List[Tuple[str, str]]] = None, trigger_type: str = "manual") -> bool:
    if _run_lock.locked():
        return False
    threading.Thread(
        target=run_batch_backups,
        kwargs={"targets": targets, "trigger_type": trigger_type},
        name="sos-backup-worker",
        daemon=True,
    ).start()
    return True


def list_local_backup_files() -> List[Dict[str, Any]]:
    os.makedirs(LOCAL_BACKUPS_ROOT, exist_ok=True)
    items: List[Dict[str, Any]] = []
    for db_dir in sorted(os.listdir(LOCAL_BACKUPS_ROOT)):
        full_dir = os.path.join(LOCAL_BACKUPS_ROOT, db_dir)
        if not os.path.isdir(full_dir):
            continue
        for fname in os.listdir(full_dir):
            if fname.endswith(".manifest.json"):
                continue
            fpath = os.path.join(full_dir, fname)
            if not os.path.isfile(fpath):
                continue
            st = os.stat(fpath)
            items.append({
                "db_name": db_dir,
                "filename": fname,
                "rel_path": f"{db_dir}/{fname}",
                "size_mb": round(st.st_size / (1024 * 1024), 2),
                "mtime": int(st.st_mtime),
                "encrypted": fname.endswith(".age"),
            })
    items.sort(key=lambda x: x["mtime"], reverse=True)
    return items
