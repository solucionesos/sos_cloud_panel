"""Fase 5 — Olfato Antivirus para Filestore de Odoo (YARA-X + Magic Bytes Spoofing + Cuarentena Reversible)."""
import hashlib
import logging
import os
import shutil
import stat
import struct
import subprocess
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

import docker
import yara_x

import backups as legacy_backups
import discovery
import notifications
import storage

_logger = logging.getLogger("sos_filestore_av")
_scan_lock = threading.Lock()

QUARANTINE_DIR = os.path.join(os.path.dirname(storage.DB_PATH), "quarantine")

YARA_RULES_SRC = r"""
rule SOS_EICAR_Antivirus_Test {
    meta:
        severity = "critical"
        description = "Archivo de prueba estándar antivirus EICAR detectado"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule SOS_PHP_Webshell_Generic {
    meta:
        severity = "critical"
        description = "Posible Webshell PHP con ejecución dinámica de comandos/código"
    strings:
        $php = "<?php" nocase
        $s1 = "shell_exec(" nocase
        $s2 = "passthru(" nocase
        $s3 = "proc_open(" nocase
        $s4 = "eval(base64_decode(" nocase
        $s5 = "eval(gzinflate(" nocase
        $s6 = "system($_" nocase
    condition:
        $php and any of ($s*)
}

rule SOS_Linux_Cryptominer_Malware {
    meta:
        severity = "critical"
        description = "Indicadores de minero de criptomonedas / botnet Linux (XMRig / Kinsing)"
    strings:
        $m1 = "stratum+tcp://" nocase
        $m2 = "stratum+ssl://" nocase
        $m3 = "xmrig" nocase
        $m4 = "kdevtmpfsi"
        $m5 = "kinsing"
        $m6 = "donate.v2.xmrig.com" nocase
    condition:
        any of them
}

rule SOS_Malicious_Dropper_Script {
    meta:
        severity = "warning"
        description = "Script descargador/ejecutor remoto sospechoso (curl/wget pipe sh o PowerShell encoded)"
    strings:
        $d1 = "curl -fsSL http" nocase
        $d2 = "| bash" nocase
        $d3 = "| sh" nocase
        $d4 = "powershell -enc" nocase
        $d5 = "Invoke-Expression" nocase
        $d6 = "FromBase64String(" nocase
    condition:
        ($d1 and ($d2 or $d3)) or ($d4) or ($d5 and $d6)
}

rule SOS_SVG_Embedded_XSS {
    meta:
        severity = "warning"
        description = "Imagen SVG con JavaScript activo embebido (riesgo de Stored XSS)"
    strings:
        $svg = "<svg" nocase
        $x1 = "<script" nocase
        $x2 = "javascript:" nocase
        $x3 = "onload=" nocase
        $x4 = "onerror=" nocase
    condition:
        $svg and any of ($x*)
}
"""

_compiled_rules = None


def _get_yara_rules():
    global _compiled_rules
    if _compiled_rules is None:
        compiler = yara_x.Compiler()
        compiler.add_source(YARA_RULES_SRC)
        _compiled_rules = compiler.build()
    return _compiled_rules


def _is_real_pe_executable(header_bytes: bytes) -> bool:
    if len(header_bytes) < 0x44 or header_bytes[:2] != b"MZ":
        return False
    try:
        pe_offset = struct.unpack("<I", header_bytes[0x3C:0x40])[0]
        if 0x40 <= pe_offset <= len(header_bytes) - 4:
            return header_bytes[pe_offset : pe_offset + 4] == b"PE\x00\x00"
    except Exception:
        pass
    return False


def _detect_magic_spoofing(head: bytes, declared_mime: str, orig_name: str) -> Optional[Tuple[str, str, str]]:
    """Verifica si el archivo binario real es un ejecutable ELF/PE disfrazado de documento/imagen."""
    mime_l = (declared_mime or "").lower()
    name_l = (orig_name or "").lower()

    if head.startswith(b"\x7fELF"):
        return (
            "SOS_Magic_Linux_ELF",
            "critical",
            f"Binario ejecutable Linux ELF almacenado en filestore ({orig_name or 'sin nombre'} • {declared_mime or 'mime desconocido'})",
        )

    if _is_real_pe_executable(head):
        # Si es un .exe/.dll camuflado como PDF/imagen/office -> crítico; si es ejecutable explícito -> warning
        safe_doc_claimed = any(x in mime_l for x in ("pdf", "image/", "word", "excel", "text/")) or name_l.endswith((".pdf", ".jpg", ".png", ".docx", ".xlsx"))
        if safe_doc_claimed:
            return (
                "SOS_Magic_Spoofed_PE_Exe",
                "critical",
                f"Ejecutable Windows PE (.exe/.dll) camuflado como '{orig_name}' ({declared_mime})",
            )
        return (
            "SOS_Magic_Windows_PE",
            "warning",
            f"Ejecutable Windows PE almacenado en adjuntos de Odoo ('{orig_name or 'adjunto'}')",
        )

    return None


def _load_attachment_metadata_map(inst: Dict[str, Any], db_name: str) -> Dict[str, Tuple[str, str]]:
    """Obtiene mapa store_fname -> (name, mimetype) desde ir_attachment de Odoo."""
    out: Dict[str, Tuple[str, str]] = {}
    try:
        rows = discovery._query_pg(
            inst,
            db_name,
            "SELECT store_fname, COALESCE(name, '') AS name, COALESCE(mimetype, '') AS mimetype "
            "FROM ir_attachment WHERE store_fname IS NOT NULL AND store_fname != '' "
            "ORDER BY id DESC LIMIT 15000",
        )
        for r in rows:
            sf = r.get("store_fname")
            if sf:
                out[sf] = (r.get("name") or "", r.get("mimetype") or "")
    except Exception:
        pass
    return out


def scan_all_filestores(max_age_days: int = 0) -> Dict[str, Any]:
    """Escanea los filestores de todas las BDs Odoo usando YARA-X + inspección de Magic Bytes."""
    if not _scan_lock.acquire(blocking=False):
        return {"ok": False, "message": "Ya hay un escaneo de filestore en ejecución."}

    run_id = storage.create_filestore_scan_run()
    scanned_dbs = 0
    scanned_files = 0
    threats_found = 0
    cutoff_mtime = (time.time() - (max_age_days * 86400)) if max_age_days > 0 else 0

    try:
        rules = _get_yara_rules()
        scanner = yara_x.Scanner(rules)
        client = docker.from_env()
        instances = discovery.discover_postgres_instances()
        dbs = discovery.discover_odoo_databases({})

        for db in dbs:
            dbname = str(db.get("name") or "")
            if not dbname or dbname.startswith("Error") or dbname.lower().startswith("tmp_"):
                continue

            pg_cname = db.get("pg_container") or ""
            inst = next((i for i in instances if i.get("container_name") == pg_cname), instances[0] if instances else None)
            fs_container_path = legacy_backups._find_filestore_dir(client, dbname, inst)
            if not fs_container_path or not os.path.isdir(fs_container_path):
                continue

            scanned_dbs += 1
            att_map = _load_attachment_metadata_map(inst, dbname) if inst else {}

            for root, _dirs, files in os.walk(fs_container_path):
                for fname in files:
                    full_p = os.path.join(root, fname)
                    try:
                        st = os.stat(full_p)
                        if not stat.S_ISREG(st.st_mode) or st.st_size == 0 or st.st_size > 25 * 1024 * 1024:
                            continue
                        if cutoff_mtime > 0 and st.st_mtime < cutoff_mtime:
                            continue

                        scanned_files += 1
                        rel_store = os.path.relpath(full_p, fs_container_path).replace("\\", "/")
                        orig_name, decl_mime = att_map.get(rel_store, ("", ""))

                        # Omitir assets internos compilados CSS/JS de Odoo web.assets_*
                        if orig_name.startswith("web.assets_") or decl_mime in ("text/css", "application/javascript") and orig_name.endswith((".css", ".js", ".map")):
                            continue

                        with open(full_p, "rb") as f:
                            head = f.read(4096)
                            # Leer archivo completo (hasta 25 MB) solo para escanear con YARA-X
                            f.seek(0)
                            data = f.read()

                        matched_rule = None
                        matched_sev = "warning"
                        matched_desc = ""

                        # 1. Magic Bytes Spoofing (ELF / PE)
                        spoof = _detect_magic_spoofing(head, decl_mime, orig_name)
                        if spoof:
                            matched_rule, matched_sev, matched_desc = spoof

                        # 2. Motor YARA-X (Rust nativo)
                        if not matched_rule:
                            yres = scanner.scan(data)
                            matching = list(yres.matching_rules)
                            if matching:
                                r0 = matching[0]
                                matched_rule = r0.identifier
                                meta_dict = dict(r0.metadata)
                                matched_sev = str(meta_dict.get("severity") or "critical")
                                matched_desc = str(meta_dict.get("description") or f"Coincidencia YARA-X: {matched_rule}")
                                if orig_name:
                                    matched_desc += f" (Adjunto: {orig_name})"

                        if matched_rule:
                            sha256_hex = hashlib.sha256(data).hexdigest()
                            logical_host_path = full_p[len("/hostfs"):] if full_p.startswith("/hostfs") else full_p
                            fid = storage.upsert_filestore_finding(
                                db_name=dbname,
                                store_fname=rel_store,
                                original_name=orig_name,
                                declared_mime=decl_mime,
                                host_path=logical_host_path,
                                sha256=sha256_hex,
                                size_bytes=int(st.st_size),
                                file_uid=int(st.st_uid),
                                file_gid=int(st.st_gid),
                                file_mode=int(stat.S_IMODE(st.st_mode)),
                                rule_name=matched_rule,
                                severity=matched_sev,
                                detail=matched_desc,
                            )
                            if fid is not None:
                                threats_found += 1
                    except Exception:
                        continue

        storage.finish_filestore_scan_run(run_id, scanned_dbs, scanned_files, threats_found, status="ok")
        if threats_found > 0:
            notifications.report_incident(
                incident_key="filestore:malware",
                kind="filestore_malware",
                severity="critical",
                target="odoo_filestore",
                title=f"Archivos sospechosos detectados en Filestore ({threats_found})",
                detail=f"Se detectaron {threats_found} adjuntos sospechosos en {scanned_dbs} bases Odoo.",
            )
        else:
            notifications.resolve_incident_if_open(
                "filestore:malware",
                "Filestore de Odoo limpio",
                f"Escaneados {scanned_files} archivos en {scanned_dbs} bases sin amenazas activas.",
            )

        return {
            "ok": True,
            "run_id": run_id,
            "scanned_dbs": scanned_dbs,
            "scanned_files": scanned_files,
            "threats_found": threats_found,
        }
    except Exception as exc:
        storage.finish_filestore_scan_run(run_id, scanned_dbs, scanned_files, threats_found, status="failed")
        return {"ok": False, "error": str(exc)}
    finally:
        _scan_lock.release()


def quarantine_finding(finding_id: int) -> Tuple[bool, str]:
    """Mueve de forma segura y reversible el archivo sospechoso fuera del filestore del host."""
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    rec = storage.get_filestore_finding(finding_id)
    if not rec:
        return False, "Hallazgo no encontrado."
    if rec["status"] == "quarantined":
        return False, "El archivo ya se encuentra en cuarentena."

    host_path = "/" + rec["host_path"].lstrip("/")
    hostfs_view = os.path.join("/hostfs", host_path.lstrip("/"))
    if not os.path.isfile(hostfs_view):
        storage.update_filestore_finding_status(finding_id, "deleted", "")
        return False, "El archivo ya no existe en el filestore."

    q_file = os.path.join(QUARANTINE_DIR, f"{finding_id}_{rec['sha256']}.quar")
    shutil.copy2(hostfs_view, q_file)
    os.chmod(q_file, 0o600)

    # Retirar del filestore del host vía nsenter mount namespace
    res = subprocess.run(
        ["nsenter", "-t", "1", "-m", "--", "/bin/rm", "-f", host_path],
        capture_output=True,
        text=True,
        timeout=8,
        check=False,
    )
    if res.returncode != 0:
        return False, f"No se pudo retirar el archivo del host: {(res.stderr or '').strip()[:160]}"

    storage.update_filestore_finding_status(finding_id, "quarantined", q_file)
    return True, f"Archivo aislado en cuarentena reversible ({rec['original_name'] or rec['store_fname']})."


def restore_quarantined_finding(finding_id: int) -> Tuple[bool, str]:
    """Restaura un archivo en cuarentena a su ubicación, permisos y propietario originales en el host."""
    rec = storage.get_filestore_finding(finding_id)
    if not rec:
        return False, "Registro no encontrado."
    q_file = rec.get("quarantine_path") or ""
    if rec["status"] != "quarantined" or not q_file or not os.path.isfile(q_file):
        return False, "No existe copia en cuarentena disponible para restaurar."

    host_path = "/" + rec["host_path"].lstrip("/")
    host_dir = os.path.dirname(host_path)
    uid = int(rec.get("file_uid") or 0)
    gid = int(rec.get("file_gid") or 0)
    mode_oct = oct(int(rec.get("file_mode") or 0o640))[2:]

    with open(q_file, "rb") as f:
        raw_bytes = f.read()

    # Crear directorio padre si hiciera falta, volcar contenido y restaurar uid:gid + permisos en el host
    subprocess.run(["nsenter", "-t", "1", "-m", "--", "/bin/mkdir", "-p", host_dir], check=False, timeout=5)
    p = subprocess.run(
        ["nsenter", "-t", "1", "-m", "--", "/usr/bin/tee", host_path],
        input=raw_bytes,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        timeout=15,
        check=False,
    )
    if p.returncode != 0:
        return False, f"Error restaurando archivo en host: {p.stderr.decode('utf-8', 'replace')[:160]}"

    subprocess.run(["nsenter", "-t", "1", "-m", "--", "/bin/chown", f"{uid}:{gid}", host_path], check=False, timeout=5)
    subprocess.run(["nsenter", "-t", "1", "-m", "--", "/bin/chmod", mode_oct, host_path], check=False, timeout=5)

    try:
        os.remove(q_file)
    except OSError:
        pass

    storage.update_filestore_finding_status(finding_id, "ignored", "")
    return True, f"Archivo restaurado intacto en '{host_path}' y marcado como excepción aprobada."
