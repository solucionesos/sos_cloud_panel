"""Motor de Auto-Remediación ('Fix' en 1 Clic) para Incidentes y Controles de Salud, SSL, Nginx, Odoo y Disco."""
import glob
import json
import logging
import os
import re
import subprocess
import time
from typing import Any, Dict, List, Optional, Tuple

import dns.resolver
import docker

import discovery
import health_monitor
import notifications
import security_scanner
import storage

_logger = logging.getLogger("sos_remediation")

HOST_ENV = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "HOME": "/root",
    "DEBIAN_FRONTEND": "noninteractive",
}

WILDCARD_STATE_DIR = "/tmp/sos_certbot_wildcard"


def _host_run(cmd: List[str], timeout: int = 90, input_bytes: Optional[bytes] = None) -> Tuple[int, str, str]:
    full_cmd = ["nsenter", "-t", "1", "-m", "-u", "-n", "-i", "--"] + cmd
    try:
        res = subprocess.run(
            full_cmd,
            input=input_bytes,
            capture_output=True,
            timeout=timeout,
            env=HOST_ENV,
            check=False,
        )
        out = (res.stdout or b"").decode("utf-8", errors="replace").strip()
        err = (res.stderr or b"").decode("utf-8", errors="replace").strip()
        return res.returncode, out, err
    except subprocess.TimeoutExpired:
        return 124, "", f"Tiempo de espera agotado ({timeout}s)"
    except Exception as exc:
        return 1, "", str(exc)


# --- Diagnóstico Inteligente de Opciones de Remediación ---

def _find_certbot_renewal_info(domain: str) -> Dict[str, Any]:
    """Busca en /hostfs/etc/letsencrypt/renewal/*.conf qué certificado cubre este dominio y su método."""
    parts = domain.lower().split(".")
    wildcard_cand = "*." + ".".join(parts[1:]) if len(parts) >= 2 else ""

    exact_match = None
    wildcard_match = None

    for conf_path in sorted(glob.glob("/hostfs/etc/letsencrypt/renewal/*.conf")):
        cert_name = os.path.basename(conf_path)[:-5]
        try:
            with open(conf_path, "r", encoding="utf-8", errors="ignore") as f:
                txt = f.read()
        except Exception:
            continue
        auth_m = re.search(r"^\s*authenticator\s*=\s*(\S+)", txt, re.MULTILINE)
        authenticator = auth_m.group(1).strip() if auth_m else "unknown"

        # Revisar nombre del certificado o dominios cubiertos
        if cert_name.lower() == domain.lower():
            exact_match = {"cert_name": cert_name, "authenticator": authenticator, "is_wildcard": False}
            break
        if wildcard_cand and cert_name.lower() == ".".join(parts[1:]):
            wildcard_match = {
                "cert_name": cert_name,
                "base_domain": ".".join(parts[1:]),
                "wildcard_domain": wildcard_cand,
                "authenticator": authenticator,
                "is_wildcard": True,
            }

    return exact_match or wildcard_match or {"cert_name": "", "authenticator": "none", "is_wildcard": False}


def _find_related_containers_for_domain(domain: str) -> List[Dict[str, Any]]:
    """Encuentra contenedores (incluso detenidos) relacionados con un dominio por puerto Nginx o por nombre."""
    nginx_map = discovery.parse_nginx_domain_mapping()
    matched_ports = [p for p, doms in (nginx_map.get("port_to_domains") or {}).items() if domain in [d.lower() for d in doms]]
    sub = domain.split(".")[0].lower()

    out = []
    seen = set()
    try:
        client = docker.from_env()
        all_c = client.containers.list(all=True)
        # Primero por puerto activo o configuración HostConfig.PortBindings
        for c in all_c:
            if c.name == os.environ.get("PANEL_CONTAINER_NAME", "sos_cloud_panel"):
                continue
            pbindings = (c.attrs.get("HostConfig", {}).get("PortBindings") or {})
            bound_ports = []
            for _, binds in pbindings.items():
                for b in (binds or []):
                    hp = b.get("HostPort", "")
                    if str(hp).isdigit():
                        bound_ports.append(int(hp))
            name_l = c.name.lower()
            if any(p in bound_ports for p in matched_ports) or (len(sub) >= 3 and sub in name_l):
                if c.name not in seen:
                    seen.add(c.name)
                    out.append({"name": c.name, "status": c.status, "is_running": c.status == "running"})
    except Exception:
        pass
    return out


def diagnose_remediation(kind: str, target: str, control: str = "") -> Dict[str, Any]:
    """Devuelve las acciones 'Fix' ejecutables disponibles para un incidente o control específico."""
    actions: List[Dict[str, Any]] = []
    domain = target.strip().lower()
    nginx_map = discovery.parse_nginx_domain_mapping()
    explicit_nginx_domains = [d.lower() for d in (nginx_map.get("all_domains") or [])]

    # 1. Certificados SSL (incidente ssl_expiring / ssl_invalid o control SOS-TLS-01)
    if kind in ("ssl_expiring", "ssl_invalid") or control == "SOS-TLS-01":
        resolves = health_monitor._resolves_in_dns(domain)
        cert_info = _find_certbot_renewal_info(domain)

        if not resolves:
            actions.append({
                "action_id": "ignore_domain",
                "label": f"🔕 Excluir dominio sin DNS ({domain})",
                "style": "secondary",
                "description": f"El dominio '{domain}' ya no existe en DNS (NXDOMAIN). Excluirlo cerrará esta alerta y limpiará las métricas.",
                "params": {"domain": domain},
            })
        else:
            if cert_info.get("cert_name") and cert_info.get("authenticator") not in ("manual", "none"):
                actions.append({
                    "action_id": "ssl_renew_cert",
                    "label": f"🔄 Renovar Certificado '{cert_info['cert_name']}' Ahora (1-Clic)",
                    "style": "primary",
                    "description": f"Ejecuta 'certbot renew --cert-name {cert_info['cert_name']} --force-renewal' y recarga Nginx sin cortes.",
                    "params": {"cert_name": cert_info["cert_name"], "domain": domain},
                })

            if cert_info.get("is_wildcard") and cert_info.get("authenticator") == "manual":
                base_dom = cert_info["base_domain"]
                actions.append({
                    "action_id": "ssl_wildcard_wizard",
                    "label": f"🌐 Renovar Wildcard *.{base_dom} (Asistente DNS en 2 pasos)",
                    "style": "primary",
                    "description": f"El certificado actual '*.{base_dom}' es de tipo DNS manual. Este asistente genera aquí mismo el código TXT '_acme-challenge.{base_dom}', comprueba su propagación y renueva los 90 días para TODOS tus subdominios de una sola vez.",
                    "params": {"base_domain": base_dom, "domain": domain},
                })

            if domain in explicit_nginx_domains:
                actions.append({
                    "action_id": "ssl_issue_http01",
                    "label": f"⚡ Emitir SSL Individual Auto-Renovable para {domain}",
                    "style": "secondary" if actions else "primary",
                    "description": f"Como '{domain}' tiene su propio server_name en Nginx, Certbot puede instalarle un certificado propio por HTTP-01 que se renovará solo cada 60 días sin registros TXT.",
                    "params": {"domain": domain},
                })

    # 2. Servicio Caído (uptime_down)
    elif kind == "uptime_down":
        resolves = health_monitor._resolves_in_dns(domain)
        rel_containers = _find_related_containers_for_domain(domain)
        for rc in rel_containers:
            verb = "Reiniciar" if rc["is_running"] else "Encender"
            actions.append({
                "action_id": "uptime_restart_container",
                "label": f"🐳 {verb} contenedor '{rc['name']}' ({rc['status']})",
                "style": "primary",
                "description": f"Inicia o reinicia '{rc['name']}' y vuelve a comprobar si {domain} responde HTTP 200.",
                "params": {"container_name": rc["name"], "domain": domain},
            })
        actions.append({
            "action_id": "ignore_domain",
            "label": f"🔕 Dar de baja / Excluir '{domain}' del monitoreo",
            "style": "secondary" if rel_containers else "primary",
            "description": (
                f"'{domain}' no resuelve en DNS o corresponde a un proyecto antiguo apagado. "
                "Al excluirlo se cerrarán sus alertas activas (puedes reactivarlo cuando quieras)."
            ) if not resolves else f"Si '{domain}' está apagado intencionalmente, exclúyelo del monitor para mantener tus KPIs reales.",
            "params": {"domain": domain},
        })

    # 3. Espacio en Disco (disk_space)
    elif kind == "disk_space":
        actions.append({
            "action_id": "disk_cleanup",
            "label": "🧹 Limpiar caché Docker e historial systemd (Seguro)",
            "style": "primary",
            "description": "Elimina imágenes huérfanas de Docker, caché de compilación y reduce logs de journald a 7 días sin tocar volúmenes ni bases de datos.",
            "params": {"target": target},
        })

    # 4. Controles del Escáner de Seguridad por Dominio
    if control in ("SOS-HDR-HSTS", "SOS-HDR-NOSNIFF", "SOS-HDR-FRAME", "SOS-HDR-SRV"):
        actions.append({
            "action_id": "nginx_hardening",
            "label": "🛡️ Aplicar Hardening Global de Cabeceras en Nginx (1-Clic)",
            "style": "primary",
            "description": "Configura HSTS, X-Content-Type-Options (nosniff), X-Frame-Options (SAMEORIGIN), Referrer-Policy, oculta versión de Nginx (server_tokens off) y asegura atributos de cookies en /etc/nginx/conf.d/sos_security_hardening.conf validando antes con 'nginx -t'. ¡Mejora todos los dominios del servidor al instante!",
            "params": {"domain": domain},
        })

    elif control == "SOS-COOKIE-01":
        actions.append({
            "action_id": "nginx_hardening",
            "label": "🍪 Asegurar Cookies HttpOnly + Secure en Nginx y proxy_mode en Odoo",
            "style": "primary",
            "description": "Activa proxy_cookie_path seguro en Nginx y verifica 'proxy_mode = True' en el contenedor Odoo asociado.",
            "params": {"domain": domain, "also_odoo_proxy": True},
        })

    elif control == "SOS-TLS-02":
        if domain in explicit_nginx_domains:
            actions.append({
                "action_id": "https_redirect",
                "label": f"🔀 Activar Redirección HTTP → HTTPS en {domain}",
                "style": "primary",
                "description": f"Ejecuta Certbot Nginx para configurar redirección 301 hacia HTTPS en {domain}.",
                "params": {"domain": domain},
            })

    elif control == "SOS-ODOO-DBMGR":
        targets = health_monitor.discover_monitored_targets()
        t_obj = next((t for t in targets if t["domain"] == domain), None)
        cname = (t_obj or {}).get("container_name") or ""
        if not cname:
            rel = _find_related_containers_for_domain(domain)
            Odoo_rel = [r for r in rel if "odoo" in r["name"].lower()]
            cname = Odoo_rel[0]["name"] if Odoo_rel else ""

        if cname:
            warn_note = _check_odoo_dbfilter_warning(cname)
            actions.append({
                "action_id": "odoo_disable_list_db",
                "label": f"🔒 Desactivar gestor público (list_db = False) en '{cname}'",
                "style": "primary",
                "description": (
                    f"Establece 'list_db = False' y 'proxy_mode = True' en el odoo.conf de '{cname}' y reinicia ese contenedor. "
                    + (f"⚠️ AVISO: {warn_note}" if warn_note else "Compatible con su dbfilter actual.")
                ),
                "params": {"container_name": cname, "domain": domain},
            })

    elif control in ("SOS-DNS-SPF", "SOS-DNS-DMARC"):
        root_dom = security_scanner._extract_root_domain(domain)
        server_ip = _detect_public_ipv4()
        actions.append({
            "action_id": "dns_assistant",
            "label": f"📋 Generar registros DNS recomendados para {root_dom}",
            "style": "secondary",
            "description": f"Muestra los registros TXT exactos de SPF (IP {server_ip}) y DMARC listos para copiar en el proveedor DNS de {root_dom}.",
            "params": {"root_domain": root_dom, "server_ip": server_ip},
        })

    return {"ok": True, "kind": kind, "target": target, "control": control, "actions": actions}


def _detect_public_ipv4() -> str:
    try:
        import socket
        for info in socket.getaddrinfo(discovery.DEFAULT_BASE_DOMAIN, None, socket.AF_INET):
            return info[4][0]
    except Exception:
        pass
    return "TU_IP_SERVIDOR"


def _check_odoo_dbfilter_warning(container_name: str) -> str:
    try:
        client = docker.from_env()
        c = client.containers.get(container_name)
        res = c.exec_run(["cat", "/etc/odoo/odoo.conf"])
        if res.exit_code == 0:
            txt = res.output.decode("utf-8", errors="ignore")
            m = re.search(r"^\s*dbfilter\s*=\s*(.+)$", txt, re.MULTILINE)
            if m and ".*" in m.group(1):
                return f"Este contenedor usa 'dbfilter = {m.group(1).strip()}' (varias BDs bajo el mismo dominio); si ocultas list_db solo podrás elegir BD pasando ?db=nombre en la URL o desde nuestro botón SSO."
    except Exception:
        pass
    return ""


# --- Ejecutores Reales de cada Acción Fix ---

def execute_nginx_hardening(domain: str = "", also_odoo_proxy: bool = False) -> Tuple[bool, str]:
    host_nginx_conf = "/hostfs/etc/nginx/nginx.conf"
    has_active_server_tokens = False
    if os.path.isfile(host_nginx_conf):
        with open(host_nginx_conf, "r", encoding="utf-8", errors="ignore") as f:
            for ln in f:
                if re.match(r"^\s*server_tokens\s+", ln):
                    has_active_server_tokens = True
                    break

    lines = [
        "# Gestionado automáticamente por SOS Cloud Control Panel",
    ]
    if not has_active_server_tokens:
        lines.append("server_tokens off;")

    lines.extend([
        'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;',
        'add_header X-Content-Type-Options "nosniff" always;',
        'add_header X-Frame-Options "SAMEORIGIN" always;',
        'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
        'proxy_cookie_path / "/; HttpOnly; Secure; SameSite=Lax";',
        "",
    ])
    snippet_bytes = "\n".join(lines).encode("utf-8")

    target_conf = "/etc/nginx/conf.d/sos_security_hardening.conf"
    hostfs_target = "/hostfs" + target_conf
    prev_bytes = None
    if os.path.isfile(hostfs_target):
        with open(hostfs_target, "rb") as f:
            prev_bytes = f.read()

    code_w, _, err_w = _host_run(["/usr/bin/tee", target_conf], input_bytes=snippet_bytes)
    if code_w != 0:
        return False, f"No se pudo escribir {target_conf}: {err_w}"

    # Validar sintaxis de Nginx antes de recargar; si falla hacer rollback inmediato
    code_t, out_t, err_t = _host_run(["/usr/sbin/nginx", "-t"])
    if code_t != 0:
        if prev_bytes is not None:
            _host_run(["/usr/bin/tee", target_conf], input_bytes=prev_bytes)
        else:
            _host_run(["/bin/rm", "-f", target_conf])
        return False, f"Rollback aplicado porque 'nginx -t' reportó conflicto: {(err_t or out_t)[:220]}"

    code_r, _, err_r = _host_run(["/bin/systemctl", "reload", "nginx"])
    if code_r != 0:
        _host_run(["/usr/sbin/nginx", "-s", "reload"])

    if also_odoo_proxy and domain:
        targets = health_monitor.discover_monitored_targets()
        t_obj = next((t for t in targets if t["domain"] == domain), None)
        if t_obj and t_obj.get("container_name"):
            _upsert_odoo_conf_keys(t_obj["container_name"], {"proxy_mode": "True"})

    # Re-escanear el dominio solicitado (o todos en segundo plano si es global)
    if domain:
        targets = health_monitor.discover_monitored_targets()
        t_obj = next((t for t in targets if t["domain"] == domain), None)
        if t_obj:
            security_scanner.scan_single_target(t_obj)

    return True, "Hardening de cabeceras y cookies aplicado en Nginx ('nginx -t' OK y recargado sin cortes)."


def _upsert_odoo_conf_keys(container_name: str, updates: Dict[str, str]) -> Tuple[bool, str]:
    client = docker.from_env()
    c = client.containers.get(container_name)
    mounts = c.attrs.get("Mounts") or []

    # Detectar ruta de odoo.conf
    conf_path = "/etc/odoo/odoo.conf"
    args = (c.attrs.get("Config", {}).get("Entrypoint") or []) + (c.attrs.get("Config", {}).get("Cmd") or [])
    for i, a in enumerate(args):
        if a in ("-c", "--config") and i + 1 < len(args):
            conf_path = args[i + 1]
            break
        if str(a).startswith("--config="):
            conf_path = str(a).split("=", 1)[1]
            break

    res = c.exec_run(["cat", conf_path], user="root")
    if res.exit_code != 0:
        return False, f"No se pudo leer {conf_path} en {container_name}."

    lines = res.output.decode("utf-8", errors="replace").splitlines()
    remaining = dict(updates)
    new_lines = []
    for ln in lines:
        replaced = False
        for k, val in list(remaining.items()):
            if re.match(rf"^\s*{re.escape(k)}\s*=", ln):
                new_lines.append(f"{k} = {val}")
                remaining.pop(k)
                replaced = True
                break
        if not replaced:
            new_lines.append(ln)

    if remaining:
        out_lines = []
        inserted = False
        for ln in new_lines:
            out_lines.append(ln)
            if not inserted and ln.strip().lower() == "[options]":
                for k, val in remaining.items():
                    out_lines.append(f"{k} = {val}")
                inserted = True
        if not inserted:
            for k, val in remaining.items():
                out_lines.append(f"{k} = {val}")
        new_lines = out_lines

    final_bytes = ("\n".join(new_lines) + "\n").encode("utf-8")

    # Verificar si conf_path es un bind mount en el host para persistencia total
    host_bind = None
    c_norm = os.path.normpath(conf_path)
    for m in mounts:
        dest = os.path.normpath(m.get("Destination") or "")
        src = m.get("Source") or ""
        if dest and src and (c_norm == dest or c_norm.startswith(dest + "/")):
            rel = os.path.relpath(c_norm, dest)
            host_bind = src if rel == "." else os.path.join(src, rel)
            break

    if host_bind and os.path.isfile(os.path.join("/hostfs", host_bind.lstrip("/"))):
        _host_run(["/usr/bin/tee", host_bind], input_bytes=final_bytes)
    else:
        sock_exec = client.api.exec_create(c.id, ["tee", conf_path], user="root", stdin=True, stdout=True, stderr=True)["Id"]
        s = client.api.exec_start(sock_exec, socket=True)
        raw_s = getattr(s, "_sock", s)
        raw_s.sendall(final_bytes)
        raw_s.close()

    c.restart(timeout=12)
    time.sleep(4)
    return True, f"Configuración actualizada ({', '.join(f'{k}={v}' for k, v in updates.items())}) y contenedor '{container_name}' reiniciado."


def execute_odoo_disable_list_db(container_name: str, domain: str = "") -> Tuple[bool, str]:
    ok, msg = _upsert_odoo_conf_keys(container_name, {"list_db": "False", "proxy_mode": "True"})
    if ok and domain:
        targets = health_monitor.discover_monitored_targets()
        t_obj = next((t for t in targets if t["domain"] == domain), None)
        if t_obj:
            security_scanner.scan_single_target(t_obj)
    return ok, msg


def execute_ssl_renew_cert(cert_name: str, domain: str = "") -> Tuple[bool, str]:
    code, out, err = _host_run(
        ["/usr/bin/certbot", "renew", "--cert-name", cert_name, "--force-renewal", "--non-interactive"],
        timeout=120,
    )
    if code != 0:
        return False, f"Certbot reportó error renovando '{cert_name}': {(err or out)[-260:]}"

    _host_run(["/bin/systemctl", "reload", "nginx"])
    health_monitor.run_ssl_checks()
    if domain:
        targets = health_monitor.discover_monitored_targets()
        t_obj = next((t for t in targets if t["domain"] == domain), None)
        if t_obj:
            security_scanner.scan_single_target(t_obj)
    return True, f"Certificado '{cert_name}' renovado por 90 días y Nginx recargado."


def execute_ssl_issue_http01(domain: str) -> Tuple[bool, str]:
    code, out, err = _host_run(
        [
            "/usr/bin/certbot",
            "--nginx",
            "-d",
            domain,
            "--non-interactive",
            "--agree-tos",
            "--register-unsafely-without-email",
            "--redirect",
        ],
        timeout=120,
    )
    if code != 0:
        return False, f"Certbot HTTP-01 falló para '{domain}': {(err or out)[-260:]}"

    _host_run(["/bin/systemctl", "reload", "nginx"])
    health_monitor.run_ssl_checks()
    targets = health_monitor.discover_monitored_targets()
    t_obj = next((t for t in targets if t["domain"] == domain), None)
    if t_obj:
        security_scanner.scan_single_target(t_obj)
    return True, f"Certificado SSL auto-renovable instalado exitosamente en '{domain}'."


def execute_https_redirect(domain: str) -> Tuple[bool, str]:
    return execute_ssl_issue_http01(domain)


# --- Asistente Guiado Wildcard DNS-01 en 2 Pasos (sin SSH) ---

def start_wildcard_dns_challenge(base_domain: str) -> Dict[str, Any]:
    """Lanza Certbot manual DNS-01 en segundo plano en el host y captura los valores TXT requeridos."""
    clean_base = re.sub(r"[^a-z0-9.\-]", "", base_domain.lower().strip("."))
    if not clean_base or "." not in clean_base:
        return {"ok": False, "message": "Dominio base inválido."}

    # Limpiar sesión previa si existiera
    _host_run(["/bin/sh", "-c", f"rm -rf {WILDCARD_STATE_DIR} && mkdir -p {WILDCARD_STATE_DIR}"])

    auth_hook_script = f"""#!/bin/sh
echo "$CERTBOT_VALIDATION" >> {WILDCARD_STATE_DIR}/tokens.txt
i=0
while [ ! -f {WILDCARD_STATE_DIR}/continue ] && [ $i -lt 600 ]; do
    sleep 1
    i=$((i + 1))
done
if [ ! -f {WILDCARD_STATE_DIR}/continue ]; then
    exit 1
fi
sleep 2
"""
    cleanup_hook_script = f"""#!/bin/sh
rm -f {WILDCARD_STATE_DIR}/tokens.txt
"""
    _host_run(["/usr/bin/tee", f"{WILDCARD_STATE_DIR}/auth_hook.sh"], input_bytes=auth_hook_script.encode("utf-8"))
    _host_run(["/usr/bin/tee", f"{WILDCARD_STATE_DIR}/cleanup_hook.sh"], input_bytes=cleanup_hook_script.encode("utf-8"))
    _host_run(["/bin/chmod", "+x", f"{WILDCARD_STATE_DIR}/auth_hook.sh", f"{WILDCARD_STATE_DIR}/cleanup_hook.sh"])

    # Lanzar certbot en background en el host registrando su salida en certbot.log
    bg_cmd = (
        f"nohup /usr/bin/certbot certonly --manual --preferred-challenges dns "
        f"--manual-auth-hook {WILDCARD_STATE_DIR}/auth_hook.sh "
        f"--manual-cleanup-hook {WILDCARD_STATE_DIR}/cleanup_hook.sh "
        f"--non-interactive --agree-tos --manual-public-ip-logging-ok "
        f"--register-unsafely-without-email --force-renewal "
        f"--cert-name {clean_base} -d '*.{clean_base}' -d '{clean_base}' "
        f"> {WILDCARD_STATE_DIR}/certbot.log 2>&1 & echo $! > {WILDCARD_STATE_DIR}/pid"
    )
    _host_run(["/bin/sh", "-c", bg_cmd])

    # Esperar hasta 15s a que Let's Encrypt entregue el/los desafío(s) TXT
    tokens: List[str] = []
    tokens_file = f"/hostfs{WILDCARD_STATE_DIR}/tokens.txt"
    log_file = f"/hostfs{WILDCARD_STATE_DIR}/certbot.log"
    for _ in range(30):
        time.sleep(0.5)
        if os.path.isfile(tokens_file):
            with open(tokens_file, "r", encoding="utf-8") as f:
                vals = [ln.strip() for ln in f.splitlines() if ln.strip()]
            # Con -d *.dom -d dom, Certbot ejecuta el hook para el 1er dominio y espera;
            # si ambos comparten o requieren 2 tokens secuenciales, capturamos el actual
            if vals:
                tokens = vals
                break

    if not tokens:
        err_log = ""
        if os.path.isfile(log_file):
            with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
                err_log = f.read()[-300:]
        return {"ok": False, "message": f"Let's Encrypt no entregó desafío TXT: {err_log or 'verifique límite de intentos Let’s Encrypt.'}"}

    return {
        "ok": True,
        "base_domain": clean_base,
        "txt_host": f"_acme-challenge.{clean_base}",
        "txt_values": tokens,
        "step": 1,
        "message": f"Agregue el registro TXT en su proveedor DNS para '_acme-challenge.{clean_base}' con el valor indicado y luego pulse 'Verificar y Continuar'.",
    }


def _check_txt_propagated(txt_fqdn: str, expected_val: str) -> bool:
    for ns in ("8.8.8.8", "1.1.1.1"):
        try:
            res = dns.resolver.Resolver(configure=False)
            res.nameservers = [ns]
            res.lifetime = 3.0
            ans = res.resolve(txt_fqdn, "TXT")
            found = ["".join(s.decode("utf-8", "ignore") if isinstance(s, bytes) else str(s) for s in r.strings) for r in ans]
            if expected_val in found:
                return True
        except Exception:
            continue
    return False


def complete_wildcard_dns_challenge(base_domain: str, force: bool = False) -> Dict[str, Any]:
    clean_base = re.sub(r"[^a-z0-9.\-]", "", base_domain.lower().strip("."))
    tokens_file = f"/hostfs{WILDCARD_STATE_DIR}/tokens.txt"
    log_file = f"/hostfs{WILDCARD_STATE_DIR}/certbot.log"
    txt_fqdn = f"_acme-challenge.{clean_base}"

    if os.path.isfile(tokens_file):
        with open(tokens_file, "r", encoding="utf-8") as f:
            vals = [ln.strip() for ln in f.splitlines() if ln.strip()]
        if vals and not force:
            if not _check_txt_propagated(txt_fqdn, vals[-1]):
                return {
                    "ok": False,
                    "needs_wait": True,
                    "txt_host": txt_fqdn,
                    "txt_values": vals,
                    "message": f"El valor TXT aún no aparece propagado en DNS público (8.8.8.8 / 1.1.1.1). Espere 30–60 segundos y vuelva a pulsar.",
                }

    count_before = len(vals) if os.path.isfile(tokens_file) else 0
    # Liberar el hook actual creando 'continue' temporalmente; si Certbot pide un 2do token para el dominio raíz, quitamos continue tras 1.5s!
    _host_run(["/usr/bin/touch", f"{WILDCARD_STATE_DIR}/continue"])
    time.sleep(2.5)
    _host_run(["/bin/rm", "-f", f"{WILDCARD_STATE_DIR}/continue"])

    # Esperar si aparece un segundo token (para el par *.dominio + dominio) o si Certbot ya terminó!
    for _ in range(36):
        time.sleep(1.0)
        if os.path.isfile(tokens_file):
            with open(tokens_file, "r", encoding="utf-8") as f:
                now_vals = [ln.strip() for ln in f.splitlines() if ln.strip()]
            if len(now_vals) > count_before:
                return {
                    "ok": True,
                    "step": 2,
                    "second_token_required": True,
                    "base_domain": clean_base,
                    "txt_host": txt_fqdn,
                    "txt_values": [now_vals[-1]],
                    "message": "Paso 1 validado. Let's Encrypt solicita un 2do valor TXT para cubrir también el dominio raíz (agregue o reemplace el TXT con este nuevo valor y pulse 'Finalizar Renovación'):",
                }

        # Verificar si el proceso PID de certbot ya finalizó
        c_pid, out_pid, _ = _host_run(["/bin/sh", "-c", f"cat {WILDCARD_STATE_DIR}/pid 2>/dev/null"])
        if out_pid.strip().isdigit():
            c_alive, _, _ = _host_run(["/bin/kill", "-0", out_pid.strip()])
            if c_alive != 0:
                break

    log_txt = ""
    if os.path.isfile(log_file):
        with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
            log_txt = f.read()

    if "Successfully received certificate" in log_txt or "Congratulations!" in log_txt:
        _host_run(["/bin/systemctl", "reload", "nginx"])
        health_monitor.run_ssl_checks()
        return {
            "ok": True,
            "completed": True,
            "message": f"¡Certificado Wildcard '*.{clean_base}' renovado por 90 días, Nginx recargado y alertas SSL cerradas!",
        }

    return {
        "ok": False,
        "message": f"Certbot no pudo completar la validación: {log_txt[-320:].strip() or 'sin detalle'}",
    }


# --- Reparación de Uptime, Dominios Inactivos y Disco ---

def execute_uptime_restart_container(container_name: str, domain: str) -> Tuple[bool, str]:
    try:
        client = docker.from_env()
        c = client.containers.get(container_name)
        # Si pertenece a un proyecto docker-compose y su BD compañera está detenida, encenderla también
        proj = (c.attrs.get("Config", {}).get("Labels") or {}).get("com.docker.compose.project", "")
        if proj:
            for other in client.containers.list(all=True, filters={"label": f"com.docker.compose.project={proj}"}):
                if other.name != c.name and "postgres" in other.name.lower() and other.status != "running":
                    other.start()
                    time.sleep(2)

        if c.status == "running":
            c.restart(timeout=12)
        else:
            c.start()
        time.sleep(5)
        health_monitor.run_uptime_checks()
        return True, f"Contenedor '{container_name}' iniciado/reiniciado y sondeo de '{domain}' actualizado."
    except Exception as exc:
        return False, f"Error operando contenedor '{container_name}': {exc}"


def execute_ignore_inactive_domain(domain: str) -> Tuple[bool, str]:
    clean = health_monitor._clean_domain(domain)
    if not clean:
        return False, "Dominio inválido."
    health_monitor.add_ignored_domain(clean)
    # Cerrar incidentes abiertos de ese dominio inmediatamente
    storage.resolve_open_incident(f"uptime:{clean}", "Dominio excluido del monitoreo activo por el administrador.")
    storage.resolve_open_incident(f"ssl:{clean}", "Dominio excluido del monitoreo activo por el administrador.")
    return True, f"Dominio '{clean}' excluido del monitoreo y sus incidentes abiertos fueron cerrados."


def execute_restore_ignored_domain(domain: str) -> Tuple[bool, str]:
    clean = health_monitor._clean_domain(domain)
    health_monitor.remove_ignored_domain(clean)
    return True, f"Dominio '{clean}' reincorporado al monitoreo activo."


def execute_disk_cleanup() -> Tuple[bool, str]:
    _, out1, _ = _host_run(["/usr/bin/docker", "image", "prune", "-f"], timeout=60)
    _, out2, _ = _host_run(["/usr/bin/docker", "builder", "prune", "-f"], timeout=60)
    _, out3, _ = _host_run(["/usr/bin/journalctl", "--vacuum-time=7d"], timeout=30)
    health_monitor.run_host_threshold_checks()
    summary = " | ".join(x.splitlines()[-1] for x in (out1, out2, out3) if x.strip())
    return True, f"Limpieza completada ({summary or 'cachés depurados'})."
