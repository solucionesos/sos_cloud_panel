#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# SOS Cloud Control Panel - Configurador Automático de SSO en Contenedores Odoo
#
# Para cada contenedor Odoo en ejecución:
#   1. Detecta su archivo odoo.conf y su ruta de addons personalizados.
#   2. Copia shared_addons/sos_sso_bridge (en el host si es bind-mount, o docker cp).
#   3. Configura sos_sso_secret en odoo.conf con el SOS_SSO_SECRET de .env.
#   4. Instala sos_sso_bridge en las BDs Odoo donde aún no esté instalado.
#   5. Reinicia el contenedor solo si hubo cambios.
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${GREEN}[SOS-SSO]${NC} $*"; }
warn() { echo -e "${YELLOW}[AVISO]${NC} $*"; }
err()  { echo -e "${RED}[ERROR]${NC} $*" >&2; }

if [[ ! -f .env ]]; then
  err "No se encontró .env en $SCRIPT_DIR. Ejecute primero ./deploy.sh"
  exit 1
fi

set -a
# shellcheck disable=SC1091
source .env
set +a

if [[ -z "${SOS_SSO_SECRET:-}" ]]; then
  err "SOS_SSO_SECRET está vacío en .env."
  exit 1
fi

BRIDGE_SRC="${SCRIPT_DIR}/shared_addons/sos_sso_bridge"
if [[ ! -d "$BRIDGE_SRC" ]]; then
  err "No se encontró $BRIDGE_SRC"
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  err "Se requiere python3 en el host para inspeccionar los contenedores Docker."
  exit 1
fi

log "Buscando contenedores Odoo en ejecución para configurar SSO automáticamente..."

# Delegamos la inspección y orquestación precisa a Python usando docker CLI
python3 - "$SCRIPT_DIR" "$SOS_SSO_SECRET" <<'PYEOF'
import json
import os
import re
import shutil
import subprocess
import sys

script_dir = sys.argv[1]
sso_secret = sys.argv[2]
bridge_src = os.path.join(script_dir, "shared_addons", "sos_sso_bridge")


def run(cmd, check=True, capture=True):
    return subprocess.run(
        cmd,
        check=check,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )


def docker_exec(cname, cmd_list, user="root"):
    return run(["docker", "exec", "-u", user, cname] + cmd_list, check=False)


def find_host_path(mounts, container_path):
    """Si container_path vive dentro de un bind mount del host, devuelve la ruta equivalente en el host."""
    cpath = os.path.normpath(container_path)
    best_match = None
    best_len = -1
    for m in mounts:
        if m.get("Type") not in ("bind", None):
            continue
        dest = os.path.normpath(m.get("Destination") or "")
        src = m.get("Source") or ""
        if not dest or not src:
            continue
        if cpath == dest or cpath.startswith(dest + os.sep):
            if len(dest) > best_len:
                rel = os.path.relpath(cpath, dest)
                best_match = src if rel == "." else os.path.join(src, rel)
                best_len = len(dest)
    return best_match


def detect_odoo_conf(cname, args_list):
    for i, arg in enumerate(args_list):
        if arg in ("-c", "--config") and i + 1 < len(args_list):
            return args_list[i + 1]
        if arg.startswith("--config="):
            return arg.split("=", 1)[1]
    for candidate in ("/etc/odoo/odoo.conf", "/etc/odoo/openerp-server.conf"):
        res = docker_exec(cname, ["test", "-f", candidate])
        if res.returncode == 0:
            return candidate
    return ""


def detect_odoo_bin(cname, entrypoint, cmd_args):
    for token in (entrypoint or []) + (cmd_args or []):
        if "odoo" in token and (token.endswith("odoo") or token.endswith("odoo-bin")):
            res = docker_exec(cname, ["test", "-x", token])
            if res.returncode == 0:
                return token
    for candidate in ("/usr/bin/odoo", "/opt/odoo/odoo-bin", "odoo"):
        res = docker_exec(cname, ["which", candidate])
        if res.returncode == 0 and res.stdout.strip():
            return res.stdout.strip()
    return "odoo"


def pick_addons_dir(cname, conf_text, mounts):
    m = re.search(r"^\s*addons_path\s*=\s*(.+)$", conf_text, re.MULTILINE)
    candidates = []
    if m:
        for p in m.group(1).split(","):
            p = p.strip()
            if p and "/usr/lib/python" not in p and "/dist-packages/" not in p and "/site-packages/" not in p:
                candidates.append(p)
    # Fallback a mounts conocidos
    for mt in mounts:
        dest = mt.get("Destination") or ""
        if "addon" in dest.lower() and dest not in candidates:
            candidates.append(dest)
    for cpath in candidates:
        if docker_exec(cname, ["test", "-d", cpath]).returncode == 0:
            return cpath
    return candidates[0] if candidates else "/mnt/extra-addons"


def upsert_sso_secret_in_conf(conf_text, secret):
    lines = conf_text.splitlines()
    found = False
    changed = False
    new_lines = []
    for line in lines:
        if re.match(r"^\s*sos_sso_secret\s*=", line):
            found = True
            current = line.split("=", 1)[1].strip()
            if current != secret:
                new_lines.append(f"sos_sso_secret = {secret}")
                changed = True
            else:
                new_lines.append(line)
        else:
            new_lines.append(line)

    if not found:
        changed = True
        # Insertar bajo [options] si existe, o al final
        inserted = False
        out_lines = []
        for line in new_lines:
            out_lines.append(line)
            if not inserted and line.strip().lower() == "[options]":
                out_lines.append(f"sos_sso_secret = {secret}")
                inserted = True
        if not inserted:
            out_lines.append(f"sos_sso_secret = {secret}")
        new_lines = out_lines

    return "\n".join(new_lines) + "\n", changed


def list_odoo_dbs_for_container(cname, odoo_bin, conf_path):
    """Lista las BDs accesibles desde el contenedor Odoo usando su propia configuración."""
    py_code = (
        "import odoo, sys; "
        f"odoo.tools.config.parse_config(['-c', '{conf_path}']); "
        "import psycopg2; "
        "c = odoo.tools.config; "
        "conn = psycopg2.connect(host=c['db_host'] or 'localhost', port=int(c['db_port'] or 5432), "
        "user=c['db_user'] or 'odoo', password=c['db_password'] or '', dbname='postgres'); "
        "cur = conn.cursor(); "
        "cur.execute(\"SELECT datname FROM pg_database WHERE datistemplate=false AND datname!='postgres'\"); "
        "dbs = [r[0] for r in cur.fetchall()]; conn.close(); "
        "out = []; "
        "\nfor d in dbs:\n"
        "  try:\n"
        "    cn = psycopg2.connect(host=c['db_host'] or 'localhost', port=int(c['db_port'] or 5432), "
        "user=c['db_user'] or 'odoo', password=c['db_password'] or '', dbname=d)\n"
        "    cr = cn.cursor()\n"
        "    cr.execute(\"SELECT state FROM ir_module_module WHERE name='sos_sso_bridge' LIMIT 1\")\n"
        "    row = cr.fetchone()\n"
        "    out.append((d, row[0] if row else 'missing'))\n"
        "    cn.close()\n"
        "  except Exception:\n"
        "    pass\n"
        "import json; print(json.dumps(out))"
    )
    res = docker_exec(cname, ["python3", "-c", py_code], user="odoo")
    if res.returncode != 0:
        res = docker_exec(cname, ["python3", "-c", py_code], user="root")
    if res.returncode != 0:
        return []
    try:
        return json.loads(res.stdout.strip().splitlines()[-1])
    except Exception:
        return []


ps = run(["docker", "ps", "--format", "{{.Names}}"])
containers = [x.strip() for x in ps.stdout.splitlines() if x.strip()]

odoo_found = 0
for cname in containers:
    insp_raw = run(["docker", "inspect", cname]).stdout
    insp = json.loads(insp_raw)[0]
    image = (insp.get("Config", {}).get("Image") or "").lower()
    if "odoo" not in image and "odoo" not in cname.lower():
        continue
    if cname == os.environ.get("PANEL_CONTAINER_NAME", "sos_cloud_panel"):
        continue

    odoo_found += 1
    print(f"\n\033[0;36m[Contenedor Odoo]\033[0m {cname} ({image})")
    mounts = insp.get("Mounts") or []
    cfg = insp.get("Config") or {}
    args_list = (cfg.get("Entrypoint") or []) + (cfg.get("Cmd") or [])
    conf_path = detect_odoo_conf(cname, args_list)
    if not conf_path:
        print("  ! No se detectó odoo.conf; omitiendo.")
        continue

    conf_res = docker_exec(cname, ["cat", conf_path])
    if conf_res.returncode != 0:
        print(f"  ! No se pudo leer {conf_path}; omitiendo.")
        continue

    conf_text = conf_res.stdout
    addons_dir = pick_addons_dir(cname, conf_text, mounts)
    needs_restart = False

    # 1. Copiar sos_sso_bridge a addons_dir
    host_addons = find_host_path(mounts, addons_dir)
    target_bridge = os.path.join(host_addons, "sos_sso_bridge") if host_addons else None
    if host_addons and os.path.isdir(host_addons):
        existed = os.path.exists(target_bridge)
        if existed:
            shutil.rmtree(target_bridge)
        shutil.copytree(bridge_src, target_bridge)
        print(f"  ✓ Módulo sos_sso_bridge copiado en host: {target_bridge}")
        if not existed:
            needs_restart = True
    else:
        existed = docker_exec(cname, ["test", "-d", f"{addons_dir}/sos_sso_bridge"]).returncode == 0
        docker_exec(cname, ["mkdir", "-p", addons_dir])
        run(["docker", "cp", bridge_src, f"{cname}:{addons_dir}/"])
        docker_exec(cname, ["chown", "-R", "odoo:odoo", f"{addons_dir}/sos_sso_bridge"])
        print(f"  ✓ Módulo sos_sso_bridge copiado al contenedor: {addons_dir}/sos_sso_bridge")
        if not existed:
            needs_restart = True

    # 2. Configurar sos_sso_secret en odoo.conf
    new_conf, conf_changed = upsert_sso_secret_in_conf(conf_text, sso_secret)
    if conf_changed:
        host_conf = find_host_path(mounts, conf_path)
        if host_conf and os.path.isfile(host_conf):
            with open(host_conf, "w", encoding="utf-8") as f:
                f.write(new_conf)
            print(f"  ✓ sos_sso_secret actualizado en {host_conf}")
        else:
            p = subprocess.run(
                ["docker", "exec", "-i", "-u", "root", cname, "tee", conf_path],
                input=new_conf,
                text=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            if p.returncode == 0:
                print(f"  ✓ sos_sso_secret actualizado en {cname}:{conf_path}")
            else:
                print(f"  ! Error escribiendo {conf_path}: {p.stderr.strip()}")
        needs_restart = True
    else:
        print("  ✓ sos_sso_secret ya estaba configurado en odoo.conf")

    # 3. Instalar sos_sso_bridge en BDs existentes donde no esté instalado
    odoo_bin = detect_odoo_bin(cname, cfg.get("Entrypoint"), cfg.get("Cmd"))
    dbs = list_odoo_dbs_for_container(cname, odoo_bin, conf_path)
    for dbname, state in dbs:
        if state == "installed":
            print(f"  ✓ BD '{dbname}': sos_sso_bridge ya instalado")
            continue
        print(f"  → Instalando sos_sso_bridge en BD '{dbname}'...")
        inst_res = docker_exec(
            cname,
            [odoo_bin, "-c", conf_path, "-d", dbname, "-i", "sos_sso_bridge", "--stop-after-init", "--no-http"],
            user="odoo",
        )
        if inst_res.returncode == 0:
            print(f"  ✓ BD '{dbname}': sos_sso_bridge instalado correctamente")
            needs_restart = True
        else:
            print(f"  ! Error instalando en '{dbname}': {inst_res.stderr[-300:] if inst_res.stderr else 'exit ' + str(inst_res.returncode)}")

    if needs_restart:
        print(f"  ↻ Reiniciando contenedor {cname} para aplicar cambios...")
        run(["docker", "restart", cname])
        print(f"  ✓ {cname} reiniciado.")

if odoo_found == 0:
    print("No se encontraron contenedores Odoo en ejecución.")
PYEOF

log "Configuración automática de SSO finalizada."
