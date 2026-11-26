#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# SOS Cloud Control Panel - Script de Despliegue / Actualización
# Uso:
#   ./deploy.sh            # Modo interactivo (si no existe .env) o actualización
#   ./deploy.sh --update   # Solo git pull + reconstrucción de contenedor
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${GREEN}[SOS-PANEL]${NC} $*"; }
warn() { echo -e "${YELLOW}[AVISO]${NC} $*"; }
err()  { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# 1. Verificar dependencias
for cmd in docker openssl; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    err "No se encontró '$cmd'. Instálelo antes de continuar."
    exit 1
  fi
done

if docker compose version >/dev/null 2>&1; then
  COMPOSE_CMD="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE_CMD="docker-compose"
else
  err "No se encontró 'docker compose' ni 'docker-compose'."
  exit 1
fi

# Modo actualización rápida
if [[ "${1:-}" == "--update" ]]; then
  if [[ -d .git ]]; then
    log "Actualizando código desde Git..."
    git pull --ff-only
  fi
  log "Reconstruyendo y reiniciando contenedor..."
  $COMPOSE_CMD up -d --build
  log "Actualización completada."
  exit 0
fi

echo -e "${CYAN}"
echo "=========================================================="
echo "   SOS Cloud Control Panel - Despliegue en Servidor"
echo "=========================================================="
echo -e "${NC}"

# 2. Detectar entorno Docker y PostgreSQL existente
DETECTED_NET=$(docker network ls --format '{{.Name}}' | grep -E 'odoo|pg' | head -n 1 || true)
DETECTED_NET="${DETECTED_NET:-odoo-net}"

DETECTED_PG=$(docker ps --format '{{.Names}}' | grep -i 'postgres' | head -n 1 || true)
DETECTED_PG="${DETECTED_PG:-host.docker.internal}"

# 3. Configurar .env si no existe
if [[ -f .env ]]; then
  warn "Ya existe un archivo .env. Se conservarán sus valores actuales."
else
  log "Creando archivo .env a partir de .env.example..."

  read -rp "Usuario administrador del panel [admin]: " IN_USER
  IN_USER="${IN_USER:-admin}"

  read -rsp "Clave maestra del panel [generar aleatoria]: " IN_PASS
  echo ""
  if [[ -z "$IN_PASS" ]]; then
    IN_PASS="$(openssl rand -base64 16 | tr -dc 'A-Za-z0-9' | head -c 16)"
    warn "Clave maestra generada automáticamente: $IN_PASS"
  fi

  read -rp "Red Docker de Odoo/PostgreSQL [$DETECTED_NET]: " IN_NET
  IN_NET="${IN_NET:-$DETECTED_NET}"

  read -rp "Host o contenedor PostgreSQL [$DETECTED_PG]: " IN_PG_HOST
  IN_PG_HOST="${IN_PG_HOST:-$DETECTED_PG}"

  DEFAULT_PG_PORT="5432"
  if [[ "$IN_PG_HOST" == "host.docker.internal" ]]; then
    DEFAULT_PG_PORT="5433"
  fi
  read -rp "Puerto PostgreSQL [$DEFAULT_PG_PORT]: " IN_PG_PORT
  IN_PG_PORT="${IN_PG_PORT:-$DEFAULT_PG_PORT}"

  read -rp "Usuario PostgreSQL [odoo]: " IN_PG_USER
  IN_PG_USER="${IN_PG_USER:-odoo}"

  read -rsp "Contraseña PostgreSQL [odoo]: " IN_PG_PASS
  echo ""
  IN_PG_PASS="${IN_PG_PASS:-odoo}"

  read -rp "Dominio base por defecto [solucionesos.com]: " IN_DOMAIN
  IN_DOMAIN="${IN_DOMAIN:-solucionesos.com}"

  read -rp "Puerto local del panel [8095]: " IN_PORT
  IN_PORT="${IN_PORT:-8095}"

  SESSION_SECRET="$(openssl rand -hex 32)"
  SSO_SECRET="$(openssl rand -hex 32)"

  PROTECTED_LIST="sos_cloud_panel"
  if [[ "$IN_PG_HOST" != "host.docker.internal" ]]; then
    PROTECTED_LIST="sos_cloud_panel,$IN_PG_HOST"
  fi

  cat > .env <<EOF
# Generado por deploy.sh el $(date -u +"%Y-%m-%dT%H:%M:%SZ")
PANEL_ADMIN_USER=$IN_USER
PANEL_ADMIN_PASSWORD=$IN_PASS
PANEL_SESSION_SECRET=$SESSION_SECRET
SOS_SSO_SECRET=$SSO_SECRET

PG_HOST=$IN_PG_HOST
PG_PORT=$IN_PG_PORT
PG_USER=$IN_PG_USER
PG_PASSWORD=$IN_PG_PASS

DEFAULT_BASE_DOMAIN=$IN_DOMAIN
NGINX_SITES_PATH=/host_nginx/sites-enabled
PROTECTED_CONTAINERS=$PROTECTED_LIST

PANEL_CONTAINER_NAME=sos_cloud_panel
PANEL_BIND_IP=127.0.0.1
PANEL_PORT=$IN_PORT
DOCKER_NETWORK=$IN_NET
HOST_NGINX_SITES=/etc/nginx/sites-enabled
EOF
  chmod 600 .env
  log "Archivo .env creado con permisos 600."
fi

# Cargar variables de .env para validaciones
set -a
# shellcheck disable=SC1091
source .env
set +a

# 4. Verificar o crear red Docker externa
DOCKER_NETWORK="${DOCKER_NETWORK:-odoo-net}"
if ! docker network inspect "$DOCKER_NETWORK" >/dev/null 2>&1; then
  warn "La red Docker '$DOCKER_NETWORK' no existe."
  read -rp "¿Desea crear la red '$DOCKER_NETWORK' ahora? [s/N]: " CREATE_NET
  if [[ "${CREATE_NET,,}" == "s" || "${CREATE_NET,,}" == "y" ]]; then
    docker network create "$DOCKER_NETWORK"
    log "Red '$DOCKER_NETWORK' creada."
  else
    err "Cree la red o ajuste DOCKER_NETWORK en .env antes de levantar el servicio."
    exit 1
  fi
fi

# 5. Levantar el servicio
log "Construyendo e iniciando sos_cloud_panel..."
$COMPOSE_CMD up -d --build

echo ""
log "Despliegue finalizado correctamente."
echo -e "  • Panel escuchando en: ${CYAN}http://${PANEL_BIND_IP:-127.0.0.1}:${PANEL_PORT:-8095}${NC}"
echo -e "  • Red Docker:          ${CYAN}${DOCKER_NETWORK}${NC}"
echo -e "  • Nginx de ejemplo:    ${CYAN}${SCRIPT_DIR}/nginx.example.conf${NC}"
echo ""
warn "Para habilitar SSO en los contenedores Odoo de este servidor:"
echo "  1. Monte '${SCRIPT_DIR}/shared_addons' en el addons-path de sus contenedores Odoo."
echo "  2. Configure la misma variable de entorno SOS_SSO_SECRET en esos contenedores:"
echo -e "     ${CYAN}SOS_SSO_SECRET=${SOS_SSO_SECRET}${NC}"
