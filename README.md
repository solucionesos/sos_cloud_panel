# SOS Cloud Control Panel

Panel de administración y monitoreo para infraestructura **Odoo** multi-instancia sobre **Docker**, **PostgreSQL** y **Nginx** (estilo Odoo.sh), con soporte de **Single Sign-On (SSO)** hacia Odoo 15, 16, 17 y 18.

---

## Características principales

- **Descubrimiento automático:**
  - Contenedores Docker Odoo y mapeo de puertos con dominios configurados en Nginx (`/etc/nginx/sites-enabled`).
  - Bases de datos Odoo en PostgreSQL (versión de Odoo, compañía, tamaño, `web.base.url` y usuarios internos).
- **SSO (Single Sign-On) hacia Odoo:** Acceso directo a cualquier base de datos y usuario mediante enlaces firmados con HMAC-SHA256 (`shared_addons/sos_sso_bridge`).
- **Monitoreo en tiempo real del servidor host:** CPU total y por núcleo, RAM/Swap, I/O de disco, almacenamiento por punto de montaje y top de procesos.
- **Gestión de contenedores y bases de datos:**
  - Estadísticas por contenedor (CPU, RAM, I/O), logs en vivo y reinicio.
  - Acciones sensibles protegidas (iniciar, detener, eliminar contenedores sin borrar volúmenes y `DROP DATABASE`) con re-autenticación por clave maestra, confirmación por nombre y bloqueo por IP tras intentos fallidos.
- **Backups bajo demanda:** Descarga de respaldos en formato `.dump` (`pg_dump -Fc`) o `.zip` completo (`dump.sql` + `manifest.json` + `filestore`).

---

## Despliegue en un nuevo servidor

### Requisitos previos
- Servidor Linux (Ubuntu/Debian) con **Docker** y **Docker Compose** (`docker compose`).
- Red Docker compartida con PostgreSQL y los contenedores Odoo (por defecto `odoo-net`).
- Nginx en el host (opcional, para publicar el panel con HTTPS y descubrir dominios).

### Instalación rápida

```bash
git clone https://github.com/solucionesos/sos_cloud_panel.git
cd sos_cloud_panel
chmod +x deploy.sh
./deploy.sh
```

El script `deploy.sh`:
1. Detecta automáticamente redes Docker y contenedores PostgreSQL existentes.
2. Genera `.env` con secretos aleatorios (`PANEL_SESSION_SECRET` y `SOS_SSO_SECRET`) y tus credenciales.
3. Construye e inicia el contenedor `sos_cloud_panel` conectado a la red Docker configurada.

### Publicar con Nginx + SSL

1. Copia `nginx.example.conf` a `/etc/nginx/sites-available/cloud.tudominio.com` y ajusta `server_name` (y el puerto si cambiaste `PANEL_PORT`).
2. Habilita el sitio y recarga Nginx:
   ```bash
   sudo ln -s /etc/nginx/sites-available/cloud.tudominio.com /etc/nginx/sites-enabled/
   sudo nginx -t && sudo systemctl reload nginx
   sudo certbot --nginx -d cloud.tudominio.com
   ```

### Habilitar SSO en contenedores Odoo (Automático)

`deploy.sh` ejecuta automáticamente `./setup_sso.sh`, el cual recorre cada contenedor Odoo en ejecución en el servidor y:
1. Copia `shared_addons/sos_sso_bridge` en su ruta de `addons_path` (en el host si es bind-mount, o dentro del contenedor).
2. Configura `sos_sso_secret` en su `odoo.conf` con el `SOS_SSO_SECRET` del panel.
3. Instala `sos_sso_bridge` en las bases de datos Odoo existentes donde aún no esté instalado y reinicia el contenedor si hubo cambios.

Si creas un nuevo contenedor Odoo más adelante, solo ejecuta:
```bash
./setup_sso.sh
```

---

## Actualización en cualquier servidor

```bash
cd /ruta/a/sos_cloud_panel
./deploy.sh --update
```

O manualmente:
```bash
git pull
docker compose up -d --build
```
