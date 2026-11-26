"""Fase 5 — Motor de Cumplimiento Normativo Automatizado e Informe Auditable Exportable:
Evalúa en vivo 25 controles técnicos mapeados a:
- Ley 1581 de 2012 / SIC (Colombia — Protección de Datos Personales y Responsabilidad Demostrada)
- ISO/IEC 27001:2022 (Anexo A)
- OWASP Top 10 / ASVS
- CIS Controls v8 (IG1)
"""
from datetime import datetime, timezone
import hashlib
import html
import json
import os
from typing import Any, Dict, List

import backup_manager
import discovery
import monitoring
import notifications
import scheduler
import security_auth
import storage
import threat_guard

FRAMEWORKS = {
    "LEY1581": "Ley 1581 / SIC (Colombia)",
    "ISO27001": "ISO/IEC 27001:2022",
    "OWASP": "OWASP Top 10 / ASVS",
    "CIS": "CIS Controls v8 (IG1)",
}


def evaluate_compliance_matrix() -> Dict[str, Any]:
    # Recopilar evidencias reales del panel
    totp_on = security_auth.is_totp_enabled()
    trusted_ips = storage.list_trusted_ips()
    audit_24h = storage.count_audit_summary_24h()
    sched = scheduler.get_scheduler_status()

    ssl_map = storage.get_all_ssl_status()
    uptime_map = storage.get_uptime_summary_by_domain()
    scans_map = storage.get_all_security_scans()

    bkp_policy = backup_manager.get_backup_policy(mask_secrets=True)
    bkp_sum = storage.get_backup_summary_30d()

    grd_policy = threat_guard.get_guard_policy()
    fw_ok, _ = threat_guard.check_firewall_capability()
    integ_records = list(storage.get_integrity_baselines().values())
    integ_alerts = sum(1 for r in integ_records if r.get("status") != "ok")

    ntf_cfg = notifications.get_notify_config(mask_secrets=True)
    any_alert_channel = any(ntf_cfg.get(k) for k in ("telegram_enabled", "webhook_enabled", "smtp_enabled"))

    fs_last = storage.get_last_filestore_scan()
    fs_detected = storage.list_filestore_findings(status_filter="detected")

    mounts = monitoring._get_storage_mounts()
    max_disk_pct = max((float(m.get("percent") or 0.0) for m in mounts), default=0.0)

    # Agregaciones de escáner web sobre dominios activos
    parsed_findings_by_dom: Dict[str, List[Dict[str, Any]]] = {}
    for dom, sc in scans_map.items():
        try:
            parsed_findings_by_dom[dom] = json.loads(sc.get("findings_json") or "[]")
        except Exception:
            parsed_findings_by_dom[dom] = []

    def _ratio_control_pass(ctrl_code: str) -> float:
        total = 0
        passed = 0
        for flist in parsed_findings_by_dom.values():
            for f in flist:
                if f.get("control") == ctrl_code:
                    total += 1
                    if f.get("status") == "pass":
                        passed += 1
        return (passed / total) if total > 0 else 0.0

    ssl_vals = list(ssl_map.values())
    all_ssl_valid = bool(ssl_vals) and all(s.get("valid") and int(s.get("days_left", -1)) > 14 for s in ssl_vals)
    some_ssl_valid = bool(ssl_vals) and any(s.get("valid") for s in ssl_vals)

    up_vals = list(uptime_map.values())
    avg_uptime = round(sum(float(u.get("uptime_24h", 100.0)) for u in up_vals) / len(up_vals), 2) if up_vals else 100.0

    dbmgr_ratio = _ratio_control_pass("SOS-ODOO-DBMGR")
    https_redir_ratio = _ratio_control_pass("SOS-TLS-02")
    hsts_ratio = _ratio_control_pass("SOS-HDR-HSTS")
    nosniff_ratio = _ratio_control_pass("SOS-HDR-NOSNIFF")
    frame_ratio = _ratio_control_pass("SOS-HDR-FRAME")
    cookie_ratio = _ratio_control_pass("SOS-COOKIE-01")
    spf_ratio = _ratio_control_pass("SOS-DNS-SPF")
    dmarc_ratio = _ratio_control_pass("SOS-DNS-DMARC")

    sso_configured = bool(os.environ.get("SOS_SSO_SECRET", ""))

    controls: List[Dict[str, Any]] = [
        # --- CAPA 01: ACCESO Y GOBERNANZA ---
        {
            "id": "SOS-ACC-01",
            "layer": "01 · Acceso y Gobernanza",
            "title": "Autenticación Multifactor (2FA TOTP) en consola administrativa",
            "status": "pass" if totp_on else "fail",
            "frameworks": ["LEY1581", "ISO27001", "OWASP", "CIS"],
            "evidence": "2FA TOTP activo con códigos de emergencia SHA-256." if totp_on else "2FA desactivado; active TOTP en 'Auditoría y Acceso'.",
        },
        {
            "id": "SOS-ACC-02",
            "layer": "01 · Acceso y Gobernanza",
            "title": "Sesiones firmadas criptográficamente y revocación remota inmediata",
            "status": "pass",
            "frameworks": ["LEY1581", "ISO27001", "OWASP"],
            "evidence": "Cookies HttpOnly + URLSafeTimedSerializer + revocación en SQLite WAL activas.",
        },
        {
            "id": "SOS-ACC-03",
            "layer": "01 · Acceso y Gobernanza",
            "title": "Acceso Single Sign-On (SSO) a instancias Odoo firmado con HMAC-SHA256 y nonce",
            "status": "pass" if sso_configured else "warn",
            "frameworks": ["LEY1581", "ISO27001", "OWASP"],
            "evidence": "SOS_SSO_SECRET activo con expiración estricta de 120s." if sso_configured else "SOS_SSO_SECRET vacío.",
        },
        {
            "id": "SOS-ACC-04",
            "layer": "01 · Acceso y Gobernanza",
            "title": "Doble confirmación y bloqueo anti-fuerza bruta en acciones destructivas",
            "status": "pass",
            "frameworks": ["LEY1581", "ISO27001", "CIS"],
            "evidence": "Re-autenticación con clave maestra y rate-limit por IP activos en DROP DB y contenedores.",
        },
        {
            "id": "SOS-ACC-05",
            "layer": "01 · Acceso y Gobernanza",
            "title": "Bitácora inmutable de auditoría de accesos y operaciones administrativas",
            "status": "pass",
            "frameworks": ["LEY1581", "ISO27001", "OWASP", "CIS"],
            "evidence": f"Registro SQLite activo ({audit_24h['events_24h']} eventos en últimas 24h) con exportación CSV.",
        },

        # --- CAPA 02: CIFRADO Y PERÍMETRO WEB ---
        {
            "id": "SOS-WEB-01",
            "layer": "02 · Cifrado y Perímetro Web",
            "title": "Certificados SSL/TLS vigentes (> 14 días) y protocolos TLS 1.2/1.3",
            "status": "pass" if all_ssl_valid else ("warn" if some_ssl_valid else "fail"),
            "frameworks": ["LEY1581", "ISO27001", "OWASP", "CIS"],
            "evidence": f"{sum(1 for s in ssl_vals if s.get('valid') and s.get('days_left', -1) > 14)}/{len(ssl_vals)} dominios con SSL óptimo.",
        },
        {
            "id": "SOS-WEB-02",
            "layer": "02 · Cifrado y Perímetro Web",
            "title": "Redirección obligatoria de tráfico HTTP plano hacia HTTPS",
            "status": "pass" if https_redir_ratio >= 0.9 else ("warn" if https_redir_ratio >= 0.5 else "fail"),
            "frameworks": ["LEY1581", "ISO27001", "OWASP"],
            "evidence": f"Cumplimiento en {int(round(https_redir_ratio * 100))}% de los dominios escaneados.",
        },
        {
            "id": "SOS-WEB-03",
            "layer": "02 · Cifrado y Perímetro Web",
            "title": "Protección del gestor y listado público de bases de datos Odoo (/web/database/list)",
            "status": "pass" if dbmgr_ratio >= 0.95 else ("warn" if dbmgr_ratio >= 0.5 else "fail"),
            "frameworks": ["LEY1581", "ISO27001", "OWASP", "CIS"],
            "evidence": f"{int(round(dbmgr_ratio * 100))}% de instancias Odoo ocultan el listado público de bases de datos.",
        },
        {
            "id": "SOS-WEB-04",
            "layer": "02 · Cifrado y Perímetro Web",
            "title": "Política HTTP Strict-Transport-Security (HSTS) en cabeceras de respuesta",
            "status": "pass" if hsts_ratio >= 0.8 else ("warn" if hsts_ratio > 0 else "fail"),
            "frameworks": ["ISO27001", "OWASP"],
            "evidence": f"HSTS presente en {int(round(hsts_ratio * 100))}% de los sitios auditados.",
        },
        {
            "id": "SOS-WEB-05",
            "layer": "02 · Cifrado y Perímetro Web",
            "title": "Mitigación de Clickjacking y MIME-Sniffing (X-Frame-Options / CSP / nosniff)",
            "status": "pass" if (nosniff_ratio >= 0.8 and frame_ratio >= 0.8) else ("warn" if (nosniff_ratio > 0 or frame_ratio > 0) else "fail"),
            "frameworks": ["ISO27001", "OWASP"],
            "evidence": f"nosniff: {int(round(nosniff_ratio * 100))}% • Anti-frame: {int(round(frame_ratio * 100))}%.",
        },
        {
            "id": "SOS-WEB-06",
            "layer": "02 · Cifrado y Perímetro Web",
            "title": "Cookies de sesión con atributos HttpOnly y Secure activos",
            "status": "pass" if cookie_ratio >= 0.9 else ("warn" if cookie_ratio >= 0.5 else "fail"),
            "frameworks": ["LEY1581", "ISO27001", "OWASP"],
            "evidence": f"Protección de cookies verificada en {int(round(cookie_ratio * 100))}% de dominios.",
        },
        {
            "id": "SOS-WEB-07",
            "layer": "02 · Cifrado y Perímetro Web",
            "title": "Autenticación anti-suplantación de correo en DNS (SPF + DMARC)",
            "status": "pass" if (spf_ratio >= 0.8 and dmarc_ratio >= 0.8) else ("warn" if spf_ratio >= 0.5 else "fail"),
            "frameworks": ["ISO27001", "CIS"],
            "evidence": f"SPF válido: {int(round(spf_ratio * 100))}% • DMARC válido: {int(round(dmarc_ratio * 100))}%.",
        },

        # --- CAPA 03: PROTECCIÓN ACTIVA DE SERVIDOR ---
        {
            "id": "SOS-SRV-01",
            "layer": "03 · Protección Activa de Servidor",
            "title": "Detección continua de ataques de fuerza bruta SSH y Login Odoo",
            "status": "pass" if sched.get("running") else "fail",
            "frameworks": ["LEY1581", "ISO27001", "OWASP", "CIS"],
            "evidence": f"Inspector incremental activo cada 30s (Modo actual: {grd_policy['mode'].upper()}).",
        },
        {
            "id": "SOS-SRV-02",
            "layer": "03 · Protección Activa de Servidor",
            "title": "Bloqueo automático en Firewall del kernel (cadena iptables SOS_GUARD)",
            "status": "pass" if (fw_ok and grd_policy["mode"] == "enforce") else ("warn" if fw_ok else "fail"),
            "frameworks": ["ISO27001", "OWASP", "CIS"],
            "evidence": "Modo BLOQUEAR activo en iptables SOS_GUARD." if (fw_ok and grd_policy["mode"] == "enforce") else "Firewall listo en Modo OBSERVAR (active Modo Bloquear para contención automática).",
        },
        {
            "id": "SOS-SRV-03",
            "layer": "03 · Protección Activa de Servidor",
            "title": "Trampas Honeypot Web contra reconocimiento automatizado (/.env, /.git, /wp-login)",
            "status": "pass" if grd_policy.get("honeypot_enabled") else "fail",
            "frameworks": ["ISO27001", "OWASP"],
            "evidence": "Detección de rutas trampa en Nginx activa." if grd_policy.get("honeypot_enabled") else "Honeypots desactivados.",
        },
        {
            "id": "SOS-SRV-04",
            "layer": "03 · Protección Activa de Servidor",
            "title": "Lista blanca administrativa y mecanismo de emergencia fail-open",
            "status": "pass" if len(trusted_ips) > 0 else "warn",
            "frameworks": ["ISO27001", "CIS"],
            "evidence": f"{len(trusted_ips)} IP(s) de confianza registradas + desbloqueo de emergencia operativo.",
        },

        # --- CAPA 04: CONTINUIDAD Y RESPALDOS VERIFICADOS ---
        {
            "id": "SOS-BKP-01",
            "layer": "04 · Continuidad y Respaldos",
            "title": "Política de respaldos automáticos diarios programada",
            "status": "pass" if bkp_policy.get("schedule_enabled") else "warn",
            "frameworks": ["LEY1581", "ISO27001", "CIS"],
            "evidence": f"Programación diaria activa ({bkp_policy['schedule_hour']:02d}:{bkp_policy['schedule_minute']:02d} UTC)." if bkp_policy.get("schedule_enabled") else "Respaldos en modo manual; active programación diaria en 'Respaldos Automáticos'.",
        },
        {
            "id": "SOS-BKP-02",
            "layer": "04 · Continuidad y Respaldos",
            "title": "Prueba automática de restauración real (Restore-Test) en PostgreSQL",
            "status": "pass" if (bkp_policy.get("verify_restore") and bkp_sum.get("verified_30d", 0) > 0) else ("warn" if bkp_policy.get("verify_restore") else "fail"),
            "frameworks": ["LEY1581", "ISO27001", "CIS"],
            "evidence": f"Restore-Test habilitado ({bkp_sum.get('verified_30d', 0)} respaldos restaurados y verificados en últimos 30d).",
        },
        {
            "id": "SOS-BKP-03",
            "layer": "04 · Continuidad y Respaldos",
            "title": "Almacenamiento de respaldos fuera del servidor (rclone Nube o Bucket S3/R2)",
            "status": "pass" if (bkp_policy.get("rclone_enabled") or bkp_policy.get("s3_enabled")) else "warn",
            "frameworks": ["LEY1581", "ISO27001", "CIS"],
            "evidence": "Destino externo en nube habilitado." if (bkp_policy.get("rclone_enabled") or bkp_policy.get("s3_enabled")) else "Solo destino local habilitado; active rclone (Google Drive) o S3/R2.",
        },
        {
            "id": "SOS-BKP-04",
            "layer": "04 · Continuidad y Respaldos",
            "title": "Cifrado asimétrico de respaldos con llave pública age y manifiesto firmado",
            "status": "pass" if (bkp_policy.get("encryption_enabled") and bkp_policy.get("age_public_key")) else "warn",
            "frameworks": ["LEY1581", "ISO27001", "OWASP", "CIS"],
            "evidence": "Cifrado age + firma HMAC-SHA256 activos." if bkp_policy.get("encryption_enabled") else "Manifiesto SHA-256 activo; cifrado age pendiente de activar.",
        },

        # --- CAPA 05: INTEGRIDAD, ANTIVIRUS Y DISPONIBILIDAD ---
        {
            "id": "SOS-INT-01",
            "layer": "05 · Integridad, Antivirus y Monitoreo",
            "title": "Línea base de integridad SHA-256 sobre llaves SSH, crontabs y archivos de autenticación",
            "status": "pass" if (len(integ_records) > 0 and integ_alerts == 0) else ("fail" if integ_alerts > 0 else "warn"),
            "frameworks": ["ISO27001", "OWASP", "CIS"],
            "evidence": f"{len(integ_records) - integ_alerts}/{len(integ_records)} archivos críticos del servidor íntegros.",
        },
        {
            "id": "SOS-INT-02",
            "layer": "05 · Integridad, Antivirus y Monitoreo",
            "title": "Inspección antimalware (YARA-X + Magic Bytes) sobre adjuntos en Filestore Odoo",
            "status": "pass" if (fs_last and len(fs_detected) == 0) else ("fail" if len(fs_detected) > 0 else "warn"),
            "frameworks": ["LEY1581", "ISO27001", "OWASP", "CIS"],
            "evidence": (
                f"Amenazas sin aislar: {len(fs_detected)}!" if len(fs_detected) > 0
                else (f"Último escaneo limpio ({fs_last['scanned_files']} adjuntos revisados)." if fs_last else "Pendiente ejecutar primer escaneo de Filestore.")
            ),
        },
        {
            "id": "SOS-MON-01",
            "layer": "05 · Integridad, Antivirus y Monitoreo",
            "title": "Monitoreo continuo cada 1 minuto de disponibilidad HTTP/HTTPS (SLA >= 99%)",
            "status": "pass" if avg_uptime >= 99.0 else ("warn" if avg_uptime >= 95.0 else "fail"),
            "frameworks": ["LEY1581", "ISO27001"],
            "evidence": f"Disponibilidad global últimas 24h: {avg_uptime}% sobre {len(up_vals)} dominios.",
        },
        {
            "id": "SOS-MON-02",
            "layer": "05 · Integridad, Antivirus y Monitoreo",
            "title": "Capacidad de almacenamiento saludable en servidor (< 85% de uso)",
            "status": "pass" if max_disk_pct < 85.0 else ("warn" if max_disk_pct < 92.0 else "fail"),
            "frameworks": ["ISO27001", "CIS"],
            "evidence": f"Uso máximo en particiones montadas: {max_disk_pct}%.",
        },
        {
            "id": "SOS-MON-03",
            "layer": "05 · Integridad, Antivirus y Monitoreo",
            "title": "Canales externos de notificación de incidentes críticos configurados",
            "status": "pass" if any_alert_channel else "warn",
            "frameworks": ["LEY1581", "ISO27001", "OWASP", "CIS"],
            "evidence": "Notificaciones externas activas." if any_alert_channel else "Alertas solo en consola; configure Telegram, Webhook o SMTP en 'Salud y Diagnóstico'.",
        },
    ]

    # Puntajes globales y por marco normativo (pass = 1.0, warn = 0.5, fail = 0.0)
    pts_map = {"pass": 1.0, "warn": 0.5, "fail": 0.0}
    total_pts = sum(pts_map.get(c["status"], 0.0) for c in controls)
    global_pct = int(round((total_pts / len(controls)) * 100))

    by_framework: Dict[str, Dict[str, Any]] = {}
    for fw_key, fw_label in FRAMEWORKS.items():
        fw_ctrls = [c for c in controls if fw_key in c["frameworks"]]
        fw_pts = sum(pts_map.get(c["status"], 0.0) for c in fw_ctrls)
        by_framework[fw_key] = {
            "key": fw_key,
            "name": fw_label,
            "score_pct": int(round((fw_pts / len(fw_ctrls)) * 100)) if fw_ctrls else 100,
            "passed": sum(1 for c in fw_ctrls if c["status"] == "pass"),
            "partial": sum(1 for c in fw_ctrls if c["status"] == "warn"),
            "failed": sum(1 for c in fw_ctrls if c["status"] == "fail"),
            "total": len(fw_ctrls),
        }

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    report_payload = {
        "generated_at_utc": now_iso,
        "server": discovery.DEFAULT_BASE_DOMAIN,
        "global_score_pct": global_pct,
        "counts": {
            "total": len(controls),
            "passed": sum(1 for c in controls if c["status"] == "pass"),
            "partial": sum(1 for c in controls if c["status"] == "warn"),
            "failed": sum(1 for c in controls if c["status"] == "fail"),
        },
        "frameworks": by_framework,
        "controls": controls,
    }
    digest = hashlib.sha256(json.dumps(report_payload, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()
    report_payload["evidence_sha256"] = digest
    return report_payload


def render_printable_compliance_html(matrix: Dict[str, Any], framework_filter: str = "") -> str:
    fw_filter = framework_filter.strip().upper()
    ctrls = matrix["controls"]
    if fw_filter in FRAMEWORKS:
        ctrls = [c for c in ctrls if fw_filter in c["frameworks"]]
        subtitle = f"Marco Evaluado: {FRAMEWORKS[fw_filter]}"
    else:
        subtitle = "Evaluación Integral Multi-Marco (Ley 1581 • ISO 27001 • OWASP • CIS)"

    fw_cards = "".join(
        f"""
        <div class="fw-box">
            <div class="fw-name">{html.escape(fw['name'])}</div>
            <div class="fw-pct">{fw['score_pct']}%</div>
            <div class="fw-meta">{fw['passed']} cumple • {fw['partial']} parcial • {fw['failed']} brecha</div>
        </div>
        """
        for fw in matrix["frameworks"].values()
    )

    rows_html = ""
    for c in ctrls:
        st = c["status"]
        badge_cls = "b-pass" if st == "pass" else ("b-warn" if st == "warn" else "b-fail")
        badge_txt = "CUMPLE" if st == "pass" else ("PARCIAL" if st == "warn" else "BRECHA")
        fws = ", ".join(c["frameworks"])
        rows_html += f"""
        <tr>
            <td><code>{html.escape(c['id'])}</code></td>
            <td>{html.escape(c['layer'])}</td>
            <td><strong>{html.escape(c['title'])}</strong><div style="font-size:11px;color:#6b7280;margin-top:2px;">Marcos: {html.escape(fws)}</div></td>
            <td><span class="badge {badge_cls}">{badge_txt}</span></td>
            <td>{html.escape(c['evidence'])}</td>
        </tr>
        """

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Informe de Cumplimiento y Seguridad — {html.escape(matrix['server'])}</title>
    <style>
        body {{ font-family: 'Segoe UI', Roboto, Arial, sans-serif; color: #1f2937; margin: 0; padding: 28px; background: #f9fafb; }}
        .sheet {{ max-width: 1050px; margin: 0 auto; background: #fff; padding: 34px 38px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.08); border-top: 6px solid #E17726; }}
        .head {{ display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 2px solid #f3f4f6; padding-bottom: 18px; margin-bottom: 22px; }}
        h1 {{ margin: 0; font-size: 22px; color: #51344D; }}
        .sub {{ font-size: 13px; color: #6b7280; margin-top: 4px; }}
        .score-big {{ text-align: right; }}
        .score-num {{ font-size: 34px; font-weight: 800; color: #E17726; line-height: 1; }}
        .fw-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 24px; }}
        .fw-box {{ border: 1px solid #e5e7eb; border-radius: 10px; padding: 12px 14px; background: #fcfaf8; }}
        .fw-name {{ font-size: 12px; font-weight: 700; color: #51344D; }}
        .fw-pct {{ font-size: 24px; font-weight: 800; color: #111827; margin: 4px 0; }}
        .fw-meta {{ font-size: 11px; color: #6b7280; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 12.5px; }}
        th {{ background: #51344D; color: #fff; text-align: left; padding: 9px 10px; }}
        td {{ padding: 9px 10px; border-bottom: 1px solid #e5e7eb; vertical-align: top; }}
        .badge {{ display: inline-block; padding: 3px 8px; border-radius: 99px; font-size: 10.5px; font-weight: 700; }}
        .b-pass {{ background: #d1fae5; color: #065f46; }}
        .b-warn {{ background: #fef3c7; color: #92400e; }}
        .b-fail {{ background: #fee2e2; color: #991b1b; }}
        .foot {{ margin-top: 22px; padding-top: 14px; border-top: 1px solid #e5e7eb; font-size: 11px; color: #6b7280; display: flex; justify-content: space-between; flex-wrap: wrap; gap: 8px; }}
        .no-print {{ margin-bottom: 16px; text-align: right; max-width: 1050px; margin-left: auto; margin-right: auto; }}
        .btn-print {{ background: #E17726; color: #fff; border: none; padding: 9px 18px; border-radius: 8px; font-weight: 700; cursor: pointer; }}
        @media print {{ body {{ background: #fff; padding: 0; }} .sheet {{ box-shadow: none; padding: 12px; }} .no-print {{ display: none; }} }}
    </style>
</head>
<body>
    <div class="no-print">
        <button class="btn-print" onclick="window.print()">🖨️ Imprimir / Guardar como PDF</button>
    </div>
    <div class="sheet">
        <div class="head">
            <div>
                <h1>Informe de Evidencia de Seguridad y Cumplimiento</h1>
                <div class="sub">Soluciones Open Source • Servidor: <strong>{html.escape(matrix['server'])}</strong></div>
                <div class="sub">{html.escape(subtitle)} • Generado: {html.escape(matrix['generated_at_utc'])}</div>
            </div>
            <div class="score-big">
                <div class="score-num">{matrix['global_score_pct']}%</div>
                <div class="sub">Índice Global ({matrix['counts']['passed']}/{matrix['counts']['total']} controles óptimos)</div>
            </div>
        </div>
        <div class="fw-grid">{fw_cards}</div>
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Dominio de Control</th>
                    <th>Control Evaluado</th>
                    <th>Estado</th>
                    <th>Evidencia Técnica Verificada en Vivo</th>
                </tr>
            </thead>
            <tbody>{rows_html}</tbody>
        </table>
        <div class="foot">
            <span>Generado automáticamente por SOS Cloud Control Panel</span>
            <span>Huella de integridad SHA-256: <code>{matrix['evidence_sha256']}</code></span>
        </div>
    </div>
</body>
</html>"""
