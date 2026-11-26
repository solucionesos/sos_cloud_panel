"""Sistema de notificaciones multi-canal (Telegram, Webhook/n8n, SMTP) y gestión de incidentes."""
from email.message import EmailMessage
import hashlib
import hmac
import json
import logging
import os
import smtplib
import ssl
import time
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Tuple

import storage

_logger = logging.getLogger("sos_notifications")

SETTING_KEY = "notify_channels_config"
DEFAULT_CONFIG: Dict[str, Any] = {
    "server_label": os.environ.get("DEFAULT_BASE_DOMAIN", "solucionesos.com"),
    "telegram_enabled": False,
    "telegram_bot_token": "",
    "telegram_chat_id": "",
    "webhook_enabled": False,
    "webhook_url": "",
    "webhook_secret": "",
    "smtp_enabled": False,
    "smtp_host": "",
    "smtp_port": 587,
    "smtp_user": "",
    "smtp_password": "",
    "smtp_from": "",
    "smtp_to": "",
    "smtp_tls": True,
    "disk_alert_threshold": 85,
}


def get_notify_config(mask_secrets: bool = False) -> Dict[str, Any]:
    raw = storage.get_setting(SETTING_KEY, "")
    cfg = dict(DEFAULT_CONFIG)
    if raw:
        try:
            saved = json.loads(raw)
            if isinstance(saved, dict):
                cfg.update(saved)
        except Exception:
            pass
    if mask_secrets:
        for secret_field in ("telegram_bot_token", "webhook_secret", "smtp_password"):
            val = str(cfg.get(secret_field) or "")
            if val:
                cfg[secret_field] = ("••••••••" + val[-4:]) if len(val) > 6 else "••••••••"
    return cfg


def save_notify_config(incoming: Dict[str, Any]) -> Dict[str, Any]:
    current = get_notify_config(mask_secrets=False)
    for k in DEFAULT_CONFIG:
        if k not in incoming:
            continue
        val = incoming[k]
        # Si viene enmascarado con •••• conservar el valor previo guardado
        if k in ("telegram_bot_token", "webhook_secret", "smtp_password") and isinstance(val, str) and val.startswith("••••"):
            continue
        if isinstance(DEFAULT_CONFIG[k], bool):
            current[k] = bool(val)
        elif isinstance(DEFAULT_CONFIG[k], int):
            try:
                current[k] = int(val)
            except (ValueError, TypeError):
                pass
        else:
            current[k] = str(val or "").strip()

    current["disk_alert_threshold"] = max(50, min(98, int(current.get("disk_alert_threshold", 85))))
    storage.set_setting(SETTING_KEY, json.dumps(current))
    return get_notify_config(mask_secrets=True)


def _send_telegram(cfg: Dict[str, Any], text: str) -> None:
    token = cfg.get("telegram_bot_token", "").strip()
    chat_id = cfg.get("telegram_chat_id", "").strip()
    if not token or not chat_id:
        raise RuntimeError("Falta token o chat_id de Telegram.")
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = urllib.parse.urlencode({
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": "true",
    }).encode("utf-8")
    req = urllib.request.Request(url, data=payload, method="POST")
    with urllib.request.urlopen(req, timeout=8) as resp:
        if resp.status >= 400:
            raise RuntimeError(f"Telegram HTTP {resp.status}")


def _send_webhook(cfg: Dict[str, Any], event_payload: Dict[str, Any]) -> None:
    url = cfg.get("webhook_url", "").strip()
    if not url:
        raise RuntimeError("Falta URL de Webhook.")
    body = json.dumps(event_payload, ensure_ascii=False).encode("utf-8")
    headers = {"Content-Type": "application/json; charset=utf-8", "User-Agent": "SOS-Cloud-Panel/2.0"}
    secret = cfg.get("webhook_secret", "").strip()
    if secret:
        sig = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
        headers["X-SOS-Signature"] = f"sha256={sig}"
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=8) as resp:
        if resp.status >= 400:
            raise RuntimeError(f"Webhook HTTP {resp.status}")


def _send_smtp(cfg: Dict[str, Any], subject: str, body_text: str) -> None:
    host = cfg.get("smtp_host", "").strip()
    port = int(cfg.get("smtp_port") or 587)
    to_addr = cfg.get("smtp_to", "").strip()
    from_addr = cfg.get("smtp_from", "").strip() or cfg.get("smtp_user", "").strip()
    if not host or not to_addr or not from_addr:
        raise RuntimeError("Configuración SMTP incompleta (host, remitente o destinatario).")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg.set_content(body_text)

    user = cfg.get("smtp_user", "").strip()
    pwd = cfg.get("smtp_password", "")

    if port == 465:
        ctx = ssl.create_default_context()
        with smtplib.SMTP_SSL(host, port, timeout=10, context=ctx) as server:
            if user:
                server.login(user, pwd)
            server.send_message(msg)
    else:
        with smtplib.SMTP(host, port, timeout=10) as server:
            if cfg.get("smtp_tls", True):
                server.starttls(context=ssl.create_default_context())
            if user:
                server.login(user, pwd)
            server.send_message(msg)


def dispatch_notification(
    event_type: str,
    severity: str,
    target: str,
    title: str,
    detail: str,
    force_all_enabled: bool = False,
) -> List[Tuple[str, bool, str]]:
    """Envía una alerta por todos los canales habilitados. Retorna lista de (canal, ok, mensaje)."""
    cfg = get_notify_config(mask_secrets=False)
    server_label = cfg.get("server_label") or "SOS Server"
    icon = "🚨" if severity == "critical" else ("✅" if event_type == "resolved" else "⚠️")
    ts_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

    tg_text = (
        f"{icon} <b>{title}</b>\n"
        f"• <b>Servidor:</b> {server_label}\n"
        f"• <b>Objetivo:</b> <code>{target}</code>\n"
        f"• <b>Severidad:</b> {severity.upper()}\n"
        f"• <b>Detalle:</b> {detail}\n"
        f"• <b>Hora:</b> {ts_str}"
    )
    plain_text = (
        f"{icon} {title}\n\n"
        f"Servidor: {server_label}\n"
        f"Objetivo: {target}\n"
        f"Severidad: {severity.upper()}\n"
        f"Detalle: {detail}\n"
        f"Hora: {ts_str}\n"
    )
    webhook_data = {
        "event": event_type,
        "severity": severity,
        "server": server_label,
        "target": target,
        "title": title,
        "detail": detail,
        "timestamp": int(time.time()),
    }

    results: List[Tuple[str, bool, str]] = []

    if cfg.get("telegram_enabled"):
        try:
            _send_telegram(cfg, tg_text)
            results.append(("telegram", True, "Enviado"))
        except Exception as e:
            _logger.warning("Fallo notificación Telegram: %s", e)
            results.append(("telegram", False, str(e)))

    if cfg.get("webhook_enabled"):
        try:
            _send_webhook(cfg, webhook_data)
            results.append(("webhook", True, "Enviado"))
        except Exception as e:
            _logger.warning("Fallo notificación Webhook: %s", e)
            results.append(("webhook", False, str(e)))

    if cfg.get("smtp_enabled"):
        try:
            _send_smtp(cfg, f"[{server_label}] {title}", plain_text)
            results.append(("smtp", True, "Enviado"))
        except Exception as e:
            _logger.warning("Fallo notificación SMTP: %s", e)
            results.append(("smtp", False, str(e)))

    return results


def report_incident(
    incident_key: str,
    kind: str,
    severity: str,
    target: str,
    title: str,
    detail: str,
) -> Dict[str, Any]:
    """Abre o actualiza un incidente y envía alerta si es nuevo (o crítico sin notificar en 12h)."""
    inc = storage.create_or_touch_incident(
        incident_key=incident_key,
        kind=kind,
        severity=severity,
        target=target,
        title=title,
        detail=detail,
    )
    now = int(time.time())
    should_notify = inc.get("is_new") or (
        severity == "critical" and (now - int(inc.get("notified_at") or 0)) >= 43200
    )
    if should_notify:
        dispatch_notification("incident_opened", severity, target, title, detail)
        storage.mark_incident_notified(inc["id"])
    return inc


def resolve_incident_if_open(incident_key: str, resolution_title: str, resolution_detail: str) -> bool:
    resolved = storage.resolve_open_incident(incident_key, resolution_detail=resolution_detail)
    if not resolved:
        return False
    duration_min = max(1, int((resolved["resolved_at"] - resolved["opened_at"]) / 60))
    full_detail = f"{resolution_detail} (Duración: ~{duration_min} min)"
    dispatch_notification("resolved", "info", resolved["target"], resolution_title, full_detail)
    return True
