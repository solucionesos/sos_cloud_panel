"""Registro centralizado de eventos de auditoría (fail-open)."""
import logging
from typing import Optional

from fastapi import Request

import storage

_logger = logging.getLogger("sos_audit")


def get_client_ip(request: Optional[Request]) -> str:
    if request is None:
        return "system"
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    return request.client.host if request.client else "unknown"


def log_event(
    request: Optional[Request],
    action: str,
    target: str = "",
    status: str = "ok",
    detail: str = "",
    username: Optional[str] = None,
) -> None:
    """Registra una entrada en audit_logs sin interrumpir el flujo principal ante fallos."""
    try:
        user = username
        if not user and request is not None:
            user = getattr(request.state, "username", None)
        user = user or "anonymous"
        ip = get_client_ip(request)
        storage.insert_audit_log(
            username=user,
            ip=ip,
            action=action,
            target=target,
            status=status,
            detail=detail,
        )
    except Exception as exc:
        _logger.warning("No se pudo registrar evento de auditoría (%s): %s", action, exc)
