"""Autenticación fuerte (2FA TOTP + códigos de respaldo), sesiones revocables, IPs de confianza y bitácora."""
import csv
import hashlib
import hmac
import io
import ipaddress
import json
import os
import secrets
import time
from typing import Dict, List, Optional, Tuple

import pyotp
import qrcode
import qrcode.image.svg
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

import audit
import scheduler
import storage

router = APIRouter()

PANEL_ADMIN_USER = os.environ.get("PANEL_ADMIN_USER", "admin")
PANEL_ADMIN_PASSWORD = os.environ.get("PANEL_ADMIN_PASSWORD", "admin")

SESSION_MAX_AGE = 86400 * 7
PREAUTH_MAX_AGE = 300  # 5 minutos para completar el paso 2FA

# Rate-limit en memoria para login y verificaciones sensibles
_login_attempts: Dict[str, Tuple[int, float]] = {}
MAX_LOGIN_ATTEMPTS = 6
LOGIN_LOCK_SECONDS = 300


def check_login_rate_limit(ip: str) -> Optional[int]:
    """Retorna segundos restantes de bloqueo si la IP excedió intentos, o None si puede intentar."""
    count, until = _login_attempts.get(ip, (0, 0.0))
    now = time.time()
    if until > now:
        return int(until - now)
    return None


def record_login_failure(ip: str) -> None:
    count, _ = _login_attempts.get(ip, (0, 0.0))
    count += 1
    if count >= MAX_LOGIN_ATTEMPTS:
        _login_attempts[ip] = (0, time.time() + LOGIN_LOCK_SECONDS)
    else:
        _login_attempts[ip] = (count, 0.0)


def clear_login_failures(ip: str) -> None:
    _login_attempts.pop(ip, None)


def public_session_id(sid: str) -> str:
    return hashlib.sha256(sid.encode("utf-8")).hexdigest()[:16]


def is_totp_enabled() -> bool:
    return storage.get_setting("totp_enabled", "0") == "1" and bool(storage.get_setting("totp_secret", ""))


def _hash_backup_code(raw_code: str) -> str:
    normalized = raw_code.strip().upper().replace("-", "").replace(" ", "")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def verify_2fa_code(code: str) -> Tuple[bool, str]:
    """Verifica un código TOTP de 6 dígitos o un código de respaldo de emergencia.
    Retorna (es_valido, metodo_usado: 'totp' | 'backup' | '').
    """
    secret = storage.get_setting("totp_secret", "")
    if not secret:
        return False, ""

    cleaned = (code or "").strip().replace(" ", "").replace("-", "")
    if not cleaned:
        return False, ""

    if cleaned.isdigit() and len(cleaned) == 6:
        totp = pyotp.TOTP(secret)
        if totp.verify(cleaned, valid_window=1):
            return True, "totp"

    # Verificar contra códigos de respaldo de un solo uso
    raw_hashes = storage.get_setting("totp_backup_hashes", "[]")
    try:
        hashes: List[str] = json.loads(raw_hashes)
    except Exception:
        hashes = []

    candidate_hash = _hash_backup_code(cleaned)
    matched_idx = None
    for idx, h in enumerate(hashes):
        if hmac.compare_digest(h, candidate_hash):
            matched_idx = idx
            break

    if matched_idx is not None:
        hashes.pop(matched_idx)
        storage.set_setting("totp_backup_hashes", json.dumps(hashes))
        return True, "backup"

    return False, ""


def create_preauth_token(serializer: URLSafeTimedSerializer, username: str, ip: str) -> str:
    return serializer.dumps({"purpose": "2fa_preauth", "user": username, "ip": ip, "nonce": secrets.token_hex(8)})


def verify_preauth_token(serializer: URLSafeTimedSerializer, token: str, ip: str) -> Optional[str]:
    try:
        data = serializer.loads(token, max_age=PREAUTH_MAX_AGE)
    except (BadSignature, SignatureExpired):
        return None
    if data.get("purpose") != "2fa_preauth":
        return None
    if data.get("ip") != ip:
        return None
    return data.get("user")


def issue_session_cookie_token(serializer: URLSafeTimedSerializer, request: Request, username: str) -> Tuple[str, str]:
    sid = secrets.token_urlsafe(24)
    ip = audit.get_client_ip(request)
    ua = request.headers.get("user-agent", "Unknown")
    storage.create_session(sid=sid, username=username, ip=ip, user_agent=ua)
    token = serializer.dumps({"user": username, "sid": sid, "ts": int(time.time())})
    return token, sid


def verify_session_request(request: Request, serializer: URLSafeTimedSerializer, cookie_name: str) -> bool:
    token = request.cookies.get(cookie_name)
    if not token:
        return False
    try:
        data = serializer.loads(token, max_age=SESSION_MAX_AGE)
    except BadSignature:
        return False

    user = data.get("user")
    if user != PANEL_ADMIN_USER:
        return False

    sid = data.get("sid")
    if sid:
        sess = storage.get_valid_session(sid, max_age_seconds=SESSION_MAX_AGE)
        if not sess:
            return False
        request.state.username = sess["username"]
        request.state.sid = sid
        return True

    # Compatibilidad transparente con sesiones previas a Fase 1 (sin 'sid'):
    legacy_sid = "legacy_" + hashlib.sha256(token.encode("utf-8")).hexdigest()[:24]
    sess = storage.get_valid_session(legacy_sid, max_age_seconds=SESSION_MAX_AGE)
    if sess is None:
        # Verificar si ya existía como revocada antes de auto-registrarla
        with storage.get_conn() as conn:
            row = conn.execute("SELECT revoked FROM sessions WHERE sid = ?", (legacy_sid,)).fetchone()
            if row and row["revoked"] != 0:
                return False
            if not row:
                storage.create_session(
                    sid=legacy_sid,
                    username=user,
                    ip=audit.get_client_ip(request),
                    user_agent=request.headers.get("user-agent", "Sesión previa"),
                )
    request.state.username = user
    request.state.sid = legacy_sid
    return True


def _require_auth(request: Request) -> None:
    from main import is_authenticated
    if not is_authenticated(request):
        raise HTTPException(status_code=401, detail="No autorizado")


def _generate_qr_svg(uri: str) -> str:
    qr = qrcode.QRCode(version=None, error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=6, border=2)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(image_factory=qrcode.image.svg.SvgPathImage)
    buf = io.BytesIO()
    img.save(buf)
    svg_text = buf.getvalue().decode("utf-8")
    # Remover declaración XML si existe para incrustar limpio en HTML
    if svg_text.startswith("<?xml"):
        svg_text = svg_text.split("?>", 1)[-1].strip()
    return svg_text


def _summarize_ua(ua: str) -> str:
    u = ua or "Desconocido"
    browser = "Navegador"
    for b in ("Edg/", "Chrome/", "Firefox/", "Safari/", "curl/", "python"):
        if b.lower() in u.lower():
            browser = b.rstrip("/").replace("Edg", "Edge").capitalize()
            break
    os_name = ""
    for o, label in (("Windows", "Windows"), ("Macintosh", "macOS"), ("Android", "Android"), ("iPhone", "iOS"), ("Linux", "Linux")):
        if o.lower() in u.lower():
            os_name = label
            break
    return f"{browser} • {os_name}" if os_name else u[:55]


# --- Endpoints API ---

@router.get("/api/security/overview")
def security_overview(request: Request):
    _require_auth(request)
    current_sid = getattr(request.state, "sid", "")
    totp_on = is_totp_enabled()

    try:
        backup_remaining = len(json.loads(storage.get_setting("totp_backup_hashes", "[]") or "[]"))
    except Exception:
        backup_remaining = 0

    raw_sessions = storage.list_active_sessions(max_age_seconds=SESSION_MAX_AGE)
    sessions_out = []
    for s in raw_sessions:
        sessions_out.append({
            "session_id": public_session_id(s["sid"]),
            "username": s["username"],
            "ip": s["ip"],
            "device": _summarize_ua(s["user_agent"]),
            "user_agent": s["user_agent"],
            "created_at": s["created_at"],
            "last_seen": s["last_seen"],
            "is_current": s["sid"] == current_sid,
        })

    summary_24h = storage.count_audit_summary_24h()
    trusted = storage.list_trusted_ips()

    return JSONResponse({
        "ok": True,
        "client_ip": audit.get_client_ip(request),
        "totp_enabled": totp_on,
        "backup_codes_remaining": backup_remaining if totp_on else 0,
        "active_sessions": sessions_out,
        "trusted_ips": trusted,
        "audit_summary": summary_24h,
        "scheduler": scheduler.get_scheduler_status(),
    })


@router.post("/api/security/2fa/setup")
def setup_2fa(request: Request):
    _require_auth(request)
    secret = pyotp.random_base32()
    storage.set_setting("totp_pending_secret", secret)
    issuer = "SOS Cloud Panel"
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=PANEL_ADMIN_USER, issuer_name=issuer)
    qr_svg = _generate_qr_svg(uri)
    return JSONResponse({
        "ok": True,
        "secret": secret,
        "qr_svg": qr_svg,
        "account": PANEL_ADMIN_USER,
        "issuer": issuer,
    })


@router.post("/api/security/2fa/enable")
async def enable_2fa(request: Request):
    _require_auth(request)
    data = await request.json()
    supplied_pw = str(data.get("admin_password") or "")
    code = str(data.get("code") or "").strip().replace(" ", "")

    ip = audit.get_client_ip(request)
    wait_s = check_login_rate_limit(ip)
    if wait_s:
        raise HTTPException(status_code=429, detail=f"Demasiados intentos. Espere {wait_s} s.")

    if not hmac.compare_digest(supplied_pw, PANEL_ADMIN_PASSWORD):
        record_login_failure(ip)
        audit.log_event(request, "security.2fa_enable", target="totp", status="denied", detail="Clave maestra incorrecta")
        return JSONResponse({"ok": False, "message": "Clave maestra del panel incorrecta."}, status_code=403)

    pending_secret = storage.get_setting("totp_pending_secret", "")
    if not pending_secret:
        return JSONResponse({"ok": False, "message": "Inicie primero la generación del código QR."}, status_code=400)

    if not (code.isdigit() and len(code) == 6 and pyotp.TOTP(pending_secret).verify(code, valid_window=1)):
        record_login_failure(ip)
        audit.log_event(request, "security.2fa_enable", target="totp", status="failed", detail="Código TOTP inválido")
        return JSONResponse({"ok": False, "message": "Código de 6 dígitos inválido. Verifique la hora de su teléfono."}, status_code=400)

    clear_login_failures(ip)
    backup_codes = [f"{secrets.token_hex(2).upper()}-{secrets.token_hex(2).upper()}" for _ in range(6)]
    backup_hashes = [_hash_backup_code(c) for c in backup_codes]

    storage.set_setting("totp_secret", pending_secret)
    storage.set_setting("totp_enabled", "1")
    storage.set_setting("totp_backup_hashes", json.dumps(backup_hashes))
    storage.delete_setting("totp_pending_secret")

    audit.log_event(request, "security.2fa_enabled", target="totp", status="ok", detail="2FA TOTP activado con 6 códigos de respaldo")
    return JSONResponse({
        "ok": True,
        "message": "Autenticación 2FA activada correctamente.",
        "backup_codes": backup_codes,
    })


@router.post("/api/security/2fa/disable")
async def disable_2fa(request: Request):
    _require_auth(request)
    data = await request.json()
    supplied_pw = str(data.get("admin_password") or "")
    code = str(data.get("code") or "")

    ip = audit.get_client_ip(request)
    wait_s = check_login_rate_limit(ip)
    if wait_s:
        raise HTTPException(status_code=429, detail=f"Demasiados intentos. Espere {wait_s} s.")

    if not hmac.compare_digest(supplied_pw, PANEL_ADMIN_PASSWORD):
        record_login_failure(ip)
        audit.log_event(request, "security.2fa_disable", target="totp", status="denied", detail="Clave maestra incorrecta")
        return JSONResponse({"ok": False, "message": "Clave maestra incorrecta."}, status_code=403)

    ok_code, _ = verify_2fa_code(code)
    if not ok_code:
        record_login_failure(ip)
        audit.log_event(request, "security.2fa_disable", target="totp", status="failed", detail="Código 2FA inválido")
        return JSONResponse({"ok": False, "message": "Código 2FA o de respaldo inválido."}, status_code=403)

    clear_login_failures(ip)
    storage.set_setting("totp_enabled", "0")
    storage.delete_setting("totp_secret")
    storage.delete_setting("totp_pending_secret")
    storage.delete_setting("totp_backup_hashes")

    audit.log_event(request, "security.2fa_disabled", target="totp", status="ok", detail="2FA TOTP desactivado")
    return JSONResponse({"ok": True, "message": "Autenticación 2FA desactivada."})


@router.post("/api/security/sessions/revoke")
async def revoke_single_session(request: Request):
    _require_auth(request)
    data = await request.json()
    target_pub_id = str(data.get("session_id") or "").strip()
    if not target_pub_id:
        return JSONResponse({"ok": False, "message": "ID de sesión requerido."}, status_code=400)

    active = storage.list_active_sessions(max_age_seconds=SESSION_MAX_AGE)
    matched_sid = None
    matched_ip = ""
    for s in active:
        if public_session_id(s["sid"]) == target_pub_id:
            matched_sid = s["sid"]
            matched_ip = s["ip"]
            break

    if not matched_sid:
        return JSONResponse({"ok": False, "message": "Sesión no encontrada o ya expirada."}, status_code=404)

    storage.revoke_session(matched_sid)
    audit.log_event(request, "security.session_revoked", target=target_pub_id, status="ok", detail=f"IP sesión: {matched_ip}")
    return JSONResponse({"ok": True, "message": "Sesión revocada inmediatamente."})


@router.post("/api/security/sessions/revoke-others")
def revoke_other_sessions_endpoint(request: Request):
    _require_auth(request)
    current_sid = getattr(request.state, "sid", "")
    count = storage.revoke_other_sessions(current_sid)
    audit.log_event(request, "security.sessions_revoked_others", target="sessions", status="ok", detail=f"{count} sesiones cerradas")
    return JSONResponse({"ok": True, "revoked_count": count, "message": f"Se cerraron {count} sesiones adicionales."})


@router.post("/api/security/trusted-ips")
async def add_trusted_ip_endpoint(request: Request):
    _require_auth(request)
    data = await request.json()
    raw_ip = str(data.get("ip") or "").strip()
    note = str(data.get("note") or "").strip()

    try:
        if "/" in raw_ip:
            normalized = str(ipaddress.ip_network(raw_ip, strict=False))
        else:
            normalized = str(ipaddress.ip_address(raw_ip))
    except ValueError:
        return JSONResponse({"ok": False, "message": "Dirección IP o rango CIDR inválido (ej. 190.24.10.5 o 192.168.1.0/24)."}, status_code=400)

    user = getattr(request.state, "username", PANEL_ADMIN_USER)
    storage.add_trusted_ip(normalized, note=note, created_by=user)
    audit.log_event(request, "security.trusted_ip_added", target=normalized, status="ok", detail=note)
    return JSONResponse({"ok": True, "ip": normalized, "message": f"IP de confianza '{normalized}' registrada."})


@router.delete("/api/security/trusted-ips")
async def remove_trusted_ip_endpoint(request: Request):
    _require_auth(request)
    data = await request.json()
    raw_ip = str(data.get("ip") or "").strip()
    if not raw_ip:
        return JSONResponse({"ok": False, "message": "IP requerida."}, status_code=400)

    removed = storage.remove_trusted_ip(raw_ip)
    if not removed:
        return JSONResponse({"ok": False, "message": "La IP no estaba en la lista."}, status_code=404)

    audit.log_event(request, "security.trusted_ip_removed", target=raw_ip, status="ok")
    return JSONResponse({"ok": True, "message": f"IP '{raw_ip}' eliminada de la lista de confianza."})


@router.get("/api/security/audit-logs")
def get_audit_logs_endpoint(
    request: Request,
    limit: int = 150,
    action: str = "",
    status: str = "",
    q: str = "",
    export: str = "",
):
    _require_auth(request)
    logs = storage.query_audit_logs(
        limit=500 if export == "csv" else limit,
        action_filter=action.strip(),
        status_filter=status.strip(),
        search=q.strip(),
    )

    if export == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["ID", "Fecha_UTC", "Usuario", "IP", "Accion", "Objetivo", "Estado", "Detalle"])
        for row in logs:
            iso_dt = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(row["ts"]))
            writer.writerow([row["id"], iso_dt, row["username"], row["ip"], row["action"], row["target"], row["status"], row["detail"]])
        audit.log_event(request, "security.audit_export", target="csv", status="ok", detail=f"{len(logs)} registros exportados")
        return Response(
            content=buf.getvalue(),
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="sos_audit_log_{int(time.time())}.csv"'},
        )

    return JSONResponse({"ok": True, "logs": logs})
