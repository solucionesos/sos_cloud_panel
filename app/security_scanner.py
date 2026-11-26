"""Escáner de postura de seguridad (0–100) para instancias Odoo, cabeceras Nginx, TLS y DNS de correo."""
from concurrent.futures import ThreadPoolExecutor
import json
import logging
import re
import ssl
import urllib.error
import urllib.request
from typing import Any, Dict, List, Tuple

import dns.resolver

import health_monitor
import storage

_logger = logging.getLogger("sos_scanner")

COMPOUND_TLDS = {
    "com.co", "net.co", "org.co", "edu.co", "gov.co",
    "com.mx", "org.mx", "gob.mx",
    "com.pe", "org.pe", "gob.pe",
    "com.ar", "com.ec", "com.ve", "com.uy", "com.py", "com.bo", "com.pa", "com.do",
    "co.uk", "com.br", "com.es",
}


def _extract_root_domain(domain: str) -> str:
    parts = domain.lower().strip(".").split(".")
    if len(parts) <= 2:
        return domain.lower()
    last_two = ".".join(parts[-2:])
    if last_two in COMPOUND_TLDS and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last_two


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _http_fetch(url: str, method: str = "GET", body: bytes = None, headers: Dict[str, str] = None, follow_redirects: bool = True) -> Tuple[int, Dict[str, str], List[str], str]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    handlers = [urllib.request.HTTPSHandler(context=ctx)]
    if not follow_redirects:
        handlers.append(_NoRedirect())
    opener = urllib.request.build_opener(*handlers)

    hdrs = {"User-Agent": "SOS-Cloud-SecurityScanner/2.0"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
    try:
        with opener.open(req, timeout=7) as resp:
            raw_headers = {k.lower(): v for k, v in resp.headers.items()}
            set_cookies = resp.headers.get_all("Set-Cookie") or []
            content = resp.read(16384).decode("utf-8", errors="replace")
            return resp.status, raw_headers, set_cookies, content
    except urllib.error.HTTPError as he:
        raw_headers = {k.lower(): v for k, v in he.headers.items()} if he.headers else {}
        set_cookies = (he.headers.get_all("Set-Cookie") if he.headers else None) or []
        try:
            content = he.read(8192).decode("utf-8", errors="replace")
        except Exception:
            content = ""
        return he.code, raw_headers, set_cookies, content
    except Exception as exc:
        return 0, {}, [], str(exc)


def _check_dns_email_security(root_domain: str) -> Tuple[int, List[Dict[str, Any]]]:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 3.5
    resolver.timeout = 2.0

    pts = 0
    findings = []

    # MX (2 pts)
    has_mx = False
    try:
        ans = resolver.resolve(root_domain, "MX")
        has_mx = len(ans) > 0
    except Exception:
        has_mx = False
    if has_mx:
        pts += 2

    # SPF (4 pts)
    spf_record = ""
    try:
        txt_ans = resolver.resolve(root_domain, "TXT")
        for rdata in txt_ans:
            txt_val = "".join(s.decode("utf-8", errors="ignore") if isinstance(s, bytes) else str(s) for s in rdata.strings)
            if "v=spf1" in txt_val.lower():
                spf_record = txt_val
                break
    except Exception:
        pass

    if spf_record:
        pts += 4
        findings.append({
            "control": "SOS-DNS-SPF",
            "title": f"Registro SPF en {root_domain}",
            "status": "pass",
            "points": "4/4",
            "detail": spf_record[:140],
        })
    else:
        findings.append({
            "control": "SOS-DNS-SPF",
            "title": f"Sin registro SPF en {root_domain}",
            "status": "warn",
            "points": "0/4",
            "detail": f"Agregue un registro TXT 'v=spf1 ... ~all' en {root_domain} para evitar suplantación de correo.",
        })

    # DMARC (4 pts)
    dmarc_record = ""
    try:
        dm_ans = resolver.resolve(f"_dmarc.{root_domain}", "TXT")
        for rdata in dm_ans:
            txt_val = "".join(s.decode("utf-8", errors="ignore") if isinstance(s, bytes) else str(s) for s in rdata.strings)
            if "v=dmarc1" in txt_val.lower():
                dmarc_record = txt_val
                break
    except Exception:
        pass

    if dmarc_record:
        pts += 4
        findings.append({
            "control": "SOS-DNS-DMARC",
            "title": f"Política DMARC en _dmarc.{root_domain}",
            "status": "pass",
            "points": "4/4",
            "detail": dmarc_record[:140],
        })
    else:
        findings.append({
            "control": "SOS-DNS-DMARC",
            "title": f"Sin política DMARC en _dmarc.{root_domain}",
            "status": "warn",
            "points": "0/4",
            "detail": f"Configure '_dmarc.{root_domain}' (ej. 'v=DMARC1; p=quarantine;') para proteger el dominio.",
        })

    return pts, findings


def _score_to_grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 45:
        return "D"
    return "F"


def scan_single_target(target: Dict[str, Any]) -> Dict[str, Any]:
    dom = target["domain"]
    is_odoo = bool(target.get("is_odoo"))
    db_name = target.get("db_name") or ""
    score = 0
    findings: List[Dict[str, Any]] = []

    # 1. TLS y Certificado (20 pts)
    _, ssl_valid, days_left, not_after, issuer, tls_ver, ssl_err = health_monitor._inspect_single_ssl(dom)
    storage.upsert_ssl_status(dom, ssl_valid, days_left, not_after, issuer, tls_ver, ssl_err)
    if ssl_valid and days_left > 14 and tls_ver in ("TLSv1.2", "TLSv1.3"):
        score += 20
        findings.append({
            "control": "SOS-TLS-01",
            "title": "Certificado TLS válido y protocolo moderno",
            "status": "pass",
            "points": "20/20",
            "detail": f"{tls_ver} • Vigente por {days_left} días ({issuer})",
        })
    elif ssl_valid and days_left > 0:
        score += 12
        findings.append({
            "control": "SOS-TLS-01",
            "title": "Certificado TLS próximo a vencer",
            "status": "warn",
            "points": "12/20",
            "detail": f"Quedan solo {days_left} días ({not_after}). Verifique renovación de Certbot.",
        })
    else:
        findings.append({
            "control": "SOS-TLS-01",
            "title": "Certificado SSL inválido o sin HTTPS activo",
            "status": "fail",
            "points": "0/20",
            "detail": ssl_err or "El sitio no presenta un certificado TLS válido en el puerto 443.",
        })

    # 2. Redirección HTTP -> HTTPS (10 pts)
    http_code, http_hdrs, _, _ = _http_fetch(f"http://{dom}/", follow_redirects=False)
    loc = http_hdrs.get("location", "")
    if http_code in (301, 302, 307, 308) and loc.startswith("https://"):
        score += 10
        findings.append({
            "control": "SOS-TLS-02",
            "title": "Redirección forzada HTTP → HTTPS",
            "status": "pass",
            "points": "10/10",
            "detail": f"HTTP {http_code} redirige a {loc[:80]}",
        })
    else:
        findings.append({
            "control": "SOS-TLS-02",
            "title": "Tráfico HTTP plano no redirige a HTTPS",
            "status": "warn",
            "points": "0/10",
            "detail": f"Respuesta en puerto 80: HTTP {http_code}. Configure 'return 301 https://$host$request_uri;' en Nginx.",
        })

    # 3. Superficie Crítica: Gestor de BDs Odoo / Archivos Sensibles (25 pts)
    if is_odoo:
        rpc_body = json.dumps({"jsonrpc": "2.0", "method": "call", "params": {}, "id": 1}).encode("utf-8")
        db_code, _, _, db_resp_text = _http_fetch(
            f"https://{dom}/web/database/list",
            method="POST",
            body=rpc_body,
            headers={"Content-Type": "application/json"},
        )
        exposed_dbs = False
        if db_code == 200 and '"result"' in db_resp_text:
            try:
                parsed = json.loads(db_resp_text)
                if isinstance(parsed.get("result"), list) and len(parsed["result"]) > 0:
                    exposed_dbs = True
            except Exception:
                pass

        if not exposed_dbs:
            score += 25
            findings.append({
                "control": "SOS-ODOO-DBMGR",
                "title": "Listado/Gestor público de bases de datos Odoo protegido",
                "status": "pass",
                "points": "25/25",
                "detail": "El endpoint /web/database/list no expone las bases de datos públicamente.",
            })
        else:
            findings.append({
                "control": "SOS-ODOO-DBMGR",
                "title": "Gestor y listado de bases de datos Odoo expuesto públicamente",
                "status": "fail",
                "points": "0/25",
                "detail": "RIESGO CRÍTICO: Configure 'list_db = False' en odoo.conf o bloquee /web/database/ en Nginx.",
            })
    else:
        env_code, _, _, env_body = _http_fetch(f"https://{dom}/.env", follow_redirects=False)
        if env_code == 200 and "=" in env_body and "<html" not in env_body.lower():
            findings.append({
                "control": "SOS-WEB-ENV",
                "title": "Archivo /.env accesible públicamente",
                "status": "fail",
                "points": "0/25",
                "detail": "Bloquee inmediatamente el acceso a archivos ocultos 'location ~ /\\.' en Nginx.",
            })
        else:
            score += 25
            findings.append({
                "control": "SOS-WEB-ENV",
                "title": "Archivos sensibles ocultos (/.env) protegidos",
                "status": "pass",
                "points": "25/25",
                "detail": f"Petición a /.env devolvió HTTP {env_code}.",
            })

    # 4. Cabeceras HTTP y Cookies en página principal / login (25 + 10 pts)
    entry_path = "/web/login" if is_odoo else "/"
    https_code, hdrs, cookies, _ = _http_fetch(f"https://{dom}{entry_path}", follow_redirects=True)

    # HSTS (8 pts)
    if "strict-transport-security" in hdrs:
        score += 8
        findings.append({
            "control": "SOS-HDR-HSTS",
            "title": "Cabecera HSTS (Strict-Transport-Security) activa",
            "status": "pass",
            "points": "8/8",
            "detail": hdrs["strict-transport-security"][:100],
        })
    else:
        findings.append({
            "control": "SOS-HDR-HSTS",
            "title": "Falta cabecera Strict-Transport-Security (HSTS)",
            "status": "warn",
            "points": "0/8",
            "detail": "Agregue 'add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;' en Nginx.",
        })

    # X-Content-Type-Options (6 pts)
    if hdrs.get("x-content-type-options", "").lower() == "nosniff":
        score += 6
        findings.append({
            "control": "SOS-HDR-NOSNIFF",
            "title": "Protección contra MIME Sniffing activa",
            "status": "pass",
            "points": "6/6",
            "detail": "X-Content-Type-Options: nosniff",
        })
    else:
        findings.append({
            "control": "SOS-HDR-NOSNIFF",
            "title": "Falta cabecera X-Content-Type-Options: nosniff",
            "status": "warn",
            "points": "0/6",
            "detail": "Agregue 'add_header X-Content-Type-Options \"nosniff\" always;' en Nginx.",
        })

    # Clickjacking: X-Frame-Options o CSP (6 pts)
    has_frame_guard = ("x-frame-options" in hdrs) or ("content-security-policy" in hdrs)
    if has_frame_guard:
        score += 6
        findings.append({
            "control": "SOS-HDR-FRAME",
            "title": "Protección anti-Clickjacking (X-Frame-Options / CSP)",
            "status": "pass",
            "points": "6/6",
            "detail": hdrs.get("x-frame-options") or hdrs.get("content-security-policy", "")[:90],
        })
    else:
        findings.append({
            "control": "SOS-HDR-FRAME",
            "title": "Sin cabecera X-Frame-Options ni Content-Security-Policy",
            "status": "warn",
            "points": "0/6",
            "detail": "Agregue 'add_header X-Frame-Options \"SAMEORIGIN\" always;' en Nginx.",
        })

    # Ocultamiento de versión en Server (5 pts)
    srv_hdr = hdrs.get("server", "")
    if not re.search(r"\d+\.\d+", srv_hdr):
        score += 5
        findings.append({
            "control": "SOS-HDR-SRV",
            "title": "Versión exacta del servidor web oculta",
            "status": "pass",
            "points": "5/5",
            "detail": f"Server: {srv_hdr or 'oculto'}",
        })
    else:
        findings.append({
            "control": "SOS-HDR-SRV",
            "title": f"Versión del servidor expuesta ({srv_hdr})",
            "status": "warn",
            "points": "0/5",
            "detail": "Active 'server_tokens off;' en /etc/nginx/nginx.conf para ocultar la versión exacta.",
        })

    # 5. Seguridad de Cookies de Sesión (10 pts)
    if cookies:
        c_joined = " ; ".join(cookies).lower()
        has_httponly = "httponly" in c_joined
        has_secure = "secure" in c_joined
        c_pts = (5 if has_httponly else 0) + (5 if has_secure else 0)
        score += c_pts
        if c_pts == 10:
            findings.append({
                "control": "SOS-COOKIE-01",
                "title": "Cookies de sesión protegidas (HttpOnly + Secure)",
                "status": "pass",
                "points": "10/10",
                "detail": "Las cookies de sesión impiden lectura por XSS y transmisión sin cifrar.",
            })
        else:
            missing = []
            if not has_httponly:
                missing.append("HttpOnly")
            if not has_secure:
                missing.append("Secure (verifique proxy_mode=True y X-Forwarded-Proto https)")
            findings.append({
                "control": "SOS-COOKIE-01",
                "title": "Cookies de sesión con atributos incompletos",
                "status": "warn",
                "points": f"{c_pts}/10",
                "detail": "Falta: " + ", ".join(missing),
            })
    elif https_code > 0:
        score += 10
        findings.append({
            "control": "SOS-COOKIE-01",
            "title": "Sin exposición de cookies inseguras en acceso público",
            "status": "pass",
            "points": "10/10",
            "detail": "No se emiten cookies sin protección en la carga anónima.",
        })

    # 6. DNS Correo (MX + SPF + DMARC = 10 pts)
    root_dom = _extract_root_domain(dom)
    dns_pts, dns_findings = _check_dns_email_security(root_dom)
    score += dns_pts
    findings.extend(dns_findings)

    grade = _score_to_grade(score)
    storage.upsert_security_scan(
        domain=dom,
        score=score,
        grade=grade,
        db_name=db_name,
        findings_json=json.dumps(findings, ensure_ascii=False),
    )
    return {
        "domain": dom,
        "score": score,
        "grade": grade,
        "db_name": db_name,
        "findings": findings,
    }


def run_all_security_scans() -> List[Dict[str, Any]]:
    targets = health_monitor.discover_monitored_targets()
    if not targets:
        return []
    with ThreadPoolExecutor(max_workers=min(8, len(targets))) as pool:
        return list(pool.map(scan_single_target, targets))
