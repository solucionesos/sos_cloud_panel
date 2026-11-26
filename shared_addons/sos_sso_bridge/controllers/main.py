import hashlib
import hmac
import logging
import os
import time

import odoo
from odoo import http, SUPERUSER_ID, tools
from odoo.http import request
from werkzeug.utils import redirect

_logger = logging.getLogger(__name__)


class SosSsoController(http.Controller):

    def _get_sso_secret(self):
        return os.environ.get('SOS_SSO_SECRET') or tools.config.get('sos_sso_secret')

    @http.route('/sso/login', type='http', auth='none', csrf=False, sitemap=False)
    def sso_login(self, db=None, uid=None, ts=None, nonce=None, sig=None, **kw):
        secret = self._get_sso_secret()
        if not secret:
            return http.Response("SSO Bridge no configurado.", status=503)

        if not all([db, uid, ts, nonce, sig]):
            return http.Response("Parámetros incompletos.", status=400)

        try:
            ts_int = int(ts)
            target_uid = int(uid)
        except ValueError:
            return http.Response("Parámetros inválidos.", status=400)

        if abs(int(time.time()) - ts_int) > 120:
            return http.Response("Enlace expirado. Genere uno nuevo.", status=403)

        payload = f"{db}:{target_uid}:{ts_int}:{nonce}"
        expected_sig = hmac.new(
            secret.encode('utf-8'),
            payload.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(expected_sig, sig):
            return http.Response("Firma inválida.", status=403)

        try:
            registry = odoo.registry(db)
        except Exception as e:
            return http.Response(f"BD inaccesible: {e}", status=404)

        try:
            with registry.cursor() as cr:
                env = odoo.api.Environment(cr, SUPERUSER_ID, {})
                user = env['res.users'].sudo().browse(target_uid)
                if not user.exists() or not user.active:
                    user = env['res.users'].sudo().search(
                        [('share', '=', False), ('active', '=', True)],
                        order='id asc',
                        limit=1
                    )
                if not user:
                    return http.Response("Usuario no encontrado.", status=404)

                # Inicializar sesión
                request.session.db = db
                request.session.uid = user.id
                request.session.login = user.login

                # Compatibilidad de session_token entre Odoo 15, 16, 17 y 18
                if hasattr(user, '_compute_session_token'):
                    try:
                        request.session.session_token = user._compute_session_token(request.session.sid)
                    except TypeError:
                        request.session.session_token = user._compute_session_token()

                # Guardar sesión
                if hasattr(request.session, 'rotate'):
                    request.session.rotate = False

                _logger.info("SOS SSO: Acceso concedido a BD '%s' como '%s' (ID %s)", db, user.login, user.id)

        except Exception as err:
            _logger.exception("SOS SSO Error durante inicio de sesión: %s", err)
            return http.Response(f"Error interno SSO: {err}", status=500)

        return redirect('/web')
