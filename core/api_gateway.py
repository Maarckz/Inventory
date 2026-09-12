
import hashlib
import hmac
import http.client
import os
import ssl
from flask import Response, jsonify, request, session

LOCKED_FAMILIES = {
    'ns': '/netscope/api/',
    'chart': '/get_chart_data',
    'chat': '/assistant/api/',
    'notify': '/notifications/api/',
}

GW_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD']

_MAX_BODY = 128 * 1024 * 1024
_SUB_TIMEOUT = 90

def _secret(app):
    sec = app.config.get('GW_SECRET')
    if not sec:
        import secrets as _secrets
        sec = _secrets.token_hex(32)
        app.config['GW_SECRET'] = sec
    return sec

def alias_for(app, key):

    msg = ('gw1:' + key).encode('utf-8')
    return hmac.new(_secret(app).encode('utf-8'), msg, hashlib.sha256).hexdigest()[:12]

def aliases(app):

    return {k: alias_for(app, k) for k in LOCKED_FAMILIES}

def _sig_for(secret, path):
    msg = ('sig1:' + path).encode('utf-8')
    return hmac.new(str(secret).encode('utf-8'), msg, hashlib.sha256).hexdigest()

def _reverse(app):

    return {alias_for(app, k): prefix for k, prefix in LOCKED_FAMILIES.items()}

def lock_enabled(app):
    return bool(app.config.get('GW_LOCK_ENABLED', True))

def _gw_404():
    return jsonify({'error': 'Não encontrado'}), 404

def _register_lock(app):

    @app.before_request
    def _gw_lock():
        p = request.path
        if p == '/gw' or p.startswith('/gw/'):
            return None
        if not lock_enabled(app):
            return None
        locked = False
        for prefix in LOCKED_FAMILIES.values():
            if p == prefix.rstrip('/') or p.startswith(prefix):
                locked = True
                break
        if not locked:
            return None
        remote = request.remote_addr or ''
        sig = request.headers.get('X-GW-Sig', '')
        if remote in ('127.0.0.1', '::1') and sig and \
                hmac.compare_digest(sig, _sig_for(_secret(app), p)):
            return None
        return _gw_404()

def _local_port():

    try:
        return int(os.getenv('PORT', '') or request.environ.get('SERVER_PORT') or 8000)
    except (ValueError, TypeError):
        try:
            return int(request.environ.get('SERVER_PORT') or 8000)
        except (ValueError, TypeError):
            return 8000

def _forward(method, real_path, body_bytes, copy_headers):

    port = _local_port()
    if request.is_secure:
        conn = http.client.HTTPSConnection(
            '127.0.0.1', port, timeout=_SUB_TIMEOUT,
            context=ssl._create_unverified_context())
    else:
        conn = http.client.HTTPConnection('127.0.0.1', port, timeout=_SUB_TIMEOUT)
    headers = {'X-GW-Sig': _sig_for(current_app_secret(), real_path.split('?', 1)[0])}
    for h, v in copy_headers:
        if v:
            headers[h] = v
    try:
        conn.request(method, real_path, body=body_bytes if body_bytes else None,
                     headers=headers)
        resp = conn.getresponse()
        data = resp.read(_MAX_BODY)
        return resp.status, resp.getheader('Content-Type') or 'application/json', data
    finally:
        try:
            conn.close()
        except Exception:
            pass

def current_app_secret():

    from flask import current_app
    return current_app.config.get('GW_SECRET', '')

def _register_route(app):

    @app.route('/gw/<alias>', methods=GW_METHODS)
    def gw_proxy(alias):
        if 'username' not in session:
            return _gw_404()
        real = _reverse(app).get(alias)
        if not real:
            return _gw_404()
        real_path = request.headers.get('X-GW-Path', '')
        if not real_path.startswith(real):
            return _gw_404()
        if len(real_path) > 2048:
            return _gw_404()
        copy_headers = [
            ('Cookie', request.headers.get('Cookie')),
            ('Content-Type', request.headers.get('Content-Type')),
            ('X-CSRFToken', request.headers.get('X-CSRFToken')),
            ('Accept', request.headers.get('Accept')),
            ('Accept-Language', request.headers.get('Accept-Language')),
        ]
        body = request.get_data(cache=False) if method_has_body(request.method) else b''
        try:
            status, ctype, data = _forward(request.method, real_path, body, copy_headers)
        except Exception:
            return _gw_404()
        return Response(data, status=status, content_type=ctype)

    def method_has_body(m):
        return m in ('POST', 'PUT', 'PATCH', 'DELETE')

def register_gateway(app):

    app.config['GW_SECRET'] = os.getenv('GW_SECRET') or _secret(app)
    flag = (os.getenv('API_LOCK', '1') or '1').strip().lower()
    app.config['GW_LOCK_ENABLED'] = flag not in ('0', 'false', 'no', 'nao', 'não', 'off')
    _register_lock(app)
    _register_route(app)

def template_aliases(app):

    if not lock_enabled(app):
        return {}
    try:
        if 'username' not in session:
            return {}
    except Exception:
        return {}
    return aliases(app)
