
from __future__ import annotations

import logging
import secrets
import threading
import time
from functools import wraps
from urllib.parse import urlparse

from flask import flash, jsonify, redirect, render_template, request, session, url_for

security_logger = logging.getLogger('security')
app_logger = logging.getLogger('inventory.app')


# Path prefixes that serve JSON API endpoints (never HTML pages). When a
# request hits one of these, ALL error paths (CSRF reject, IP reject, 404,
# 500, etc.) must return JSON instead of rendering error.html — otherwise
# the frontend's ``r.json()`` call throws "JSON.parse: unexpected character
# at line 1 column 1" and the user sees a cryptic error instead of a
# meaningful message.
_API_PREFIXES = (
    '/netscope/api/',
    '/assistant/api/',
    '/notifications/api/',
    '/get_chart_data',
    '/gw/',
    '/api/',
)


def is_api_request(req=None):
    """Return True if the current request is a JSON API call.

    Detected via: (a) path prefix, (b) ``Accept: application/json`` header,
    or (c) ``Content-Type: application/json`` on the request body. Used by
    CSRF check, IP filter, and the global error handler to decide whether
    to return JSON (``jsonify({...})``) or HTML (``render_template``).
    """
    try:
        r = req or request
    except RuntimeError:
        return False
    path = (r.path or '')
    if any(path.startswith(p) for p in _API_PREFIXES):
        return True
    accept = (r.headers.get('Accept') or '').lower()
    if 'application/json' in accept and 'text/html' not in accept:
        return True
    ctype = (r.headers.get('Content-Type') or '').lower()
    if 'application/json' in ctype:
        return True
    return False


def _api_error(message, code, **extra):
    """Build a JSON error response tuple for API requests."""
    payload = {'error': message, 'status': code}
    payload.update(extra)
    return jsonify(payload), code


def is_ip_allowed(ip: str, server_ips: list, compiled_allowed_networks: list) -> bool:
    if not compiled_allowed_networks:
        return True

    if ip in ('127.0.0.1', '::1'):
        return True

    if ip in server_ips:
        return True

    try:
        import ipaddress
        ip_addr = ipaddress.ip_address(ip)
        for network in compiled_allowed_networks:
            if ip_addr in network:
                return True
    except ValueError:
        app_logger.error(f"Erro ao verificar IP {ip}")

    return False

def verify_password(app, stored_hash: str, password: str) -> bool:
    try:
        import bcrypt
        if stored_hash.startswith('$2b$'):
            return bcrypt.checkpw(
                password.encode('utf-8'), stored_hash.encode('utf-8'))
        return False
    except Exception as e:
        app.logger.error(f"Erro na verificação de senha: {str(e)}")
        return False

def hash_password(password: str) -> str:
    import bcrypt
    return bcrypt.hashpw(
        password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

_KNOWN_WEAK_DEFAULTS = {
    '', 'minhachave', 'changeme', 'change_me', 'secret', 'secretkey',
    'supersecret', 'default_salt_value', 'supersecreta_altere_esta_chave_salt!',
    'trocar', 'teste', 'test', '123456', 'abc123',
}

def _is_weak_secret(value: str, *, min_len: int = 24) -> bool:
    if not value or value.strip().lower() in _KNOWN_WEAK_DEFAULTS:
        return True
    if len(value) < min_len:
        return True
    if len(set(value.lower())) <= 6:
        return True
    return False

def _persist_env_secret(key: str, value: str) -> None:

    import os
    env_path = os.path.join(os.getcwd(), '.env')
    try:
        if os.path.exists(env_path):
            with open(env_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            for i, line in enumerate(lines):
                if line.strip().startswith(f'{key}='):
                    lines[i] = f'{key}={value}\n'
                    break
            else:
                lines.append(f'{key}={value}\n')
            with open(env_path, 'w', encoding='utf-8') as f:
                f.writelines(lines)
    except OSError:
        pass

def ensure_strong_secrets(app) -> None:

    changed = False

    current_key = app.secret_key or ''
    if _is_weak_secret(current_key):
        new_key = secrets.token_hex(32)
        app.secret_key = new_key
        _persist_env_secret('SECRET_KEY', new_key)
        app_logger.warning(
            "[Segurança] SECRET_KEY fraca/padrão detectada — nova chave "
            "gerada e gravada no .env (sessões abertas foram invalidadas).")
        changed = True

    current_salt = app.config.get('SESSION_SALT') or ''
    if _is_weak_secret(current_salt, min_len=16):
        new_salt = secrets.token_hex(16)
        app.config['SESSION_SALT'] = new_salt
        _persist_env_secret('SESSION_SALT', new_salt)
        app_logger.warning(
            "[Segurança] SESSION_SALT fraca/padrão detectada — novo salt "
            "gerado e gravado no .env.")
        changed = True

    return changed

class MemoryRateLimiter:

    def __init__(self, max_events: int, window_seconds: float):
        self.max_events = max_events
        self.window = window_seconds
        self._events: dict = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.time()
        with self._lock:
            bucket = [t for t in self._events.get(key, []) if now - t < self.window]
            if len(bucket) >= self.max_events:
                self._events[key] = bucket
                return False
            bucket.append(now)
            self._events[key] = bucket
            if len(self._events) > 10000:
                cutoff = now - self.window
                self._events = {
                    k: v for k, v in self._events.items()
                    if v and v[-1] > cutoff
                }
            return True

login_limiter = MemoryRateLimiter(max_events=10, window_seconds=60)

def _same_origin(candidate: str, host_url: str) -> bool:
    try:
        c = urlparse(candidate)
        o = urlparse(host_url)
        if not c.scheme or not c.netloc:
            return False
        return (c.scheme.lower(), c.netloc.lower()) == (o.scheme.lower(), o.netloc.lower())
    except (ValueError, AttributeError):
        return False

def register_csrf_protection(app) -> None:

    @app.before_request
    def _csrf_origin_check():
        if request.method not in ('POST', 'PUT', 'PATCH', 'DELETE'):
            return None
        if request.path.startswith('/static'):
            return None

        origin = request.headers.get('Origin')
        referer = request.headers.get('Referer')
        header = origin or referer
        if not header:
            return None

        if not _same_origin(header, request.host_url):
            security_logger.warning(
                f"CSRF BLOQUEADO - Origem estrangeira: {header} "
                f"IP: {request.remote_addr} Path: {request.path}")
            if is_api_request():
                return _api_error('Requisição bloqueada (CSRF: origem divergente).',
                                  400, reason='csrf_origin_mismatch')
            return render_template(
                'error.html', error_code=400,
                title="Requisição inválida",
                message="A requisição não pôde ser verificada (origem "
                        "diferente da do servidor). Volte e tente "
                        "novamente."), 400
        return None

_ALLOWED_WHILE_CHANGING = {
    'static', 'health', 'logout', 'settings', 'change_password',
    'set_language',
}

def register_password_change_guard(app) -> None:

    @app.before_request
    def _enforce_password_change():
        if not session.get('must_change_password'):
            return None
        if request.endpoint in _ALLOWED_WHILE_CHANGING:
            return None
        if request.path.startswith('/static'):
            return None
        flash("Defina uma nova senha para continuar.", "warning")
        return redirect(url_for('settings'))

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session or session.get('role') != 'admin':
            flash("Acesso negado. Apenas administradores.", "danger")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function
