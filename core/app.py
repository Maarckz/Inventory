
from __future__ import annotations

import os

from dotenv import load_dotenv
from flask import Flask, render_template, request, session
from flask_apscheduler import APScheduler
from flask_session import Session

from models import db
from core import config as cfg
from core.logging_setup import setup_logging
from core.security import (
    ensure_strong_secrets, register_csrf_protection, is_ip_allowed,
)
from core.i18n import inject_translations, formatar_data

load_dotenv()

_scheduler: APScheduler | None = None

def get_scheduler() -> APScheduler | None:
    return _scheduler

def _acquire_scheduler_lock(app: Flask) -> bool:

    try:
        import fcntl
        lock_path = os.path.join(cfg.LOG_DIR, 'scheduler.lock')
        os.makedirs(os.path.dirname(lock_path) or '.', exist_ok=True)
        fd = open(lock_path, 'w')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            fd.close()
            app.logger.info("Scheduler já ativo em outro processo — pulando start.")
            return False
        app.extensions['scheduler_lock_fd'] = fd
        return True
    except ImportError:
        return True
    except Exception as e:
        app.logger.warning(f"Lock do scheduler falhou ({e}); iniciando scheduler.")
        return True

def create_app() -> Flask:

    global _scheduler

    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    app = Flask(
        __name__,
        static_folder=os.path.join(project_root, 'static'),
        template_folder=os.path.join(project_root, 'templates'),
    )
    app.secret_key = os.getenv('SECRET_KEY')
    app.config['STATIC_FOLDER'] = 'static'

    app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 12 * 60 * 60

    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Strict',
        PERMANENT_SESSION_LIFETIME=900,
        MAX_CONTENT_LENGTH=1024 * 1024,
        SESSION_SALT=os.getenv('SESSION_SALT', 'default_salt_value')
    )

    try:
        trust_proxy = max(0, int(os.getenv('TRUST_PROXY', '0') or '0'))
    except ValueError:
        trust_proxy = 0
    if trust_proxy > 0:
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(
            app.wsgi_app,
            x_for=trust_proxy, x_proto=trust_proxy,
            x_host=trust_proxy, x_port=trust_proxy,
        )
        app.config['TRUST_PROXY'] = trust_proxy

    from services.netscope import ns_bp, init_netscope
    app.register_blueprint(ns_bp)

    app.config['SQLALCHEMY_DATABASE_URI'] = cfg.get_database_url()
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db.init_app(app)

    app.config['SESSION_TYPE'] = 'sqlalchemy'
    app.config['SESSION_SQLALCHEMY'] = db
    app.config['SESSION_SQLALCHEMY_TABLE'] = 'flask_sessions'
    app.config['SESSION_PERMANENT'] = True
    Session(app)

    _scheduler = APScheduler()
    scheduler = _scheduler
    scheduler.init_app(app)
    if _acquire_scheduler_lock(app):
        scheduler.start()

    def scheduled_sync():
        with app.app_context():
            from utils.collector import sync_wazuh_data
            from services.netscope_wazuh_bridge import sync_from_inventory as netscope_sync
            sync_wazuh_data(app)
            try:
                netscope_sync(app)
            except Exception as e:
                app.logger.error(f"[NetScope] Ponte Wazuh falhou após sync agendado: {e}")

    with app.app_context():
        from core.bootstrap import (
            drop_report_history, bootstrap_admin, ensure_sync_job,
            ensure_must_change_password_column, ensure_user_full_name_column,
        )
        db.create_all()
        ensure_must_change_password_column(db)
        ensure_user_full_name_column(db)
        drop_report_history(app, db)
        ensure_sync_job(app, scheduler, scheduled_sync)
        bootstrap_admin(app, db)

    os.makedirs(cfg.LOG_DIR, exist_ok=True)

    ssl_context = cfg.get_ssl_context()

    secure_override = (os.getenv('SESSION_COOKIE_SECURE') or '').strip().lower()
    if secure_override in ('true', '1', 'yes', 'sim'):
        cookie_secure = True
    elif secure_override in ('false', '0', 'no', 'nao', 'não'):
        cookie_secure = False
    else:
        cookie_secure = ssl_context is not None
    app.config['SESSION_COOKIE_SECURE'] = cookie_secure

    if cfg.https_enabled() and ssl_context is None:
        app.logger.warning(
            "[Boot] USE_HTTPS=True mas os certificados não foram "
            f"encontrados (SSL_CERT_PATH={cfg.SSL_CERT!r}, "
            f"SSL_KEY_PATH={cfg.SSL_KEY!r}). O app vai subir em HTTP e o "
            "cookie Secure fica DESLIGADO para o login funcionar. Para "
            "HTTPS de verdade: gere/instale os certificados ou rode atrás "
            "de um proxy TLS com TRUST_PROXY>=1 e SESSION_COOKIE_SECURE=true.")
    elif cookie_secure and ssl_context is None and trust_proxy == 0:
        app.logger.warning(
            "[Boot] SESSION_COOKIE_SECURE=true sem TLS local nem proxy "
            "configurado: browsers NÃO enviam o cookie em HTTP e o login "
            "não vai funcionar. Defina SESSION_COOKIE_SECURE=false ou "
            "configure TRUST_PROXY.")

    server_ips = cfg.discover_server_ips()
    app.config['SERVER_IPS'] = server_ips
    app.config['SSL_CONTEXT'] = ssl_context

    compiled_allowed_networks = cfg.compile_allowed_networks(
        os.getenv('ALLOWED_IP_RANGES'))
    app.config['COMPILED_ALLOWED_NETWORKS'] = compiled_allowed_networks

    import logging
    logging.getLogger('inventory.app').addHandler(logging.NullHandler())
    setup_logging(app, cfg.LOG_DIR)

    ensure_strong_secrets(app)

    with app.app_context():
        init_netscope(app)

    def _boot_notifications():
        try:
            from services.notifications import evaluate_all
            r = evaluate_all(app, logger=app.logger)
            app.logger.info(
                "[Notificações] avaliação inicial: "
                f"{r['created']} novo(s) alerta(s), regras: {r['rules']}")
        except Exception as e:
            app.logger.warning(f"[Notificações] avaliação inicial falhou: {e}")

    with app.app_context():
        _boot_notifications()

    app.MACHINES_CACHE = {'data': None, 'last_update': 0}
    app.STATS_CACHE = {'data': None, 'last_update': 0}

    app.jinja_env.filters['formatar_data'] = formatar_data
    app.context_processor(inject_translations)

    app.context_processor(lambda: {'boot_id': cfg.APP_VERSION})

    app.context_processor(
        lambda: {'gw_aliases': template_aliases(app)})

    from core.api_gateway import register_gateway, template_aliases
    register_gateway(app)

    @app.before_request
    def check_access():
        client_ip = request.remote_addr

        username = session['username'] if 'username' in session else 'Não autenticado'

        import logging
        logging.getLogger('audit').info(
            f"ACESSO - IP: {client_ip}, Usuário: {username}, "
            f"Endpoint: {request.endpoint}, Método: {request.method}")

        if not request.path.startswith('/static'):
            if not is_ip_allowed(client_ip, server_ips, compiled_allowed_networks):
                logging.getLogger('security').warning(
                    f"ACESSO BLOQUEADO - IP não permitido: {client_ip}, "
                    f"Usuário: {username}, Endpoint: {request.endpoint}")
                return render_template(
                    'error.html', error_code=403,
                    message="Acesso não permitido a partir do seu endereço IP"), 403
        return None

    register_csrf_protection(app)
    from core.security import register_password_change_guard
    register_password_change_guard(app)

    register_routes(app)

    return app

def sync_wazuh_and_netscope(app_ref):

    with app_ref.app_context():
        from utils.collector import sync_wazuh_data
        from services.netscope_wazuh_bridge import sync_from_inventory as netscope_sync
        sync_wazuh_data(app_ref)
        try:
            netscope_sync(app_ref)
        except Exception as e:
            app_ref.logger.error(f"[NetScope] Ponte Wazuh falhou após sync manual: {e}")

FULL_SYNC_STATE = {
    'running': False, 'seq': 0, 'done_seq': 0,
    'started_at': None, 'finished_at': None, 'lock': __import__('threading').Lock(),
}

def full_sync_status():

    with FULL_SYNC_STATE['lock']:
        return {k: FULL_SYNC_STATE[k] for k in
                ('running', 'seq', 'done_seq', 'started_at', 'finished_at')}

def run_full_sync(app_ref, seq=0):

    from datetime import datetime as _dt
    try:
        sync_wazuh_and_netscope(app_ref)
        with app_ref.app_context():
            try:
                from services.netscope_core import load_config
                from services.netscope_engine import run_scan, _scan_state
                cfg = load_config()
                networks = cfg.get('networks') or []
                if networks:
                    with _scan_state['lock']:
                        busy = _scan_state['running']
                        if not busy:
                            _scan_state['running'] = True
                            _scan_state['result'] = None
                    if busy:
                        app_ref.logger.info(
                            "[Sincronizar Agora] Ping sweep pulado — já existe "
                            "uma varredura em andamento.")
                    else:
                        try:
                            run_scan(app_ref, networks, cfg.get('scan', {}),
                                     auto_snapshot=False)
                        finally:
                            with _scan_state['lock']:
                                _scan_state['running'] = False
            except Exception as e:
                app_ref.logger.error(f"[Sincronizar Agora] Ping sweep falhou: {e}")
            try:
                from services.netscope_discovery import run_manual_pass
                run_manual_pass(app_ref)
            except Exception as e:
                app_ref.logger.error(f"[Sincronizar Agora] ARP Discovery falhou: {e}")
    finally:
        with FULL_SYNC_STATE['lock']:
            FULL_SYNC_STATE['running'] = False
            FULL_SYNC_STATE['done_seq'] = seq or FULL_SYNC_STATE['seq']
            FULL_SYNC_STATE['finished_at'] = _dt.now().strftime(
                '%Y-%m-%d %H:%M:%S')

def register_routes(app: Flask) -> None:

    from routes import dashboard, auth, machines, admin, settings

    for module in (dashboard, auth, machines, admin, settings):
        for rule, endpoint, view, opts in module.ROUTES:
            view_func = getattr(module, view) if isinstance(view, str) else view
            app.add_url_rule(rule, endpoint, view_func=view_func, **opts)

    from routes.assistant import assistant_bp
    app.register_blueprint(assistant_bp)

    from routes.notifications import notify_bp
    app.register_blueprint(notify_bp)

    from routes.errors import register_error_handlers
    register_error_handlers(app)

def run_server(app: Flask) -> None:

    host = os.getenv('HOST', '0.0.0.0')
    port = int(os.getenv('PORT', '8000'))
    debug = os.getenv('DEBUG', 'False').lower() == 'true'

    print(f" * IPs do servidor: {app.config['SERVER_IPS']}")
    print(f" * Redes permitidas: {os.getenv('ALLOWED_IP_RANGES', '').split(',')}")

    app.run(
        debug=debug,
        host=host,
        port=port,
        ssl_context=app.config['SSL_CONTEXT']
    )
