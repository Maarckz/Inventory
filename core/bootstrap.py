
from __future__ import annotations

import logging
import os
import secrets

app_logger = logging.getLogger('inventory.app')

def _column_exists(conn, table: str, column: str) -> bool:

    try:
        dialect = conn.dialect.name
        if dialect == 'postgresql':
            from sqlalchemy import text
            row = conn.execute(text(
                "SELECT 1 FROM information_schema.columns "
                "WHERE table_name = :t AND column_name = :c"),
                {'t': table, 'c': column}).first()
            return row is not None
        else:
            from sqlalchemy import text
            rows = conn.execute(text(f"PRAGMA table_info({table})")).fetchall()
            return any(r[1] == column for r in rows)
    except Exception:
        return True

def _ensure_column(db, table: str, column: str, ddl: str) -> bool:

    from sqlalchemy import text
    try:
        with db.engine.connect() as conn:
            if _column_exists(conn, table, column):
                return False
            conn.execute(text(f'ALTER TABLE {table} ADD COLUMN {ddl}'))
            conn.commit()
            app_logger.info(
                f"[Boot] Coluna {table}.{column} adicionada.")
            return True
    except Exception as e:
        db.session.rollback()
        app_logger.warning(f"[Boot] Migração {table}.{column} pulada: {e}")
        return False

def ensure_must_change_password_column(db) -> None:

    _ensure_column(db, 'users', 'must_change_password',
                   'must_change_password BOOLEAN DEFAULT FALSE')

def ensure_user_full_name_column(db) -> None:

    _ensure_column(db, 'users', 'full_name',
                   'full_name VARCHAR(120)')

def drop_report_history(app, db) -> None:

    try:
        from sqlalchemy import text
        db.session.execute(text('DROP TABLE IF EXISTS report_history'))
        db.session.commit()
        app.logger.info("[Boot] Tabela report_history removida (histórico de "
                        "relatórios descontinuado na v0.13.0).")
    except Exception as _e:
        db.session.rollback()
        app.logger.debug(f"[Boot] report_history não pôde ser removida: {_e}")

def bootstrap_admin(app, db) -> None:

    from models import User
    from core.security import hash_password

    if User.query.first():
        return

    env_password = os.getenv('ADMIN_PASSWORD', '').strip()
    generated = False
    if not env_password:
        env_password = secrets.token_urlsafe(12)
        generated = True
        _persist_env_password(env_password)

    must_change = _resolve_must_change(generated)

    admin_user = User(
        username='admin',
        password_hash=hash_password(env_password),
        role='admin',
        must_change_password=must_change,
    )
    db.session.add(admin_user)
    db.session.commit()

    if generated:
        app.logger.warning(
            "Usuário admin criado com senha GERADA (gravada em ADMIN_PASSWORD "
            "no .env). Troque no primeiro login.")
    else:
        app.logger.info(
            "Usuário admin criado com senha de ADMIN_PASSWORD (.env). "
            + ("Troca obrigatória no primeiro login." if must_change
               else "Troca obrigatória no 1º login DESATIVADA "
                    "(ADMIN_MUST_CHANGE_PASSWORD=false)."))

    if os.getenv('ENSURE_ADMIN_PASSWORD', '').strip():
        app_logger.warning(
            "[Boot] ENSURE_ADMIN_PASSWORD não tem mais efeito (v0.18): a "
            "senha do admin NUNCA é redefinida automaticamente. Para trocar, "
            "use /settings ou remova o usuário e reinicie com ADMIN_PASSWORD.")

def _resolve_must_change(generated: bool) -> bool:

    raw = os.getenv('ADMIN_MUST_CHANGE_PASSWORD', '').strip().lower()
    if raw in ('true', '1', 'yes', 'sim'):
        return True
    if raw in ('false', '0', 'no', 'nao', 'não'):
        return False
    return generated

def _persist_env_password(password: str) -> None:
    env_path = os.path.join(os.getcwd(), '.env')
    try:
        if os.path.exists(env_path):
            with open(env_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            for i, line in enumerate(lines):
                if line.strip().startswith('ADMIN_PASSWORD='):
                    lines[i] = f'ADMIN_PASSWORD={password}\n'
                    break
            else:
                lines.append(f'\n# v0.18 — senha inicial do admin (troque no 1º login)\nADMIN_PASSWORD={password}\n')
            with open(env_path, 'w', encoding='utf-8') as f:
                f.writelines(lines)
    except OSError:
        pass

def ensure_sync_job(app, scheduler, scheduled_sync) -> None:

    from models import SystemSetting, db

    sync_setting = SystemSetting.query.filter_by(key='sync_interval').first()
    if not sync_setting:
        sync_setting = SystemSetting(key='sync_interval', value={'seconds': 3600})
        db.session.add(sync_setting)
        db.session.commit()

    interval_seconds = sync_setting.value.get('seconds', 3600)

    if scheduler.get_job('wazuh_sync'):
        scheduler.remove_job('wazuh_sync')

    scheduler.add_job(id='wazuh_sync', func=scheduled_sync,
                      trigger='interval', seconds=interval_seconds)
    app.logger.info(f"Sincronização agendada para cada {interval_seconds} segundos.")

WAZUH_INTERVAL_MIN = 300
WAZUH_INTERVAL_MAX = 86400
WAZUH_INTERVAL_DEFAULT = 3600

def clamp_wazuh_interval(seconds):

    try:
        v = int(seconds)
    except (TypeError, ValueError):
        return WAZUH_INTERVAL_DEFAULT
    return max(WAZUH_INTERVAL_MIN, min(WAZUH_INTERVAL_MAX, v))

def read_wazuh_interval():

    from models import SystemSetting
    try:
        s = SystemSetting.query.filter_by(key='sync_interval').first()
        if s and isinstance(s.value, dict):
            return clamp_wazuh_interval(s.value.get('seconds', WAZUH_INTERVAL_DEFAULT))
    except Exception:
        pass
    return WAZUH_INTERVAL_DEFAULT

def reschedule_wazuh_sync(seconds, scheduled_sync=None):

    from models import SystemSetting, db
    from core.app import get_scheduler

    seconds = clamp_wazuh_interval(seconds)

    s = SystemSetting.query.filter_by(key='sync_interval').first()
    if not s:
        s = SystemSetting(key='sync_interval', value={'seconds': seconds})
        db.session.add(s)
    else:
        s.value = {'seconds': seconds}
    db.session.commit()

    if scheduled_sync is None:
        from routes.settings import _scheduled_sync
        scheduled_sync = _scheduled_sync()

    scheduler = get_scheduler()
    if scheduler.get_job('wazuh_sync'):
        scheduler.remove_job('wazuh_sync')
    scheduler.add_job(id='wazuh_sync', func=scheduled_sync,
                      trigger='interval', seconds=seconds)
    return seconds
