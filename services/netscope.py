
from flask import Flask

from services.netscope_core import load_config
from routes.netscope import ns_bp

__version__ = '0.17.0-inventory'

def init_netscope(app: Flask):

    _migrate_schema_v010(app)

    try:
        with app.app_context():
            from services.netscope_wazuh_bridge import sync_from_inventory
            sync_from_inventory(app)
    except Exception as e:
        try:
            app.logger.warning(f"[NetScope] Sincronização inicial pulada: {e}")
        except Exception:
            pass

    try:
        from services.netscope_engine import start_auto_scan_thread
        start_auto_scan_thread(app)
        app.logger.info("[NetScope] Thread de auto-scan no ar (config decide).")
    except Exception as e:
        app.logger.warning(f"[NetScope] Falha ao iniciar auto-scan: {e}")

    try:
        from services.netscope_discovery import start_arp_monitor
        start_arp_monitor(app)
        app.logger.info("[NetScope] Monitor ARP no ar (novos hosts via ARP entre scans).")
    except Exception as e:
        app.logger.warning(f"[NetScope] Monitor ARP não iniciado: {e}")

    app.logger.info("[NetScope] Módulo NetScope inicializado (dados no PostgreSQL do Inventory).")

def _migrate_schema_v010(app: Flask):

    try:
        with app.app_context():
            from models import db
            from sqlalchemy import text
            try:
                db.session.execute(text(
                    'ALTER TABLE netscope_devices ALTER COLUMN mac DROP NOT NULL'
                ))
                db.session.commit()
            except Exception:
                db.session.rollback()
                raise
    except Exception as e:
        try:
            app.logger.info(f"[NetScope] Migração de schema v0.10 pulada: {e}")
        except Exception:
            pass
