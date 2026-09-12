
from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler

def setup_logging(app, log_dir: str) -> None:
    os.makedirs(log_dir, exist_ok=True)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

    info_handler = RotatingFileHandler(
        os.path.join(log_dir, 'info.log'),
        maxBytes=10 * 1024 * 1024, backupCount=5)
    info_handler.setLevel(logging.INFO)
    info_handler.setFormatter(formatter)

    warning_handler = RotatingFileHandler(
        os.path.join(log_dir, 'warning.log'),
        maxBytes=10 * 1024 * 1024, backupCount=5)
    warning_handler.setLevel(logging.WARNING)
    warning_handler.setFormatter(formatter)

    error_handler = RotatingFileHandler(
        os.path.join(log_dir, 'error.log'),
        maxBytes=10 * 1024 * 1024, backupCount=5)
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(formatter)

    security_handler = RotatingFileHandler(
        os.path.join(log_dir, 'security.log'),
        maxBytes=10 * 1024 * 1024, backupCount=5)
    security_handler.setLevel(logging.INFO)
    security_handler.setFormatter(
        logging.Formatter('%(asctime)s - SECURITY - %(message)s'))

    app.logger.setLevel(logging.DEBUG)
    for handler in (info_handler, warning_handler, error_handler):
        app.logger.addHandler(handler)

    security_logger = logging.getLogger('security')
    security_logger.setLevel(logging.INFO)
    security_logger.addHandler(security_handler)
    security_logger.propagate = False

    audit_logger = logging.getLogger('audit')
    audit_handler = RotatingFileHandler(
        os.path.join(log_dir, 'audit.log'),
        maxBytes=10 * 1024 * 1024, backupCount=5)
    audit_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
    audit_logger.addHandler(audit_handler)
    audit_logger.setLevel(logging.INFO)
    audit_logger.propagate = False
