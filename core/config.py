
from __future__ import annotations

import ipaddress
import os
import socket
import struct
import fcntl

from dotenv import load_dotenv

load_dotenv()

APP_VERSION = '0.18.29'

db_user = os.getenv("DB_USER")
db_pass = os.getenv("DB_PASS")
db_host = os.getenv("DB_HOST", "localhost")
db_port = os.getenv("DB_PORT", "5432")
db_name = os.getenv("DB_NAME")

def get_database_url() -> str:
    override = os.getenv('DATABASE_URL', '').strip()
    if override:
        return override
    if not all([db_user, db_pass, db_name]):
        raise RuntimeError("Variáveis de banco incompletas")
    return (
        f"postgresql+psycopg2://{db_user}:"
        f"{db_pass}@{db_host}:{db_port}/{db_name}"
    )

LOG_DIR = os.getenv('LOG_DIR', 'logs')
SSL_CERT = os.getenv('SSL_CERT_PATH')
SSL_KEY = os.getenv('SSL_KEY_PATH')

GROQ_API_KEY = (os.getenv('GROQ_API_KEY') or '').strip()
GROQ_MODEL = (os.getenv('GROQ_MODEL') or '').strip()
GROQ_BASE_URL = (os.getenv('GROQ_BASE_URL') or '').strip()

def https_enabled() -> bool:
    return (os.getenv('USE_HTTPS') or '').lower() == 'true'

def get_ssl_context():

    if https_enabled() and SSL_CERT and SSL_KEY:
        if os.path.exists(SSL_CERT) and os.path.exists(SSL_KEY):
            return (SSL_CERT, SSL_KEY)
    return None

def discover_server_ips() -> list:

    ips = {'127.0.0.1', 'localhost'}
    try:
        for iface in os.listdir('/sys/class/net'):
            try:
                with open(f'/sys/class/net/{iface}/operstate') as f:
                    if f.read().strip() != 'up':
                        continue
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    ip = socket.inet_ntoa(fcntl.ioctl(
                        s.fileno(),
                        0x8915,
                        struct.pack('256s', iface[:15].encode('utf-8'))
                    )[20:24])
                    if ip and ip != '127.0.0.1':
                        ips.add(ip)
                except OSError:
                    continue
                finally:
                    s.close()
            except Exception:
                continue
    except Exception:
        pass
    return list(ips)

def compile_allowed_networks(raw):

    compiled = []
    ranges = (raw or '').split(',')
    if ranges and any(ranges):
        for ip_range in ranges:
            if ip_range.strip():
                try:
                    compiled.append(
                        ipaddress.ip_network(ip_range.strip(), strict=False))
                except ValueError:
                    continue
    return compiled
