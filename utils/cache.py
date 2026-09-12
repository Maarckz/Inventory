
import json
import logging
import os
import time

try:
    import redis
except ImportError:
    redis = None

logger = logging.getLogger(__name__)

REDIS_URL = os.getenv('REDIS_URL', '').strip()

_PREFIX = 'inventory:'

TTL_MACHINES = int(os.getenv('REDIS_TTL_MACHINES', 3600))
TTL_STATS = int(os.getenv('REDIS_TTL_STATS', 40))

_client = None
_mode = 'memory'

def _connect():

    global _client, _mode
    if not REDIS_URL:
        _mode = 'memory'
        return None

    if REDIS_URL.startswith('fakeredis'):
        try:
            import fakeredis
            _client = fakeredis.FakeRedis()
            _mode = 'fakeredis'
            logger.info('[Cache] fakeredis ativo (modo teste — Redis em memória do processo).')
            return _client
        except ImportError:
            logger.warning('[Cache] fakeredis solicitado mas não instalado — usando memória.')
            _mode = 'memory'
            return None

    if redis is None:
        logger.warning('[Cache] REDIS_URL definido mas o pacote "redis" não está instalado — usando memória.')
        _mode = 'memory'
        return None
    try:
        client = redis.Redis.from_url(
            REDIS_URL,
            socket_connect_timeout=1,
            socket_timeout=1,
            decode_responses=False,
        )
        client.ping()
        _client = client
        _mode = 'redis'
        logger.info(f'[Cache] Redis conectado ({REDIS_URL}) — cache compartilhado entre workers.')
        return _client
    except Exception as exc:
        logger.warning(f'[Cache] Redis em {REDIS_URL} indisponível ({exc}) — usando cache em memória.')
        _mode = 'memory'
        _client = None
        return None

def cache_mode():

    return _mode

def get_json(key, default=None):

    if _client is not None:
        try:
            raw = _client.get(_PREFIX + key)
            if raw is not None:
                return json.loads(raw)
        except Exception as exc:
            logger.warning(f'[Cache] falha lendo "{key}" do Redis: {exc}')
    return default

def set_json(key, value, ttl=None):

    if _client is None:
        return False
    try:
        payload = json.dumps(value, ensure_ascii=False, default=str)
        _client.set(_PREFIX + key, payload, ex=ttl)
        return True
    except Exception as exc:
        logger.warning(f'[Cache] falha gravando "{key}" no Redis: {exc}')
        return False

def invalidate(*keys):

    if _client is None:
        return False
    try:
        if keys:
            _client.delete(*(_PREFIX + k for k in keys))
        return True
    except Exception as exc:
        logger.warning(f'[Cache] falha invalidando {keys} no Redis: {exc}')
        return False

def ping():

    if _client is None:
        return {'mode': _mode, 'ok': _mode == 'memory'}
    try:
        _client.ping()
        return {'mode': _mode, 'ok': True}
    except Exception as exc:
        return {'mode': _mode, 'ok': False, 'error': str(exc)}

_connect()
