import os
import json
import time
import shutil
import random
import logging
import requests
import urllib3
from datetime import datetime, timedelta
from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, '..', 'data')
INVENTORY_FOLDER = os.path.join(DATA_DIR, 'inventory')
OLD_HOSTS_DIR = os.path.join(INVENTORY_FOLDER, 'hosts_antigos')
LOGS_DIR = os.path.join(BASE_DIR, '..', 'logs')
DEFAULT_STATUS = 'Desligado'
ENDPOINTS = [
    'hardware', 'os', 'packages', 'ports',
    'processes', 'netaddr', 'netiface', 'netproto'
]
MIN_REQUEST_INTERVAL = 0.2  
MAX_RETRIES = 3
RETRY_DELAY_BASE = 1.0    


def setup_directories():
    """Cria diretórios necessários se não existirem"""
    os.makedirs(INVENTORY_FOLDER, exist_ok=True)
    os.makedirs(OLD_HOSTS_DIR, exist_ok=True)
    os.makedirs(LOGS_DIR, exist_ok=True)


def setup_logging():
    """Configura sistema de logs para console e arquivo"""
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    fmt = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

    ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    log_file = os.path.join(LOGS_DIR, 'get_data.log')
    fh = logging.FileHandler(log_file)
    fh.setFormatter(fmt)
    logger.addHandler(fh)


class WazuhAPI:
    """Encapsula operações de API com rate limiting e retry"""
    def __init__(self, protocol, host, port, user, password):
        self.base_url = f"{protocol}://{host}:{port}"
        self.session = requests.Session()
        self.session.verify = False
        # Apenas para autenticação inicial
        self.session.auth = (user, password)
        self.token = None
        self._last_req = 0.0

    def authenticate(self) -> bool:
        """Obtém token JWT da API e desabilita basic auth após sucesso"""
        url = f"{self.base_url}/security/user/authenticate?raw=true"
        try:
            resp = self._request('GET', url, timeout=10)
            self.token = resp.text.strip()
            # Atualiza header e remove credenciais básicas
            self.session.headers.update({'Authorization': f'Bearer {self.token}'})
            self.session.auth = None
            logging.info('Autenticação bem-sucedida')
            return True
        except Exception as e:
            logging.error(f'Falha na autenticação: {e}')
            return False

    def _request(self, method, url, **kwargs):
        """Requisição com rate limiting e retry exponencial"""
        elapsed = time.time() - self._last_req
        if elapsed < MIN_REQUEST_INTERVAL:
            time.sleep(MIN_REQUEST_INTERVAL - elapsed)

        for attempt in range(MAX_RETRIES + 1):
            try:
                resp = self.session.request(method, url, **kwargs)
                resp.raise_for_status()
                self._last_req = time.time()
                return resp
            except requests.RequestException as e:
                if attempt < MAX_RETRIES:
                    delay = RETRY_DELAY_BASE * (2 ** attempt) + random.random() * 0.1
                    logging.warning(
                        f'Requisição a {url} falhou (tentativa {attempt+1}): {e}. ' \
                        f'Retentando em {delay:.2f}s...'
                    )
                    time.sleep(delay)
                else:
                    logging.error(f'Erro crítico na requisição a {url}: {e}')
                    raise

    def get_json(self, endpoint):
        """GET autenticado e retorna JSON, com log detalhado em caso de falha"""
        url = f"{self.base_url}/{endpoint}"
        try:
            resp = self._request('GET', url, timeout=30)
            return resp.json()
        except Exception as e:
            logging.error(f'Falha ao obter JSON de {url}: {e}')
            return {}

class InventoryManager:
    """Gerencia extração e armazenamento de inventário"""
    def __init__(self, api: WazuhAPI):
        self.api = api

    @staticmethod
    def _determine_status(last_seen: str) -> str:
        """Define status com base no último keepalive"""
        if not last_seen or last_seen == 'unknown':
            return DEFAULT_STATUS
        try:
            ts = last_seen.rstrip('Z') + '+00:00' if last_seen.endswith('Z') else last_seen
            delta = datetime.now(datetime.fromisoformat(ts).tzinfo) - datetime.fromisoformat(ts)
            return 'Ligado' if delta <= timedelta(days=30) else DEFAULT_STATUS
        except Exception as e:
            logging.error(f"Timestamp inválido '{last_seen}': {e}")
            return DEFAULT_STATUS

    @staticmethod
    def _clean_data(obj):
        """Remove campos internos de dicionários e listas"""
        if isinstance(obj, dict):
            return {
                k: InventoryManager._clean_data(v)
                for k, v in obj.items()
                if k not in ('agent_id', 'scan_id', 'scan_time')
            }
        if isinstance(obj, list):
            return [InventoryManager._clean_data(i) for i in obj]
        return obj

    def _fetch_inventory(self, agent_id: int) -> dict:
        """Chama endpoints do syscollector"""
        inv = {}
        for ep in ENDPOINTS:
            data = self.api.get_json(f"syscollector/{agent_id}/{ep}")
            items = data.get('data', {}).get('affected_items', [])
            inv[ep] = [self._clean_data(it) for it in items]
        return inv

    @staticmethod
    def _save_json(name: str, content: dict) -> None:
        """Serializa inventário em arquivo JSON"""
        path = os.path.join(INVENTORY_FOLDER, f"{name}.json")
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(content, f, ensure_ascii=False, indent=4)
        logging.info(f"Inventário salvo: {name}")

    def _process_agent(self, agent: dict) -> str:
        """Processa um agente e retorna hostname seguro"""
        agent_id = agent.get('id')
        agent['calculated_status'] = self._determine_status(agent.get('lastKeepAlive', 'unknown'))
        inv = self._fetch_inventory(agent_id)
        hostname = (
            inv.get('os', [{}])[0].get('hostname')
            or agent.get('name', 'unknown')
        ).upper().strip() or 'UNKNOWN'
        safe = ''.join(c for c in hostname if c.isalnum() or c in '.-_ ').strip()
        self._save_json(safe, {'agent_info': agent, 'inventory': inv})
        return safe

    def process_agents(self, max_workers: int = 5) -> set:
        """Processa todos os agentes usando ThreadPoolExecutor"""
        existing = set(os.listdir(INVENTORY_FOLDER))
        resp = self.api.get_json(
            'agents?select=id,name,ip,lastKeepAlive,status,os.platform,os.name,os.version'
        )
        agents = resp.get('data', {}).get('affected_items', [])
        if not agents:
            logging.warning('Nenhum agente encontrado')
            return set()

        processed = set()
        with ThreadPoolExecutor(max_workers=max_workers) as exe:
            futures = {exe.submit(self._process_agent, ag): ag for ag in agents}
            for fut in as_completed(futures):
                try:
                    name = fut.result()
                    processed.add(name)
                except Exception as e:
                    logging.error(f"Erro em agente: {e}")

        self._archive_old(existing, processed)
        return processed

    @staticmethod
    def _archive_old(before: set, current: set) -> None:
        """Move arquivos antigos não processados"""
        moved = 0
        for fn in before:
            if not fn.endswith('.json'):
                continue
            name = os.path.splitext(fn)[0]
            if name not in current:
                src = os.path.join(INVENTORY_FOLDER, fn)
                dst = os.path.join(OLD_HOSTS_DIR, fn)
                shutil.move(src, dst)
                moved += 1
        logging.info(f"{moved} arquivos antigos movidos")

def main():
    setup_directories()
    setup_logging()

    try:
        load_dotenv(os.path.join(BASE_DIR, '..', '.env'))
    except Exception as e:
        logging.error(f"Erro ao carregar .env: {e}")
        return

    api = WazuhAPI(
        protocol=os.getenv('WAZUH_PROTOCOL', 'https'),
        host=os.getenv('WAZUH_HOST', ''),
        port=os.getenv('WAZUH_PORT', '55000'),
        user=os.getenv('WAZUH_USER', ''),
        password=os.getenv('WAZUH_PASSWORD', '')
    )

    if not api.authenticate():
        logging.error('Autenticação crítica falhou. Saindo.')
        return

    start = time.time()
    inv_mgr = InventoryManager(api)
    hosts = inv_mgr.process_agents(max_workers=5)
    elapsed = time.time() - start

    logging.info(f"Processados {len(hosts)} hosts em {elapsed:.2f}s")


if __name__ == '__main__':
    main()
