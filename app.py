###########################
## IMPORTING BIBLIOTECAS ##
###########################
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from logging.handlers import RotatingFileHandler
from collections import defaultdict
from dotenv import load_dotenv
from datetime import datetime
import ipaddress
import threading
import logging
import bcrypt
import socket
import struct
import fcntl
import math
import time
import json
import os

# Carregar variáveis de ambiente
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')
app.config['STATIC_FOLDER'] = 'static'

# Configurações de hardening
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Strict',
    PERMANENT_SESSION_LIFETIME=900,
    MAX_CONTENT_LENGTH=1024 * 1024,
)

# Configurações do .env
INVENTORY_DIR = os.getenv('INVENTORY_DIR')
LOG_DIR = os.getenv('LOG_DIR')
AUTH_FILE = os.getenv('AUTH_FILE')
SSL_CERT = os.getenv('SSL_CERT_PATH')
SSL_KEY = os.getenv('SSL_KEY_PATH')
USE_HTTPS = os.getenv('USE_HTTPS').lower() == 'true'
ALLOWED_IP_RANGES = os.getenv('ALLOWED_IP_RANGES').split(',')

# Configurar sistema de logs
# Criar diretórios necessários
os.makedirs(INVENTORY_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(os.path.dirname(AUTH_FILE), exist_ok=True)

# Configuração SSL
ssl_context = None
if USE_HTTPS:
    if os.path.exists(SSL_CERT) and os.path.exists(SSL_KEY):
        ssl_context = (SSL_CERT, SSL_KEY)
    else:
        app.logger.warning("Certificado SSL não encontrado. Executando HTTP")

    
# Obter IPs do servidor (apenas interfaces UP, somente IPv4)
server_ips = {'127.0.0.1', 'localhost'}
try:
    for iface in os.listdir('/sys/class/net'):
        try:
            # Verifica se a interface está UP
            with open(f'/sys/class/net/{iface}/operstate') as f:
                if f.read().strip() != 'up':
                    continue
            # Obtém o IP IPv4 da interface
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                ip = socket.inet_ntoa(fcntl.ioctl(
                    s.fileno(),
                    0x8915,  # SIOCGIFADDR
                    struct.pack('256s', iface[:15].encode('utf-8'))
                )[20:24])
                if ip and ip != '127.0.0.1':
                    server_ips.add(ip)
            except OSError:
                continue
            finally:
                s.close()
        except Exception:
            continue
except Exception as e:
    app.logger.error(f"Erro ao obter IPs do servidor: {str(e)}")
    
SERVER_IPS = list(server_ips)


# Pré-compilar redes permitidas
compiled_allowed_networks = []
if ALLOWED_IP_RANGES and any(ALLOWED_IP_RANGES):
    for ip_range in ALLOWED_IP_RANGES:
        if ip_range.strip():
            try:
                network = ipaddress.ip_network(ip_range.strip(), strict=False)
                compiled_allowed_networks.append(network)
            except ValueError as e:
                app.logger.error(f"Rede inválida {ip_range}: {str(e)}")

# Configurar loggers para diferentes níveis
def setup_logging():
    # Formato comum para todos os logs
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    
    # Handler para INFO
    info_handler = RotatingFileHandler(os.path.join(LOG_DIR, 'info.log'), maxBytes=10*1024*1024, backupCount=5)
    info_handler.setLevel(logging.INFO)
    info_handler.setFormatter(formatter)
    
    # Handler para WARNING
    warning_handler = RotatingFileHandler(os.path.join(LOG_DIR, 'warning.log'), maxBytes=10*1024*1024, backupCount=5)
    warning_handler.setLevel(logging.WARNING)
    warning_handler.setFormatter(formatter)
    
    # Handler para ERROR
    error_handler = RotatingFileHandler(os.path.join(LOG_DIR, 'error.log'), maxBytes=10*1024*1024, backupCount=5)
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(formatter)
    
    # Handler para SECURITY
    security_handler = RotatingFileHandler(os.path.join(LOG_DIR, 'security.log'), maxBytes=10*1024*1024, backupCount=5)
    security_handler.setLevel(logging.INFO)
    security_handler.setFormatter(logging.Formatter('%(asctime)s - SECURITY - %(message)s'))
    
    # Logger principal
    app.logger.setLevel(logging.DEBUG)
    app.logger.addHandler(info_handler)
    app.logger.addHandler(warning_handler)
    app.logger.addHandler(error_handler)
    
    # Logger de segurança
    security_logger = logging.getLogger('security')
    security_logger.setLevel(logging.INFO)
    security_logger.addHandler(security_handler)
    security_logger.propagate = False
    
    # Logger de auditoria
    audit_logger = logging.getLogger('audit')
    audit_handler = RotatingFileHandler(os.path.join(LOG_DIR, 'audit.log'), maxBytes=10*1024*1024, backupCount=5)
    audit_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
    audit_logger.addHandler(audit_handler)
    audit_logger.setLevel(logging.INFO)
    audit_logger.propagate = False

setup_logging()

# Obter loggers para uso
security_logger = logging.getLogger('security')
audit_logger = logging.getLogger('audit')

# Funções auxiliares
def load_json(file_path):
    """Carrega dados JSON de um arquivo com tratamento de erros"""
    try:
        if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        return None
    except (json.JSONDecodeError, IOError) as e:
        app.logger.error(f"Erro ao carregar JSON: {str(e)}")
        return None

def load_all_json_files(directory):
    """Carrega todos os arquivos JSON de um diretório"""
    data = []
    try:
        for filename in os.listdir(directory):
            if filename.endswith('.json'):
                file_path = os.path.join(directory, filename)
                json_data = load_json(file_path)
                if json_data:
                    data.append(json_data)
    except OSError as e:
        app.logger.error(f"Erro ao listar arquivos: {str(e)}")
    return data

# Cache para máquinas e estatísticas
MACHINES_CACHE = {'data': None, 'last_update': 0}
STATS_CACHE = {'data': None, 'last_update': 0}
CACHE_TIMEOUT = 15

def get_cached_machines():
    """Obtém máquinas com cache"""
    current_time = time.time()
    if not MACHINES_CACHE['data'] or (current_time - MACHINES_CACHE['last_update']) > CACHE_TIMEOUT:
        MACHINES_CACHE['data'] = get_all_machines()
        MACHINES_CACHE['last_update'] = current_time
    return MACHINES_CACHE['data']

def get_cached_stats():
    """Obtém estatísticas com cache"""
    current_time = time.time()
    if not STATS_CACHE['data'] or (current_time - STATS_CACHE['last_update']) > CACHE_TIMEOUT:
        machines = get_cached_machines()
        STATS_CACHE['data'] = get_machine_stats(machines)
        STATS_CACHE['last_update'] = current_time
    return STATS_CACHE['data']


def formatar_data(data_iso):
    """Formata data ISO para formato legível"""
    try:
        data = datetime.fromisoformat(data_iso)
        return data.strftime('%d/%m/%Y %H:%M')
    except (ValueError, TypeError):
        return data_iso

app.jinja_env.filters['formatar_data'] = formatar_data

def get_machine_stats(machines):
    """Gera estatísticas das máquinas"""
    stats = {
        'os': defaultdict(int),
        'cpu': defaultdict(int),
        'ram': defaultdict(int),
        'status': {'Ativo': 0, 'Inativo': 0},
        'ports': defaultdict(int),
        'processes': defaultdict(int),
        'total': 0
    }
    
    for machine in machines:
        # Process OS stats
        os_name = machine.get('os_name', 'Unknown')
        stats['os'][os_name] += 1
        
        # Process CPU stats
        cpu_name = machine.get('cpu_name', 'Unknown')
        stats['cpu'][cpu_name] += 1
        
        # Process RAM stats com mais granularidade
        ram_gb = machine.get('ram_gb', 0)
        if ram_gb > 0:
            if ram_gb <= 2:
                ram_range = "0-2GB"
            elif ram_gb <= 4:
                ram_range = "3-4GB"
            elif ram_gb <= 6:
                ram_range = "5-6GB"
            elif ram_gb <= 8:
                ram_range = "7-8GB"
            elif ram_gb <= 12:
                ram_range = "9-12GB"
            elif ram_gb <= 16:
                ram_range = "13-16GB"
            elif ram_gb <= 24:
                ram_range = "17-24GB"
            elif ram_gb <= 32:
                ram_range = "25-32GB"
            elif ram_gb <= 64:
                ram_range = "33-64GB"
            else:
                ram_range = "64+GB"
        else:
            ram_range = 'Unknown'
        stats['ram'][ram_range] += 1
        
        # Process status
        status = machine.get('device_status', 'Inativo')
        stats['status'][status] += 1
        
         # Process port stats
        for port in machine.get('ports', []):
            ip = port.get('local', {}).get('ip', '')
            # Verificar se é IPv4: se contém ponto ou se é um endereço IPv4 válido
            if ip and '.' in ip:  # Simplificação, mas eficaz
                port_number = port.get('local', {}).get('port', 'Unknown')
                if port_number != 'N/A' and port_number != 'Unknown':
                    stats['ports'][str(port_number)] += 1
        
        # Process process stats
        for proc in machine.get('processes', []):
            proc_name = proc.get('name', 'Unknown')
            if proc_name != 'N/A' and proc_name != 'Unknown':
                stats['processes'][proc_name] += 1
        
        stats['total'] += 1
    
    return stats
        

def process_machine_data(raw_data):
    """Processa dados brutos da máquina para formato de exibição"""
    if not raw_data or 'agent_info' not in raw_data:
        return None
        
    processed = {
        'hostname': raw_data['agent_info'].get('name', 'N/A'),
        'ip_address': raw_data['agent_info'].get('ip', 'N/A'),
        'device_status': 'Ativo' if raw_data['agent_info'].get('status') == 'active' else 'Inativo',
        'last_seen': raw_data['agent_info'].get('lastKeepAlive', 'N/A'),
        'id': raw_data['agent_info'].get('id', 'N/A'),
    }
    
    # Hardware info
    if raw_data.get('inventory', {}).get('hardware'):
        hardware = raw_data['inventory']['hardware'][0]
        processed['cpu_name'] = hardware.get('cpu', {}).get('name', 'Unknown')
        processed['cpu_cores'] = hardware.get('cpu', {}).get('cores', 'N/A')
        
        ram_total = hardware.get('ram', {}).get('total', 0)
        processed['ram_total'] = round(ram_total / (1024 * 1024), 2) if ram_total else 0
        processed['ram_gb'] = round(ram_total / (1024 * 1024)) if ram_total else 0
        processed['ram_usage'] = hardware.get('ram', {}).get('usage', 'N/A')
        processed['board_serial'] = hardware.get('board_serial', 'N/A')
    
    # OS info
    if raw_data.get('inventory', {}).get('os'):
        os_info = raw_data['inventory']['os'][0]
        processed['os_sysname'] = os_info.get('sysname', 'N/A')
        processed['os_name'] = os_info.get('os', {}).get('name', 'Unknown')
        processed['os_version'] = os_info.get('os', {}).get('version', 'N/A')
        processed['os_codename'] = os_info.get('os', {}).get('codename', '')
        processed['os_platform'] = os_info.get('os', {}).get('platform', 'N/A')
        processed['os_architecture'] = os_info.get('architecture', 'N/A')
        processed['os_full'] = f"{processed['os_name']} {processed['os_version']} ({processed['os_codename']})"
        processed['os_kernel'] = os_info.get('release', 'N/A')
    
    # Network interfaces
    processed['netiface'] = []
    if raw_data.get('inventory', {}).get('netiface'):
        for iface in raw_data['inventory']['netiface']:
            processed['netiface'].append({
                'name': iface.get('name', 'N/A'),
                'mac': iface.get('mac', 'N/A'),
                'state': iface.get('state', 'N/A'),
                'mtu': iface.get('mtu', 'N/A'),
                'type': iface.get('type', 'N/A')
            })
    
    # Network ports
    processed['ports'] = []
    if raw_data.get('inventory', {}).get('ports'):
        for port in raw_data['inventory']['ports']:
            processed['ports'].append({
                'local': {
                    'port': port.get('local', {}).get('port', 'N/A'),
                    'ip': port.get('local', {}).get('ip', 'N/A')
                },
                'process': port.get('process', 'N/A'),
                'pid': port.get('pid', 'N/A'),
                'state': port.get('state', 'N/A'),
                'protocol': port.get('protocol', 'N/A')
            })
    
    # Network addresses
    processed['netaddr'] = []
    if raw_data.get('inventory', {}).get('netaddr'):
        for addr in raw_data['inventory']['netaddr']:
            processed['netaddr'].append({
                'iface': addr.get('iface', 'N/A'),
                'address': addr.get('address', 'N/A'),
                'netmask': addr.get('netmask', 'N/A'),
                'proto': addr.get('proto', 'N/A'),
                'broadcast': addr.get('broadcast', 'N/A')
            })
    # Pacotes instalados
    processed['packages'] = []
    if raw_data.get('inventory', {}).get('packages'):
        for pkg in raw_data['inventory']['packages']:
            processed['packages'].append({
                'name': pkg.get('name', 'N/A'),
                'version': pkg.get('version', 'N/A'),
                'description': pkg.get('description', 'N/A'),
                'install_time': pkg.get('install_time', 'N/A'),
                'architecture': pkg.get('architecture', 'N/A'),
                'format': pkg.get('format', 'N/A')
            })

    # Processos em execução
    processed['processes'] = []
    if raw_data.get('inventory', {}).get('processes'):
        for proc in raw_data['inventory']['processes']:
            processed['processes'].append({
                'pid': proc.get('pid', 'N/A'),
                'name': proc.get('name', 'N/A'),
                'state': proc.get('state', 'N/A'),
                'pid': proc.get('pid', 'N/A'),
                'euser': proc.get('euser', 'N/A'),
                'cmd': proc.get('cmd', 'N/A')
            })
    
    
    return processed

def get_all_machines():
    """Obtém e processa todos os dados das máquinas"""
    raw_machines = load_all_json_files(INVENTORY_DIR)
    machines = []
    for machine in raw_machines:
        processed = process_machine_data(machine)
        if processed:
            machines.append(processed)
    return machines

def verify_password(stored_hash, password):
    """Verifica senha usando bcrypt"""
    try:
        if stored_hash.startswith('$2b$'):
            return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))
        return False
    except Exception as e:
        app.logger.error(f"Erro na verificação de senha: {str(e)}")
        return False

def is_ip_allowed(ip):
    """Verifica se o IP está em um dos ranges permitidos"""
    if not compiled_allowed_networks:
        return True  # Permite todos se não houver ranges definidos
    
    # Sempre permitir IPs do servidor
    if ip in SERVER_IPS:
        return True
        
    try:
        ip_addr = ipaddress.ip_address(ip)
        for network in compiled_allowed_networks:
            if ip_addr in network:
                return True
    except ValueError as e:
        app.logger.error(f"Erro ao verificar IP {ip}: {str(e)}")
    
    return False

# Middleware para verificar IP e tentativas de login
@app.before_request
def check_access():
    """Verifica restrições de IP e registra acesso"""
    client_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', 'Desconhecido')
    
    # Registrar acesso em log de auditoria
    if 'username' in session:
        username = session['username']
    else:
        username = 'Não autenticado'
    
    audit_logger.info(f"ACESSO - IP: {client_ip}, Usuário: {username}, Endpoint: {request.endpoint}, Método: {request.method}")
    
    # Verificar se o IP está permitido (exceto para arquivos estáticos)
    if not request.path.startswith('/static'):
        if not is_ip_allowed(client_ip):
            security_logger.warning(f"ACESSO BLOQUEADO - IP não permitido: {client_ip}, Usuário: {username}, Endpoint: {request.endpoint}")
            return render_template('error.html', error_code=403, message="Acesso não permitido a partir do seu endereço IP"), 403

# Rotas
@app.route('/')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    stats = get_cached_stats()
    
    return render_template('dashboard.html', 
                         stats=stats,
                         active_count=stats['status']['Ativo'],
                         inactive_count=stats['status']['Inativo'])

@app.route('/get_chart_data')
def get_chart_data():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    stats = get_cached_stats()
    machines = get_cached_machines()
    
    # Mapeamento de serviços conhecidos
    common_services = {
        '22': 'SSH',
        '80': 'HTTP',
        '443': 'HTTPS',
        '21': 'FTP',
        '25': 'SMTP',
        '53': 'DNS',
        '3306': 'MySQL',
        '5432': 'PostgreSQL',
        '27017': 'MongoDB',
        '6379': 'Redis',
        '11211': 'Memcached',
        '9200': 'Elasticsearch'
    }
    
    # Coletar informações sobre as portas
    port_details = defaultdict(lambda: {'count': 0, 'protocol': 'tcp'})
    
    for machine in machines:
        for port in machine.get('ports', []):
            port_num = str(port.get('local', {}).get('port', ''))
            protocol = port.get('protocol', 'tcp').lower()
            
            if port_num and port_num != 'N/A':
                port_details[port_num]['count'] += 1
                # Manter o protocolo mais comum
                if protocol == 'udp':  # Sobrescreve apenas se for UDP (para simplificar)
                    port_details[port_num]['protocol'] = protocol
    
    # Ordenar e pegar as top 10 portas
    sorted_ports = sorted(port_details.items(), key=lambda x: x[1]['count'], reverse=True)[:10]
    
    # Preparar dados para o gráfico
    port_labels = []
    port_data = []
    port_protocols = []  # Nova lista para armazenar os protocolos
    
    for port, details in sorted_ports:
        service = common_services.get(port, '')
        protocol = details['protocol'].upper()
        
        if service:
            label = f"{service} - {port}/{protocol}"
        else:
            label = f"{port}/{protocol}"
        
        port_labels.append(label)
        port_data.append(details['count'])
        port_protocols.append(details['protocol'])  # 'tcp' ou 'udp'
    
    # Ordenar e pegar os top 10 processos
    sorted_processes = sorted(stats['processes'].items(), key=lambda x: x[1], reverse=True)[:10]
    process_labels = [proc for proc, count in sorted_processes]
    process_data = [count for proc, count in sorted_processes]
    
    
    return jsonify({
        'os_labels': list(stats['os'].keys()),
        'os_data': list(stats['os'].values()),
        'cpu_labels': list(stats['cpu'].keys()),
        'cpu_data': list(stats['cpu'].values()),
        'ram_labels': list(stats['ram'].keys()),
        'ram_data': list(stats['ram'].values()),
        'port_labels': port_labels,
        'port_data': port_data,
        'port_protocols': port_protocols,  # Enviar os protocolos para o frontend
        'process_labels': process_labels,
        'process_data': process_data
    })

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        # Limitar tamanho das entradas
        username = request.form.get('username', '')[:50]
        password = request.form.get('password', '')[:100]
        client_ip = request.remote_addr
        
        # Validar entradas
        if not username or not password:
            flash('Preencha todos os campos', 'error')
            return render_template('login.html')
        
        # Carregar usuários
        users = load_json(AUTH_FILE) or []
        user = next((u for u in users if u['username'] == username), None)
        
        # Verificar credenciais
        if user and verify_password(user['password_hash'], password):
            session['username'] = username
            # Registrar login bem-sucedido
            security_logger.info(f"LOGIN BEM-SUCEDIDO - Usuário: {username}, IP: {client_ip}")
            return redirect(url_for('dashboard'))
        else:
            # Registrar tentativa falha
            security_logger.warning(f"TENTATIVA DE LOGIN FALHA - Usuário: {username}, IP: {client_ip}")
            flash('Credenciais inválidas', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    username = session.get('username', 'Desconhecido')
    client_ip = request.remote_addr
    
    # Registrar logout
    security_logger.info(f"LOGOUT - Usuário: {username}, IP: {client_ip}")
    
    session.clear()
    return redirect(url_for('login'))

@app.route('/painel')
def painel():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    page = request.args.get('page', 1, type=int)
    per_page = 50
    
    machines = get_cached_machines()
    total_machines = len(machines)
    
    # Paginação simples
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    paginated_machines = machines[start_idx:end_idx]
    
    return render_template('painel.html', 
                          machines=paginated_machines,
                          page=page,
                          per_page=per_page,
                          total=total_machines)

@app.route('/search')
def search():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Validar e sanitizar entrada
    query = request.args.get('query', '')[:100].strip().lower()
    machines = get_cached_machines()
    
    if query:
        # Verificar se é uma pesquisa por RAM (ex: "ram_gb:3-4gb")
        if query.startswith('ram_gb:'):
            ram_query = query[7:]  # Remove 'ram_gb:'
            results = []
            added_hostnames = set()
            
            # Definir os ranges de RAM
            ram_ranges = {
                "0-2gb": (0, 2),
                "3-4gb": (3, 4),
                "5-6gb": (5, 6),
                "7-8gb": (7, 8),
                "9-12gb": (9, 12),
                "13-16gb": (13, 16),
                "17-24gb": (17, 24),
                "25-32gb": (25, 32),
                "33-64gb": (33, 64),
                "64+gb": (65, float('inf'))
            }
            
            # Verificar se o query é um range válido
            if ram_query in ram_ranges:
                min_ram, max_ram = ram_ranges[ram_query]
                
                for m in machines:
                    hostname = m.get('hostname', '')
                    
                    if hostname in added_hostnames:
                        continue
                        
                    ram_gb = m.get('ram_gb', 0)
                    
                    # Verificar se a RAM está no range
                    if ram_gb >= min_ram and ram_gb <= max_ram:
                        results.append(m)
                        added_hostnames.add(hostname)
            else:
                # Se não for um range válido, tentar como valor exato
                try:
                    ram_value = float(ram_query.replace('gb', ''))
                    for m in machines:
                        hostname = m.get('hostname', '')
                        
                        if hostname in added_hostnames:
                            continue
                            
                        ram_gb = m.get('ram_gb', 0)
                        
                        if ram_gb == ram_value:
                            results.append(m)
                            added_hostnames.add(hostname)
                except ValueError:
                    # Se não for um número válido, retornar vazio
                    pass
            
            return render_template('search.html', results=results)
        
        # Restante da função original para outros tipos de pesquisa
        if ':' in query:
            tag_parts = query.split(':', 2)
            tag = tag_parts[0].strip()
            search_term = tag_parts[-1].strip()
            
            sub_tag = tag_parts[1].strip() if len(tag_parts) > 2 else None
            
            results = []
            added_hostnames = set()
            
            for m in machines:
                hostname = m.get('hostname', '')
                
                if hostname in added_hostnames:
                    continue
                    
                found = False
                
                if tag == 'ports':
                    for port in m.get('ports', []):
                        if search_term == str(port.get('local', {}).get('port', '')):
                            found = True
                            break
                            
                elif tag == 'agent_info':
                    if (search_term in m.get('hostname', '').lower() or
                        search_term in m.get('ip_address', '').lower() or
                        search_term in m.get('id', '').lower()):
                        found = True
                    
                    elif sub_tag == 'status':
                        status_map = {
                            'active': 'ativo',
                            'disconnected': 'inativo'
                        }
                        machine_status = m.get('device_status', '').lower()
                        if status_map.get(search_term) == machine_status:
                            found = True
                
                elif tag == 'inventory' and sub_tag:
                    if sub_tag == 'os':
                        if (search_term in m.get('os_name', '').lower() or
                            search_term in m.get('os_version', '').lower() or
                            search_term in m.get('os_architecture', '').lower() or
                            search_term in m.get('os_kernel', '').lower() or
                            search_term in m.get('os_platform', '').lower()):
                            found = True
                    
                    elif sub_tag == 'hardware':
                        if (search_term in m.get('cpu_name', '').lower() or
                            search_term in str(m.get('cpu_cores', '')).lower() or
                            search_term in str(m.get('ram_gb', '')).lower() or
                            search_term in m.get('board_serial', '').lower()):
                            found = True
                    
                    elif sub_tag == 'packages':
                        for pkg in m.get('packages', []):
                            if (search_term in pkg.get('name', '').lower() or
                                search_term in pkg.get('version', '').lower()):
                                found = True
                                break
                    
                    elif sub_tag == 'processes':
                        for proc in m.get('processes', []):
                            if (search_term in proc.get('name', '').lower() or
                                search_term in str(proc.get('pid', '')).lower() or
                                search_term in proc.get('cmd', '').lower()):
                                found = True
                                break
                
                if found:
                    results.append(m)
                    added_hostnames.add(hostname)
        else:
            # Pesquisa geral (sem tag)
            results = []
            added_hostnames = set()
            
            for m in machines:
                hostname = m.get('hostname', '')
                
                if hostname in added_hostnames:
                    continue
                    
                found = False
                
                if (query in m.get('hostname', '').lower() or
                    query in m.get('ip_address', '').lower() or
                    query in m.get('os_name', '').lower() or
                    query in m.get('cpu_name', '').lower() or
                    query in m.get('device_status', '').lower() or
                    query in str(m.get('ram_gb', 0))):
                    found = True
                    
                if not found:
                    for iface in m.get('netiface', []):
                        if (query in iface.get('name', '').lower() or
                            query in iface.get('mac', '').lower()):
                            found = True
                            break
                            
                if not found:
                    for addr in m.get('netaddr', []):
                        if (query in addr.get('iface', '').lower() or
                            query in addr.get('address', '').lower()):
                            found = True
                            break
                            
                if not found:
                    for port in m.get('ports', []):
                        if (query in str(port.get('local', {}).get('port', '')) or
                            query in port.get('process', '').lower()):
                            found = True
                            break
                            
                if not found:
                    for proc in m.get('processes', []):
                        if (query in str(proc.get('pid', '')).lower() or
                            query in proc.get('name', '').lower() or
                            query in proc.get('euser', '').lower() or
                            query in proc.get('cmd', '').lower()):
                            found = True
                            break

                if not found:
                    for pkg in m.get('packages', []):
                        if (query in pkg.get('name', '').lower() or
                            query in pkg.get('version', '').lower() or
                            query in pkg.get('description', '').lower() or
                            query in pkg.get('architecture', '').lower() or
                            query in pkg.get('format', '').lower()):
                            found = True
                            break
                
                if not found:
                    if (query in m.get('os_version', '').lower() or
                        query in m.get('os_platform', '').lower() or
                        query in m.get('os_architecture', '').lower() or
                        query in m.get('board_serial', '').lower() or
                        query in m.get('os_kernel', '').lower()):
                        found = True
                
                if found:
                    results.append(m)
                    added_hostnames.add(hostname)
    else:
        results = machines
    
    return render_template('search.html', results=results)

@app.route('/machine/<hostname>')
def machine_details(hostname):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Validar hostname
    if not hostname.replace('.', '').replace('-', '').isalnum():
        flash('Nome de host inválido', 'error')
        return redirect(url_for('painel'))
    
    machines = get_cached_machines()
    machine = next((m for m in machines if m.get('hostname') == hostname), None)
    
    if not machine:
        flash('Máquina não encontrada', 'error')
        return redirect(url_for('painel'))
    
    return render_template('machine_details.html', machine=machine)

@app.route('/settings')
def settings():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    machines = get_cached_machines()
    return render_template('settings.html', machines=machines)

@app.route('/get_data')
def get_data():
    if 'username' not in session:
        return redirect(url_for('login'))

    script_path = os.path.join(os.path.dirname(__file__), 'utils', 'get_data.py')
    try:
        os.popen(f'python3 {script_path} &')
        app.logger.info("Coleta de dados iniciada")
        flash('Coleta de dados iniciada, aguarde alguns minutos.', 'success')
        return redirect(url_for('dashboard'))
    except Exception as e:
        app.logger.error(f"Erro ao iniciar coleta: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Template de erro básico para evitar falhas
@app.errorhandler(404)
@app.errorhandler(403)
@app.errorhandler(500)
@app.errorhandler(502)
@app.errorhandler(503)
@app.errorhandler(504)
def handle_errors(error):
    code = error.code if hasattr(error, 'code') else 500
    client_ip = request.remote_addr
    username = session.get('username', 'Desconhecido')
    
    # Registrar erros no log apropriado
    error_message = f"Erro {code} - IP: {client_ip}, Usuário: {username}, Endpoint: {request.endpoint}"
    app.logger.error(error_message)
    
    # Criar template de erro dinâmico
    messages = {
        403: "Acesso proibido",
        404: "Página não encontrada",
        500: "Erro interno do servidor",
        502: "Bad Gateway",
        503: "Serviço indisponível",
        504: "Gateway Timeout"
    }
    
    title = messages.get(code, "Erro desconhecido")
    message = f"Ocorreu um erro {code} ao processar sua requisição."
    
    return render_template('error.html', 
                          error_code=code,
                          title=title,
                          message=message,
                          error_details=error_message), code


if __name__ == '__main__':
    
    # Configurações do servidor
    host = os.getenv('HOST', '0.0.0.0')
    port = int(os.getenv('PORT'))
    debug = os.getenv('DEBUG', 'False').lower() == 'true'
    
    print(f" * IPs do servidor: {SERVER_IPS}")
    print(f" * Redes permitidas: {ALLOWED_IP_RANGES}")
    
    app.run(
        debug=debug,
        host=host,
        port=port,
        ssl_context=ssl_context
    )