###########################
## IMPORTING BIBLIOTECAS ##
###########################
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, make_response
from logging.handlers import RotatingFileHandler
from utils.pdf_export import generate_pdf_report
from datetime import datetime, timedelta
from utils.language import LANGUAGES
from collections import defaultdict
from flask_session import Session
from dotenv import load_dotenv
from datetime import datetime
from io import BytesIO
import ipaddress
import logging
import bcrypt
import socket
import struct
import base64
import qrcode
import fcntl
import pyotp
import time
import json
import os


load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')
app.config['STATIC_FOLDER'] = 'static'

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Strict',
    PERMANENT_SESSION_LIFETIME=900,
    MAX_CONTENT_LENGTH=1024 * 1024,
    SESSION_SALT=os.getenv('SESSION_SALT', 'default_salt_value')
)

app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = os.path.join(os.getenv('LOG_DIR'), 'flask_sessions')
app.config['SESSION_PERMANENT'] = True
Session(app)

INVENTORY_DIR = os.getenv('INVENTORY_DIR')
GROUPS_DIR = os.getenv('GROUPS_DIR')
LOG_DIR = os.getenv('LOG_DIR')
AUTH_FILE = os.getenv('AUTH_FILE')
SSL_CERT = os.getenv('SSL_CERT_PATH')
SSL_KEY = os.getenv('SSL_KEY_PATH')
USE_HTTPS = os.getenv('USE_HTTPS').lower() == 'true'
ALLOWED_IP_RANGES = os.getenv('ALLOWED_IP_RANGES').split(',')

os.makedirs(INVENTORY_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(os.path.dirname(AUTH_FILE), exist_ok=True)
os.makedirs(app.config['SESSION_FILE_DIR'], exist_ok=True)  # Diretório para sessões

ssl_context = None
if USE_HTTPS:
    if os.path.exists(SSL_CERT) and os.path.exists(SSL_KEY):
        ssl_context = (SSL_CERT, SSL_KEY)
    else:
        app.logger.warning("Certificado SSL não encontrado. Executando HTTP")

server_ips = {'127.0.0.1', 'localhost'}
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

compiled_allowed_networks = []
if ALLOWED_IP_RANGES and any(ALLOWED_IP_RANGES):
    for ip_range in ALLOWED_IP_RANGES:
        if ip_range.strip():
            try:
                network = ipaddress.ip_network(ip_range.strip(), strict=False)
                compiled_allowed_networks.append(network)
            except ValueError as e:
                app.logger.error(f"Rede inválida {ip_range}: {str(e)}")

def setup_logging():
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    
    info_handler = RotatingFileHandler(os.path.join(LOG_DIR, 'info.log'), maxBytes=10*1024*1024, backupCount=5)
    info_handler.setLevel(logging.INFO)
    info_handler.setFormatter(formatter)
    
    warning_handler = RotatingFileHandler(os.path.join(LOG_DIR, 'warning.log'), maxBytes=10*1024*1024, backupCount=5)
    warning_handler.setLevel(logging.WARNING)
    warning_handler.setFormatter(formatter)
    
    error_handler = RotatingFileHandler(os.path.join(LOG_DIR, 'error.log'), maxBytes=10*1024*1024, backupCount=5)
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(formatter)
    
    security_handler = RotatingFileHandler(os.path.join(LOG_DIR, 'security.log'), maxBytes=10*1024*1024, backupCount=5)
    security_handler.setLevel(logging.INFO)
    security_handler.setFormatter(logging.Formatter('%(asctime)s - SECURITY - %(message)s'))
    
    app.logger.setLevel(logging.DEBUG)
    app.logger.addHandler(info_handler)
    app.logger.addHandler(warning_handler)
    app.logger.addHandler(error_handler)
    
    security_logger = logging.getLogger('security')
    security_logger.setLevel(logging.INFO)
    security_logger.addHandler(security_handler)
    security_logger.propagate = False
    
    audit_logger = logging.getLogger('audit')
    audit_handler = RotatingFileHandler(os.path.join(LOG_DIR, 'audit.log'), maxBytes=10*1024*1024, backupCount=5)
    audit_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
    audit_logger.addHandler(audit_handler)
    audit_logger.setLevel(logging.INFO)
    audit_logger.propagate = False

setup_logging()

security_logger = logging.getLogger('security')
audit_logger = logging.getLogger('audit')

def load_json(file_path):
    try:
        if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        return None
    except (json.JSONDecodeError, IOError) as e:
        app.logger.error(f"Erro ao carregar JSON: {str(e)}")
        return None

def load_all_json_files(directory):
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

MACHINES_CACHE = {'data': None, 'last_update': 0}
STATS_CACHE = {'data': None, 'last_update': 0}
CACHE_TIMEOUT = 40

def get_cached_machines():
    current_time = time.time()
    if not MACHINES_CACHE['data'] or (current_time - MACHINES_CACHE['last_update']) > CACHE_TIMEOUT:
        MACHINES_CACHE['data'] = get_all_machines()
        MACHINES_CACHE['last_update'] = current_time
    return MACHINES_CACHE['data']

def get_cached_stats():
    current_time = time.time()
    if not STATS_CACHE['data'] or (current_time - STATS_CACHE['last_update']) > CACHE_TIMEOUT:
        machines = get_cached_machines()
        STATS_CACHE['data'] = get_machine_stats(machines)
        STATS_CACHE['last_update'] = current_time
    return STATS_CACHE['data']


def formatar_data(data_iso):
    try:
        data = datetime.fromisoformat(data_iso)
        return data.strftime('%d/%m/%Y %H:%M')
    except (ValueError, TypeError):
        return data_iso

app.jinja_env.filters['formatar_data'] = formatar_data

def get_ram_range(ram_gb):
    ranges = [
        (2, "0-2GB"), (4, "3-4GB"), (8, "5-8GB"),
        (16, "9-16GB"), (32, "17-32GB"), (64, "33-64GB")
    ]
    for limit, label in ranges:
        if ram_gb <= limit:
            return label
    return "64+GB" if ram_gb > 0 else "Unknown"

def get_machine_stats(machines):
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
        stats['ram'][get_ram_range(ram_gb)] += 1
        
        status = machine.get('device_status', 'Inativo')
        stats['status'][status] += 1
        
        for port in machine.get('ports', []):
            ip = port.get('local', {}).get('ip', '')
            if ip and '.' in ip:  # Simplificação, mas eficaz
                port_number = port.get('local', {}).get('port', 'Unknown')
                if port_number != 'N/A' and port_number != 'Unknown':
                    stats['ports'][str(port_number)] += 1
        
        for proc in machine.get('processes', []):
            proc_name = proc.get('name', 'Unknown')
            if proc_name != 'N/A' and proc_name != 'Unknown':
                stats['processes'][proc_name] += 1
        
        stats['total'] += 1
    
    return stats
        

def process_machine_data(raw_data):
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
    raw_machines = load_all_json_files(INVENTORY_DIR)
    machines = []
    for machine in raw_machines:
        processed = process_machine_data(machine)
        if processed:
            machines.append(processed)
    return machines

def verify_password(stored_hash, password):
    try:
        if stored_hash.startswith('$2b$'):
            return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))
        return False
    except Exception as e:
        app.logger.error(f"Erro na verificação de senha: {str(e)}")
        return False

def is_ip_allowed(ip):
    if not compiled_allowed_networks:
        return True 
    
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

@app.before_request
def check_access():
    client_ip = request.remote_addr
    #user_agent = request.headers.get('User-Agent', 'Desconhecido')
    
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
@app.route('/dashboard')
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
        '9200': 'Elk'
    }
    
    port_details = defaultdict(lambda: {'count': 0, 'protocol': 'tcp'})
    
    for machine in machines:
        for port in machine.get('ports', []):
            port_num = str(port.get('local', {}).get('port', ''))
            protocol = port.get('protocol', 'tcp').lower()
            
            if port_num and port_num != 'N/A':
                port_details[port_num]['count'] += 1
                if protocol == 'udp':  
                    port_details[port_num]['protocol'] = protocol
    
    sorted_ports = sorted(port_details.items(), key=lambda x: x[1]['count'], reverse=True)[:10]
    
    port_labels = []
    port_data = []
    port_protocols = []
    
    for port, details in sorted_ports:
        service = common_services.get(port, '')
        protocol = details['protocol'].upper()
        
        if service:
            label = f"{service} - {port}/{protocol}"
        else:
            label = f"{port}/{protocol}"
        
        port_labels.append(label)
        port_data.append(details['count'])
        port_protocols.append(details['protocol'])

    sorted_processes = sorted(stats['processes'].items(), key=lambda x: x[1], reverse=True)[:10]
    process_labels = [proc for proc, count in sorted_processes]
    process_data = [count for proc, count in sorted_processes]
    
    groups = []
    with open(os.path.join(GROUPS_DIR, 'groups.json')) as f:
        groups = json.load(f)
    
    # Obter máquinas recentemente adicionadas (últimas 5 por data)
    recent_machines = sorted(machines, 
                           key=lambda x: x.get('last_seen', ''),
                           reverse=True)[:5]
    
    # Preparar dados para timeline (últimos 7 dias)
    timeline_data = {'dates': [], 'active': [], 'inactive': []}
    today = datetime.now().date()
    
    for i in range(6, -1, -1):
        date = today - timedelta(days=i)
        date_str = date.strftime('%d/%m')
        timeline_data['dates'].append(date_str)
        
        # Contar máquinas ativas/inativas para cada dia
        active_count = 0
        inactive_count = 0
        
        for machine in machines:
            if machine.get('last_seen') != 'N/A':
                try:
                    machine_date = datetime.fromisoformat(machine['last_seen']).date()
                    if machine_date == date:
                        if machine.get('device_status') == 'Ativo':
                            active_count += 1
                        else:
                            inactive_count += 1
                except (ValueError, TypeError):
                    continue
        
        timeline_data['active'].append(active_count)
        timeline_data['inactive'].append(inactive_count)
    
    return jsonify({
        'os_labels': list(stats['os'].keys()),
        'os_data': list(stats['os'].values()),
        'cpu_labels': list(stats['cpu'].keys()),
        'cpu_data': list(stats['cpu'].values()),
        'ram_labels': list(stats['ram'].keys()),
        'ram_data': list(stats['ram'].values()),
        'port_labels': port_labels,
        'port_data': port_data,
        'port_protocols': port_protocols,
        'process_labels': process_labels,
        'process_data': process_data,
        'active_count': stats.get('status', {}).get('Ativo', 0),
        'inactive_count': stats.get('status', {}).get('Inativo', 0),
        'last_update': [machine.get('agent_info', {}).get('lastKeepAlive', 0) for machine in machines],
        'groups': groups,
        'timeline_dates': timeline_data['dates'],
        'timeline_active': timeline_data['active'],
        'timeline_inactive': timeline_data['inactive'],
        'recent_machines': [
            {
                'name': m.get('hostname', 'N/A'),
                'os': m.get('os_name', 'N/A'),
                'status': m.get('device_status', 'N/A')
            } for m in recent_machines
        ]
    })

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '')[:50]
        password = request.form.get('password', '')[:100]
        client_ip = request.remote_addr
        
        if not username or not password:
            flash('Preencha todos os campos', 'error')
            #flash(translate('Preencha todos os campos'), 'categoria')
            return render_template('login.html')
        
        users = load_json(AUTH_FILE) or []
        user = next((u for u in users if u['username'] == username), None)
        
        if user and verify_password(user['password_hash'], password):
            if user.get('mfa_enabled', False):
                session['mfa_username'] = username
                session['mfa_expire'] = time.time() + 300  
                return redirect(url_for('verify_mfa'))
            
            session['username'] = username
            session['user_ip'] = client_ip  
            session['user_agent'] = request.headers.get('User-Agent', '') 
            session['login_time'] = time.time() 
            
            security_logger.info(f"LOGIN BEM-SUCEDIDO - Usuário: {username}, IP: {client_ip}")
            return redirect(url_for('dashboard'))
        else:
            security_logger.warning(f"TENTATIVA DE LOGIN FALHA - Usuário: {username}, IP: {client_ip}")
            #flash(translate('Credenciais inválidas'), 'categoria')
            flash('Credenciais inválidas', 'error')
    
    return render_template('login.html')

@app.route('/verify_mfa', methods=['GET', 'POST'])
def verify_mfa():
    if 'mfa_username' not in session or time.time() > session.get('mfa_expire', 0):
        #flash(translate('Sessão expirada. Faça login novamente'), 'categoria')
        flash('Sessão expirada. Faça login novamente', 'error')
        session.pop('mfa_username', None)
        return redirect(url_for('login'))
    
    username = session['mfa_username']
    
    if request.method == 'POST':
        code = request.form.get('code', '')
        users = load_json(AUTH_FILE) or []
        user = next((u for u in users if u['username'] == username), None)
        
        if user and user.get('mfa_enabled', False) and user.get('mfa_secret'):
            totp = pyotp.TOTP(user['mfa_secret'])
            if totp.verify(code, valid_window=1):
                session.pop('mfa_username', None)
                session['username'] = username
                session['user_ip'] = request.remote_addr  
                session['user_agent'] = request.headers.get('User-Agent', '') 
                session['login_time'] = time.time() 
                
                security_logger.info(f"LOGIN MFA BEM-SUCEDIDO - Usuário: {username}, IP: {request.remote_addr}")
                return redirect(url_for('dashboard'))
        
        #flash(translate('Código MFA inválido'), 'categoria')
        flash('Código MFA inválido', 'error')
    
    return render_template('verify_mfa.html')

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
    
    # Limpeza inicial da query
    query = request.args.get('query', '')[:100].strip().lower()
    machines = get_cached_machines()
    results = []
    added_hostnames = set()

    if not query:
        return render_template('search.html', results=machines, query="")

    # --- LÓGICA ESPECIAL PARA RAM (RANGE E VALORES) ---
    if query.startswith('ram_gb:'):
        # Remove prefixo e a unidade 'gb' para pegar apenas os números/range
        ram_query = query.replace('ram_gb:', '').replace('gb', '').strip()
        
        # Mapeamento de ranges (deve ser idêntico aos labels do Chart.js)
        ram_ranges = {
            "0-2": (0, 2),
            "3-4": (3, 4),
            "5-6": (5, 6),
            "7-8": (7, 8),
            "9-12": (9, 12),
            "13-16": (13, 16),
            "17-24": (17, 24),
            "25-32": (25, 32),
            "33-64": (33, 64)
        }

        for m in machines:
            try:
                # Converte ram_gb da máquina para float para comparação precisa
                ram_val = float(m.get('ram_gb', 0))
                
                # Caso 1: Range (ex: 17-32)
                if "-" in ram_query:
                    if ram_query in ram_ranges:
                        min_r, max_r = ram_ranges[ram_query]
                    else:
                        # Tenta extrair range manual se não estiver no dicionário
                        parts = ram_query.split('-')
                        min_r, max_r = float(parts[0]), float(parts[1])
                    
                    if min_r <= ram_val <= max_r:
                        results.append(m)
                
                # Caso 2: Maior que (ex: >64)
                elif ram_query.startswith('>'):
                    limit = float(ram_query.replace('>', ''))
                    if ram_val > limit:
                        results.append(m)
                
                # Caso 3: Menor que (ex: <8)
                elif ram_query.startswith('<'):
                    limit = float(ram_query.replace('<', ''))
                    if ram_val < limit:
                        results.append(m)

                # Caso 4: Valor exato ou aproximado
                else:
                    if float(ram_query) == ram_val:
                        results.append(m)
            except (ValueError, IndexError):
                continue
        
        return render_template('search.html', results=results, query=query)

    # --- LÓGICA PARA TAGS (ports:, agent_info:, inventory:xxx:) ---
    if ':' in query:
        tag_parts = query.split(':')
        tag = tag_parts[0].strip()
        
        # Pega o último termo como termo de busca
        search_term = tag_parts[-1].strip()
        # Sub-tag se existir (ex: inventory:os:windows -> sub_tag é 'os')
        sub_tag = tag_parts[1].strip() if len(tag_parts) > 2 else None
        
        for m in machines:
            hostname = m.get('hostname', '')
            if hostname in added_hostnames: continue
            found = False
            
            if tag == 'ports':
                for port in m.get('ports', []):
                    if search_term == str(port.get('local', {}).get('port', '')):
                        found = True; break
            
            elif tag == 'agent_info':
                if (search_term in m.get('hostname', '').lower() or
                    search_term in m.get('ip_address', '').lower() or
                    search_term in m.get('id', '').lower()):
                    found = True
                elif sub_tag == 'status':
                    status_map = {'active': 'ativo', 'disconnected': 'inativo'}
                    if status_map.get(search_term) == m.get('device_status', '').lower():
                        found = True
            
            elif tag == 'inventory' and sub_tag:
                if sub_tag == 'os':
                    if any(search_term in str(m.get(k, '')).lower() for k in ['os_name', 'os_version', 'os_architecture', 'os_kernel', 'os_platform']):
                        found = True
                elif sub_tag == 'hardware':
                    if (search_term in m.get('cpu_name', '').lower() or
                        search_term in str(m.get('cpu_cores', '')) or
                        search_term in m.get('board_serial', '').lower()):
                        found = True
                elif sub_tag == 'packages':
                    for pkg in m.get('packages', []):
                        if search_term in pkg.get('name', '').lower() or search_term in pkg.get('version', '').lower():
                            found = True; break
                elif sub_tag == 'processes':
                    for proc in m.get('processes', []):
                        if search_term in proc.get('name', '').lower() or search_term in str(proc.get('pid', '')):
                            found = True; break
            
            if found:
                results.append(m)
                added_hostnames.add(hostname)
                
    # --- PESQUISA GLOBAL (SEM TAGS) ---
    else:
        for m in machines:
            hostname = m.get('hostname', '')
            if hostname in added_hostnames: continue
            
            # Busca em campos principais
            if any(query in str(m.get(k, '')).lower() for k in ['hostname', 'ip_address', 'os_name', 'cpu_name', 'device_status', 'ram_gb']):
                results.append(m)
                added_hostnames.add(hostname)
                continue
            
            # Busca em sub-listas (Interfaces, Portas, Processos, Pacotes)
            found_in_sub = False
            # Redes
            for iface in m.get('netiface', []):
                if query in iface.get('name', '').lower() or query in iface.get('mac', '').lower():
                    found_in_sub = True; break
            if not found_in_sub:
                for addr in m.get('netaddr', []):
                    if query in addr.get('address', '').lower():
                        found_in_sub = True; break
            # Portas e Processos
            if not found_in_sub:
                for port in m.get('ports', []):
                    if query in str(port.get('local', {}).get('port', '')) or query in port.get('process', '').lower():
                        found_in_sub = True; break
            # Pacotes
            if not found_in_sub:
                for pkg in m.get('packages', []):
                    if query in pkg.get('name', '').lower() or query in pkg.get('description', '').lower():
                        found_in_sub = True; break

            if found_in_sub:
                results.append(m)
                added_hostnames.add(hostname)

    return render_template('search.html', results=results, query=query)

@app.route('/machine/<hostname>')
def machine_details(hostname):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if not hostname.replace('.', '').replace('-', '').isalnum():
        #flash(translate('Nome de host inválido'), 'categoria')
        flash('Nome de host inválido', 'error')
        return redirect(url_for('painel'))
    
    machines = get_cached_machines()
    machine = next((m for m in machines if m.get('hostname') == hostname), None)
    
    if not machine:
        #flash(translate('Máquina não encontrada'), 'categoria')
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
    groups_script_path = os.path.join(os.path.dirname(__file__), 'utils', 'get_groups.py')
    try:
        os.popen(f'python3 {script_path} &')
        os.popen(f'python3 {groups_script_path} &')
        app.logger.info("Coleta de dados iniciada")
        #flash(translate('Coleta de dados iniciada, aguarde alguns minutos.'), 'categoria')
        flash('Coleta de dados iniciada, aguarde alguns minutos.', 'success')
        return redirect(url_for('dashboard'))
    except Exception as e:
        app.logger.error(f"Erro ao iniciar coleta: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/mfa_status')
def mfa_status():
    if 'username' not in session:
        return jsonify({'error': 'Não autenticado'}), 401
    
    username = session['username']
    users = load_json(AUTH_FILE) or []
    user = next((u for u in users if u['username'] == username), None)
    
    if user:
        return jsonify({
            'enabled': user.get('mfa_enabled', False),
            'configured': bool(user.get('mfa_secret', ''))
        })
    return jsonify({'error': 'Usuário não encontrado'}), 404

@app.route('/toggle_mfa', methods=['POST'])
def toggle_mfa():
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Não autenticado'}), 401
    
    username = session['username']
    users = load_json(AUTH_FILE) or []
    user_index = next((i for i, u in enumerate(users) if u['username'] == username), None)
    
    if user_index is None:
        return jsonify({'success': False, 'error': 'Usuário não encontrado'}), 404
    
    user = users[user_index]
    action = request.json.get('action')
    
    if action == 'enable':
        secret = pyotp.random_base32()
        user['mfa_secret'] = secret
        user['mfa_enabled'] = False
        
        # Salvar alterações
        try:
            with open(AUTH_FILE, 'w') as f:
                json.dump(users, f)
            # Gerar QR code
            totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
                name=username,
                issuer_name="Inventory System"
            )
            img = qrcode.make(totp_uri)
            buffered = BytesIO()
            img.save(buffered, format="PNG")
            img_str = base64.b64encode(buffered.getvalue()).decode()
            qr_code = f"data:image/png;base64,{img_str}"
            return jsonify({'success': True, 'qr_code': qr_code, 'secret': secret})
        except Exception as e:
            app.logger.error(f"Erro ao gerar segredo MFA: {str(e)}")
            return jsonify({'success': False, 'error': 'Erro ao gerar segredo MFA'}), 500
    
    elif action == 'disable':
        user['mfa_enabled'] = False
        user['mfa_secret'] = ''
        try:
            with open(AUTH_FILE, 'w') as f:
                json.dump(users, f)
            return jsonify({'success': True})
        except Exception as e:
            app.logger.error(f"Erro ao desabilitar MFA: {str(e)}")
            return jsonify({'success': False, 'error': 'Erro ao desabilitar MFA'}), 500
    
    return jsonify({'success': False, 'error': 'Ação inválida'}), 400

@app.route('/verify_mfa_setup', methods=['POST'])
def verify_mfa_setup():
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Não autenticado'}), 401
    
    username = session['username']
    code = request.json.get('code', '')
    
    users = load_json(AUTH_FILE) or []
    user_index = next((i for i, u in enumerate(users) if u['username'] == username), None)
    if user_index is None:
        return jsonify({'success': False, 'error': 'Usuário não encontrado'}), 404
    
    user = users[user_index]
    if not user.get('mfa_secret'):
        return jsonify({'success': False, 'error': 'Segredo MFA não encontrado'}), 400
    
    totp = pyotp.TOTP(user['mfa_secret'])
    if totp.verify(code, valid_window=1):
        user['mfa_enabled'] = True
        users[user_index] = user
        
        try:
            with open(AUTH_FILE, 'w') as f:
                json.dump(users, f)
            return jsonify({'success': True})
        except Exception as e:
            app.logger.error(f"Erro ao ativar MFA: {str(e)}")
            return jsonify({'success': False, 'error': 'Erro ao ativar MFA'}), 500
    else:
        return jsonify({'success': False, 'error': 'Código inválido'}), 400

@app.route('/export_pdf')
def export_pdf():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    include_details = request.args.get('include_details', '0') == '1'
    stats = get_cached_stats()
    machines = get_cached_machines()
    
    pdf_buffer = generate_pdf_report(stats, machines, include_details)
    
    response = make_response(pdf_buffer.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename=inventory_report.pdf'
    return response


def translate(key, lang=None):
    if not lang:
        lang = session.get('language', 'pt')
    
    return LANGUAGES.get(lang, {}).get(key, LANGUAGES['pt'].get(key, key))

# Context processor para templates
@app.context_processor
def inject_translations():
    return dict(
        translate=translate,
        language=session.get('language', 'pt')
    )

# Rota para mudar idioma
@app.route('/set_language/<language>')
def set_language(language):
    if language in LANGUAGES:
        session['language'] = language
    return redirect(request.referrer or url_for('dashboard'))

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
    
    error_message = f"Erro {code} - IP: {client_ip}, Usuário: {username}, Endpoint: {request.endpoint}"
    app.logger.error(error_message)
    
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
