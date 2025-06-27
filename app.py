'''
TO DO LIST:
Alterar a Estrutura Para POO
Criar painel de admin
Verificar se o usuário é admin
Testar binario compilado
Implementacao com docker image
'''


#########################
## IMPORTING LIBRARIES ##
#########################
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
AUTH_FILE = os.getenv('AUTH_FILE')
SSL_CERT = os.getenv('SSL_CERT_PATH')
SSL_KEY = os.getenv('SSL_KEY_PATH')
USE_HTTPS = os.getenv('USE_HTTPS').lower() == 'true'
MAX_LOGIN_ATTEMPTS = int(os.getenv('MAX_LOGIN_ATTEMPTS'))
LOGIN_BLOCK_TIME = int(os.getenv('LOGIN_BLOCK_TIME')) 
ALLOWED_IP_RANGES = os.getenv('ALLOWED_IP_RANGES').split(',')

# Arquivo para armazenar IPs bloqueados
BLOCKED_IPS_FILE = os.getenv('BLOCKED_IPS_FILE')
blocked_ips_lock = threading.Lock()

# Obter IPs do servidor (apenas interfaces UP, somente IPv4)
def get_server_ips():
    """Obtém todos os IPs IPv4 das interfaces UP do servidor"""
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
    return list(server_ips)

SERVER_IPS = get_server_ips()

# Configurar sistema de logs
LOG_DIR = 'logs'
os.makedirs(LOG_DIR, exist_ok=True)

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

# Funções para gerenciar IPs bloqueados
def load_blocked_ips():
    """Carrega IPs bloqueados do arquivo com tratamento robusto"""
    try:
        if os.path.exists(BLOCKED_IPS_FILE) and os.path.getsize(BLOCKED_IPS_FILE) > 0:
            with open(BLOCKED_IPS_FILE, 'r') as f:
                try:
                    data = json.load(f)
                    # Se o arquivo estiver no formato antigo, converter
                    if isinstance(data, dict) and 'blocked_ips' not in data:
                        # Converter para novo formato
                        new_data = {
                            'blocked_ips': {},
                            'login_attempts': {}
                        }
                        for ip, value in data.items():
                            if isinstance(value, (int, float)):
                                # É um timestamp de bloqueio
                                new_data['blocked_ips'][ip] = value
                            elif isinstance(value, dict) and 'timestamp' in value:
                                # É uma entrada de bloqueio
                                new_data['blocked_ips'][ip] = value['timestamp']
                            elif isinstance(value, int):
                                # É uma tentativa de login
                                new_data['login_attempts'][ip] = value
                        # Salvar novo formato
                        save_blocked_ips(new_data)
                        return new_data
                    return data
                except json.JSONDecodeError:
                    app.logger.error(f"Arquivo de IPs bloqueados corrompido. Recriando.")
                    # Criar novo arquivo vazio
                    return {'blocked_ips': {}, 'login_attempts': {}}
        return {'blocked_ips': {}, 'login_attempts': {}}
    except (json.JSONDecodeError, IOError) as e:
        app.logger.error(f"Erro ao carregar IPs bloqueados: {str(e)}")
        return {'blocked_ips': {}, 'login_attempts': {}}

def save_blocked_ips(data):
    """Salva IPs bloqueados no arquivo"""
    try:
        with blocked_ips_lock:
            with open(BLOCKED_IPS_FILE, 'w') as f:
                json.dump(data, f)
    except IOError as e:
        app.logger.error(f"Erro ao salvar IPs bloqueados: {str(e)}")

def is_ip_blocked(ip):
    """Verifica se o IP está bloqueado, ignorando IPs do servidor"""
    # Nunca bloquear IPs do próprio servidor
    if ip in SERVER_IPS:
        return False
        
    data = load_blocked_ips()
    blocked_ips = data.get('blocked_ips', {})
    
    if ip in blocked_ips:
        block_time = blocked_ips[ip]
        # Garantir que block_time é numérico
        if isinstance(block_time, (int, float)):
            current_time = time.time()
            # Verifica se o tempo de bloqueio expirou
            if current_time - block_time < LOGIN_BLOCK_TIME:
                return True
            else:
                # Remove bloqueio expirado
                remove_blocked_ip(ip)
        else:
            # Formato inválido - remover entrada
            app.logger.error(f"Formato inválido de timestamp para IP {ip}: {block_time}")
            remove_blocked_ip(ip)
    return False

def add_blocked_ip(ip):
    """Adiciona um IP à lista de bloqueados com timestamp atual"""
    # Nunca bloquear IPs do próprio servidor
    if ip in SERVER_IPS:
        app.logger.info(f"Tentativa de bloquear IP do servidor ignorada: {ip}")
        return
        
    data = load_blocked_ips()
    data['blocked_ips'][ip] = time.time()  # Armazena apenas o timestamp
    save_blocked_ips(data)
    minutes = math.ceil(LOGIN_BLOCK_TIME / 60)
    security_logger.warning(f"IP BLOQUEADO: {ip} por {minutes} minutos")

def remove_blocked_ip(ip):
    """Remove um IP da lista de bloqueados"""
    data = load_blocked_ips()
    if ip in data.get('blocked_ips', {}):
        del data['blocked_ips'][ip]
        save_blocked_ips(data)
        security_logger.info(f"IP DESBLOQUEADO: {ip}")

def increment_login_attempt(ip):
    """Incrementa a contagem de tentativas de login para um IP, ignorando IPs do servidor"""
    # Nunca contar tentativas para IPs do servidor
    if ip in SERVER_IPS:
        return 0
        
    data = load_blocked_ips()
    attempts = data.get('login_attempts', {}).get(ip, 0) + 1
    data.setdefault('login_attempts', {})[ip] = attempts
    save_blocked_ips(data)
    return attempts

def get_login_attempts(ip):
    """Obtém o número de tentativas de login para um IP"""
    data = load_blocked_ips()
    return data.get('login_attempts', {}).get(ip, 0)

def reset_login_attempts(ip):
    """Reseta a contagem de tentativas de login para um IP"""
    data = load_blocked_ips()
    if ip in data.get('login_attempts', {}):
        del data['login_attempts'][ip]
        save_blocked_ips(data)

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
        'total': 0
    }
    
    for machine in machines:
        # Process OS stats
        os_name = machine.get('os_name', 'Unknown')
        stats['os'][os_name] += 1
        
        # Process CPU stats
        cpu_name = machine.get('cpu_name', 'Unknown')
        stats['cpu'][cpu_name] += 1
        
        # Process RAM stats
        ram_gb = machine.get('ram_gb', 0)
        if ram_gb > 0:
            if ram_gb <= 4:
                ram_range = "0-4GB"
            elif ram_gb <= 8:
                ram_range = "5-8GB"
            elif ram_gb <= 16:
                ram_range = "9-16GB"
            else:
                ram_range = "16+GB"
        else:
            ram_range = 'Unknown'
        stats['ram'][ram_range] += 1
        
        # Process status
        status = machine.get('device_status', 'Inativo')
        stats['status'][status] += 1
        
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
    if not ALLOWED_IP_RANGES or not any(ALLOWED_IP_RANGES):
        return True  # Permite todos se não houver ranges definidos
    
    # Sempre permitir IPs do servidor
    if ip in SERVER_IPS:
        return True
        
    try:
        ip_addr = ipaddress.ip_address(ip)
        for ip_range in ALLOWED_IP_RANGES:
            if ip_range.strip():
                try:
                    network = ipaddress.ip_network(ip_range.strip(), strict=False)
                    if ip_addr in network:
                        return True
                except ValueError as e:
                    app.logger.error(f"Rede inválida {ip_range}: {str(e)}")
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
    
    # Verificar se o IP está bloqueado para login (exceto servidor)
    if request.endpoint == 'login' and request.method == 'POST' and client_ip not in SERVER_IPS:
        if is_ip_blocked(client_ip):
            security_logger.warning(f"TENTATIVA BLOQUEADA - IP bloqueado: {client_ip}")
            minutes = math.ceil(LOGIN_BLOCK_TIME / 60)
            flash(f'Muitas tentativas falhas. Tente novamente em {minutes} minutos.', 'error')
            return redirect(url_for('login'))
    
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
    
    machines = get_all_machines()
    stats = get_machine_stats(machines)
    
    return render_template('dashboard.html', 
                         stats=stats,
                         active_count=stats['status']['Ativo'],
                         inactive_count=stats['status']['Inativo'])

@app.route('/get_chart_data')
def get_chart_data():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    machines = get_all_machines()
    stats = get_machine_stats(machines)
    
    return jsonify({
        'os_labels': list(stats['os'].keys()),
        'os_data': list(stats['os'].values()),
        'cpu_labels': list(stats['cpu'].keys()),
        'cpu_data': list(stats['cpu'].values()),
        'ram_labels': list(stats['ram'].keys()),
        'ram_data': list(stats['ram'].values()),
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
            reset_login_attempts(client_ip)  # Resetar tentativas após login bem-sucedido
            # Registrar login bem-sucedido
            security_logger.info(f"LOGIN BEM-SUCEDIDO - Usuário: {username}, IP: {client_ip}")
            return redirect(url_for('dashboard'))
        else:
            # Registrar tentativa falha (exceto para IP do servidor)
            if client_ip not in SERVER_IPS:
                security_logger.warning(f"TENTATIVA DE LOGIN FALHA - Usuário: {username}, IP: {client_ip}")
                
                # Incrementar tentativa
                attempts = increment_login_attempt(client_ip)
                
                # Verificar se atingiu o limite de tentativas
                if attempts >= MAX_LOGIN_ATTEMPTS:
                    add_blocked_ip(client_ip)
                    minutes = math.ceil(LOGIN_BLOCK_TIME / 60)
                    flash(f'Muitas tentativas falhas. Tente novamente em {minutes} minutos.', 'error')
                else:
                    flash('Credenciais inválidas', 'error')
            else:
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
    
    machines = get_all_machines()
    return render_template('painel.html', machines=machines)

@app.route('/search')
def search():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Validar e sanitizar entrada
    query = request.args.get('query', '')[:100].lower()
    machines = get_all_machines()
    
    if query:
        results = []
        added_hostnames = set()  # Conjunto para controlar máquinas já adicionadas
        
        for m in machines:
            hostname = m.get('hostname', '')
            
            # Verificar se a máquina já foi adicionada
            if hostname in added_hostnames:
                continue
                
            found = False
            
            # Busca em campos básicos
            if (query in m.get('hostname', '').lower() or
                query in m.get('ip_address', '').lower() or
                query in m.get('os_name', '').lower() or
                query in m.get('cpu_name', '').lower() or
                query in m.get('device_status', '').lower() or
                query in str(m.get('ram_gb', 0))):
                found = True
                
            # Busca em campos de rede
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
                        
            # Busca em campos detalhados do sistema
            if not found:
                if (query in m.get('os_version', '').lower() or
                    query in m.get('os_platform', '').lower() or
                    query in m.get('os_architecture', '').lower() or
                    query in m.get('board_serial', '').lower() or
                    query in m.get('os_kernel', '').lower()):
                    found = True
            
            # Adicionar máquina se encontrada e ainda não estiver na lista
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
    
    machines = get_all_machines()
    machine = next((m for m in machines if m.get('hostname') == hostname), None)
    
    if not machine:
        flash('Máquina não encontrada', 'error')
        return redirect(url_for('painel'))
    
    return render_template('machine_details.html', machine=machine)

@app.route('/get_data')
def get_data():
    if 'username' not in session:
        return redirect(url_for('login'))

    script_path = os.path.join(os.path.dirname(__file__), 'utils', 'get_data.py')
    try:
        os.popen(f'python3 {script_path} &')
        app.logger.info("Coleta de dados iniciada")
        flash('Coleta de dados iniciada', 'success')
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
    # Criar diretórios necessários
    os.makedirs(INVENTORY_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(AUTH_FILE), exist_ok=True)
    os.makedirs(LOG_DIR, exist_ok=True)
    
    # Configuração SSL
    ssl_context = None
    if USE_HTTPS:
        if os.path.exists(SSL_CERT) and os.path.exists(SSL_KEY):
            ssl_context = (SSL_CERT, SSL_KEY)
        else:
            app.logger.warning("Certificado SSL não encontrado. Executando HTTP")
    
    # Configurações do servidor
    host = os.getenv('HOST', '0.0.0.0')
    port = int(os.getenv('PORT'))
    debug = os.getenv('DEBUG', 'False').lower() == 'true'
    
    # Inicializar sistema de bloqueio
    load_blocked_ips()  # Converter formato se necessário
    
    app.logger.info(f"IPs do servidor: {SERVER_IPS}")
    app.logger.info(f"Redes permitidas: {ALLOWED_IP_RANGES}")
    
    app.run(
        debug=debug,
        host=host,
        port=port,
        ssl_context=ssl_context
    )