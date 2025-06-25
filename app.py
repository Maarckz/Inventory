#########################
## IMPORTING LIBRARIES ##
#########################
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from collections import defaultdict
from dotenv import load_dotenv
from datetime import datetime
import bcrypt
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
    PERMANENT_SESSION_LIFETIME=1800,  # 30 minutos
    MAX_CONTENT_LENGTH=1024 * 1024,    # 1MB limite de upload
)

# Configurações do .env
INVENTORY_DIR = os.getenv('INVENTORY_DIR')
AUTH_FILE = os.getenv('AUTH_FILE')
SSL_CERT = os.getenv('SSL_CERT_PATH')
SSL_KEY = os.getenv('SSL_KEY_PATH')
USE_HTTPS = os.getenv('USE_HTTPS').lower() == 'true'
MAX_LOGIN_ATTEMPTS = int(os.getenv('MAX_LOGIN_ATTEMPTS'))
LOGIN_BLOCK_TIME = int(os.getenv('LOGIN_BLOCK_TIME'))  # Default to 300 seconds (5 minutes)


# Funções auxiliares
def load_json(file_path):
    """Carrega dados JSON de um arquivo com tratamento de erros"""
    try:
        if os.path.exists(file_path):
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

# Middleware para verificar tentativas de login
@app.before_request
def check_login_attempts():
    if request.endpoint == 'login' and request.method == 'POST':
        ip = request.remote_addr
        session.setdefault('login_attempts', {})
        attempts = session['login_attempts'].get(ip, 0)
        
        if attempts >= MAX_LOGIN_ATTEMPTS:
            flash(f'Muitas tentativas falhas. Tente novamente em {LOGIN_BLOCK_TIME//60} minutos.', 'error')
            return redirect(url_for('login'))

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
        return jsonify({'error': 'Não autorizado'}), 401
    
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
        
        # Validar entradas
        if not username or not password:
            flash('Preencha todos os campos', 'error')
            return render_template('login.html')
        
        # Verificar bloqueio por IP
        ip = request.remote_addr
        session.setdefault('login_attempts', {})
        
        if session['login_attempts'].get(ip, 0) >= MAX_LOGIN_ATTEMPTS:
            flash(f'Muitas tentativas falhas. Tente novamente em {LOGIN_BLOCK_TIME//60} minutos.', 'error')
            return render_template('login.html')
            
        # Carregar usuários
        users = load_json(AUTH_FILE) or []
        user = next((u for u in users if u['username'] == username), None)
        
        # Verificar credenciais
        if user and verify_password(user['password_hash'], password):
            session['username'] = username
            session.pop('login_attempts', None)  # Resetar tentativas
            return redirect(url_for('dashboard'))
        else:
            # Registrar tentativa falha
            session['login_attempts'][ip] = session['login_attempts'].get(ip, 0) + 1
            flash('Credenciais inválidas', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
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
        return jsonify({'error': 'Não autorizado'}), 401

    script_path = os.path.join(os.path.dirname(__file__), 'utils', 'get_data.py')
    try:
        os.popen(f'python3 {script_path} &')
        flash('Coleta de dados iniciada', 'success')
        return redirect(url_for('dashboard'))
    except Exception as e:
        app.logger.error(f"Erro ao iniciar coleta: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.errorhandler(404)
@app.errorhandler(403)
@app.errorhandler(500)
@app.errorhandler(502)
@app.errorhandler(503)
@app.errorhandler(504)
def handle_errors(error):
    code = error.code if hasattr(error, 'code') else 500
    app.logger.error(f"Erro {code}: {str(error)}")
    
    if code == 404:
        return render_template('error.html', error_code=404, message="Página não encontrada"), 404
    elif code == 403:
        return render_template('error.html', error_code=403, message="Acesso proibido"), 403
    else:
        return render_template('error.html', error_code=500, message="Erro interno do servidor"), 500


if __name__ == '__main__':
    # Criar diretórios necessários
    os.makedirs(INVENTORY_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(AUTH_FILE), exist_ok=True)
    
    # Configuração SSL
    ssl_context = None
    if USE_HTTPS:
        if os.path.exists(SSL_CERT) and os.path.exists(SSL_KEY):
            ssl_context = (SSL_CERT, SSL_KEY)
        else:
            app.logger.warning("Certificado SSL não encontrado. Executando sem HTTPS")
    
    # Configurações do servidor
    host = os.getenv('HOST', '0.0.0.0')
    port = int(os.getenv('PORT'))
    debug = os.getenv('DEBUG', 'False').lower() == 'true'
    
    app.run(
        debug=debug,
        host=host,
        port=port,
        ssl_context=ssl_context
    )
