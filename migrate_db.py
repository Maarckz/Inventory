from models import db, User, HostInventory, Group
from dotenv import load_dotenv
from flask import Flask
import json
import os

load_dotenv()

app = Flask(__name__)

db_user = os.getenv("DB_USER")
db_pass = os.getenv("DB_PASS")
db_host = os.getenv("DB_HOST", "localhost")
db_port = os.getenv("DB_PORT", "5432")
db_name = os.getenv("DB_NAME")

if not all([db_user, db_pass, db_name]):
    raise RuntimeError("Variáveis de banco incompletas")

database_url = (
    f"postgresql+psycopg2://{db_user}:"
    f"{db_pass}@{db_host}:{db_port}/{db_name}"
)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

INVENTORY_DIR = os.getenv('INVENTORY_DIR')
GROUPS_DIR = os.getenv('GROUPS_DIR')
AUTH_FILE = os.getenv('AUTH_FILE')

def migrate_users():
    if os.path.exists(AUTH_FILE):
        with open(AUTH_FILE, 'r', encoding='utf-8') as f:
            try:
                users_data = json.load(f)

                if isinstance(users_data, list):
                    users_iterable = users_data
                else:
                    users_iterable = [{"username": k, **v} for k, v in users_data.items()]

                for data in users_iterable:
                    username = data.get('username')
                    if not username:
                        continue

                    user = User.query.filter_by(username=username).first()

                    if not user:
                        user = User(
                            username=username,
                            password_hash=data.get('password_hash', ''),
                            role=data.get('role', 'user'),
                            mfa_enabled=data.get('mfa_enabled', False),
                            mfa_secret=data.get('mfa_secret')
                        )
                        db.session.add(user)
                    else:
                        user.role = data.get('role', user.role)

                db.session.commit()
                print("Usuários migrados com sucesso.")

            except Exception as e:
                db.session.rollback()
                print(f"Erro ao migrar usuários: {e}")
    else:
        print(f"Arquivo não encontrado: {AUTH_FILE}")

def build_host_groups_map():
    host_groups_map = {}

    groups_file = os.path.join(GROUPS_DIR, 'groups.json')
    if not os.path.exists(groups_file):
        return host_groups_map
    try:
        with open(groups_file, 'r', encoding='utf-8') as gf:
            groups_data = json.load(gf)

            for group in groups_data:
                gname = group.get('grupo')

                for agent in group.get('agentes', []):
                    hostname = agent.get('name')

                    if not hostname:
                        continue
                    hostname = hostname.upper()
                    
                    if hostname not in host_groups_map:
                        host_groups_map[hostname] = []
                    host_groups_map[hostname].append(gname)

    except Exception as e:
        print(f"Erro ao processar groups.json: {e}")

    return host_groups_map

def migrate_hosts():
    if not os.path.exists(INVENTORY_DIR):
        print(f"Diretório não encontrado: {INVENTORY_DIR}")
        return

    host_groups_map = build_host_groups_map()

    for filename in os.listdir(INVENTORY_DIR):
        if not filename.endswith('.json'):
            continue

        filepath = os.path.join(INVENTORY_DIR, filename)

        with open(filepath, 'r', encoding='utf-8') as f:
            try:
                file_content = json.load(f)

                if isinstance(file_content, list):
                    hosts_iterable = file_content
                else:
                    hosts_iterable = [file_content]

                for host_data in hosts_iterable:


                    hostname = host_data.get('hostname') or filename.replace('.json', '')
                    hostname_upper = hostname.upper()

                    groups = host_groups_map.get(hostname_upper, [])

                    if not groups:
                        agent_info = host_data.get('agent_info', {})
                        if isinstance(agent_info, dict):
                            g = agent_info.get('group')

                            if g:
                                if isinstance(g, list):
                                    groups = g
                                elif isinstance(g, str):
                                    groups = [g]

                    if isinstance(groups, str):
                        groups = [groups]
                    elif not isinstance(groups, list):
                        groups = []

 
                    host_data['groups'] = groups

     
                    if 'agent_info' in host_data:
                        if isinstance(host_data['agent_info'], dict):
                            host_data['agent_info'].pop('group', None)


                    host = HostInventory.query.filter_by(hostname=hostname).first()

                    if not host:
                        host = HostInventory(
                            hostname=hostname,
                            data=host_data,
                            is_legacy=False
                        )
                        db.session.add(host)
                    else:
                        host.data = host_data
                        host.is_legacy = False

            except Exception as e:
                print(f"Erro ao processar {filename}: {e}")

    try:
        db.session.commit()
        print("Hosts migrados com sucesso.")
    except Exception as e:
        db.session.rollback()
        print(f"Erro ao salvar hosts: {e}")


def migrate_groups():
    if not os.path.exists(GROUPS_DIR):
        print(f"Diretório não encontrado: {GROUPS_DIR}")
        return

    for filename in os.listdir(GROUPS_DIR):
        if not filename.endswith('.json'):
            continue

        filepath = os.path.join(GROUPS_DIR, filename)

        with open(filepath, 'r', encoding='utf-8') as f:
            try:
                file_content = json.load(f)

                if isinstance(file_content, list):
                    groups_iterable = file_content
                else:
                    groups_iterable = [file_content]

                for group_data in groups_iterable:
                    name = group_data.get('name') or group_data.get('grupo') or filename.replace('.json', '')

                    group = Group.query.filter_by(name=name).first()

                    if not group:
                        group = Group(
                            name=name,
                            data=group_data,
                            is_legacy=False
                        )
                        db.session.add(group)
                    else:
                        group.data = group_data
                        group.is_legacy = False

            except Exception as e:
                print(f"Erro ao migrar grupo {filename}: {e}")

    try:
        db.session.commit()
        print("Grupos migrados com sucesso.")
    except Exception as e:
        db.session.rollback()
        print(f"Erro ao salvar grupos: {e}")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        print("Iniciando migração...")

        migrate_users()
        migrate_hosts()
        migrate_groups()

        print("Migração concluída com sucesso.")