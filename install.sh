
set -euo pipefail

C_G='\033[1;32m'; C_Y='\033[1;33m'; C_R='\033[1;31m'; C_B='\033[1;36m'; C_0='\033[0m'
msg()  { printf '%b[inventory]%b %s\n' "$C_B" "$C_0" "$*"; }
ok()   { printf '%b  ✔%b %s\n' "$C_G" "$C_0" "$*"; }
warn() { printf '%b  ⚠%b %s\n' "$C_Y" "$C_0" "$*"; }
die()  { printf '%b  ✖ %s%b\n' "$C_R" "$*" "$C_0" >&2; exit 1; }

APP_USER="inventory"
APP_GROUP="inventory"
HERE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="${APP_DIR:-/opt/Inventory}"
WITH_SERVICE=1

usage() {
  cat <<'USO'
INVENTORY - instalador automatico (Debian/Ubuntu)

Uso: sudo bash install.sh [opcoes]

Opcoes:
  --here         instala na propria pasta do script (padrao: /opt/Inventory)
  --no-service   nao cria o servico systemd (inicie manualmente depois)
  -h, --help     mostra esta ajuda

Variaveis:
  APP_DIR=/caminho   escolhe a pasta de instalacao
                     ex.: sudo APP_DIR=/srv/Inventory bash install.sh

Apos a instalacao: https://IP-DO-SERVIDOR:8000 (login admin / senha do .env)
USO
}

for arg in "$@"; do
  case "$arg" in
    --no-service) WITH_SERVICE=0 ;;
    --here)       APP_DIR="$HERE_DIR" ;;
    -h|--help)    usage; exit 0 ;;
    *) die "Argumento desconhecido: $arg (use --help)" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "Rode como root: sudo bash install.sh"
command -v apt-get >/dev/null 2>&1 \
  || die "Este script usa apt (Debian/Ubuntu). Instale as dependências manualmente em outra distro."

printf '\n'
msg "═══ INVENTORY — instalação (v0.18.9) ═══"
msg "Pasta de destino: $APP_DIR"

msg "[1/9] Dependências do sistema (apt)…"
NEED_APT=()
for p in docker.io docker-compose-v2 python3-venv python3-pip openssl; do
  dpkg -s "$p" >/dev/null 2>&1 || NEED_APT+=("$p")
done
if [ ${#NEED_APT[@]} -gt 0 ]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y >/dev/null
  apt-get install -y --no-install-recommends "${NEED_APT[@]}" >/dev/null
  ok "instalado: ${NEED_APT[*]}"
else
  ok "tudo já presente (docker, compose, venv, pip, openssl)"
fi

if ! docker info >/dev/null 2>&1; then
  msg "      ativando o daemon do Docker…"
  systemctl enable --now docker >/dev/null 2>&1 || service docker start >/dev/null 2>&1 || true
  sleep 2
  docker info >/dev/null 2>&1 || die "O Docker não subiu. Verifique: systemctl status docker"
fi
ok "Docker ativo: $(docker --version | cut -d, -f1)"

msg "[2/9] Usuário da aplicação…"
if id -u "$APP_USER" >/dev/null 2>&1; then
  ok "usuário '$APP_USER' já existe"
else
  useradd --system --create-home --shell /usr/sbin/nologin "$APP_USER"
  ok "usuário '$APP_USER' criado (sistema, sem shell de login)"
fi

msg "[3/9] Pasta da aplicação…"
if [ "$HERE_DIR" != "$APP_DIR" ]; then
  mkdir -p "$APP_DIR"
  cp -a "$HERE_DIR"/. "$APP_DIR"/
  ok "projeto copiado de $HERE_DIR → $APP_DIR"
else
  ok "instalando na própria pasta do script"
fi
cd "$APP_DIR"

chown -R "$APP_USER:$APP_GROUP" "$APP_DIR"

if [ -d "$APP_DIR/postgres" ]; then
  warn "pasta 'postgres/' antiga detectada (layout pré-v0.18.8)."
  warn "  → se ela contém dados:  sudo systemctl stop inventory 2>/dev/null; sudo docker compose down"
  warn "    mv postgres/data data/postgres && sudo chown -R 999:999 data/postgres"
fi

msg "[4/9] Configuração (.env)…"
if [ ! -f .env ]; then
  if [ -f .env.example ]; then
    cp .env.example .env
    sed -i "s|^SECRET_KEY=.*|SECRET_KEY=$(openssl rand -hex 32)|" .env
    sed -i "s|^SESSION_SALT=.*|SESSION_SALT=$(openssl rand -hex 16)|" .env
    ok ".env criado a partir do .env.example (SECRET_KEY/SESSION_SALT gerados)"
  else
    die ".env não encontrado e sem .env.example para criar"
  fi
else
  ok ".env existente preservado"
fi
get_env() { grep -E "^$1=" .env 2>/dev/null | tail -n1 | cut -d= -f2- ; }
DB_USER="$(get_env DB_USER)";        DB_USER="${DB_USER:-inventorydb}"
DB_PASS="$(get_env DB_PASS)";        DB_PASS="${DB_PASS:-senhadoinventorydb}"
DB_NAME="$(get_env DB_NAME)";        DB_NAME="${DB_NAME:-inventory_db}"
APP_PORT="$(get_env PORT)";          APP_PORT="${APP_PORT:-8000}"
ADMIN_PASSWORD_ENV="$(get_env ADMIN_PASSWORD)"; ADMIN_PASSWORD_ENV="${ADMIN_PASSWORD_ENV:-Meuadmin123}"
warn "revise .env → WAZUH_HOST/WAZUH_USER/WAZUH_PASSWORD (API do Wazuh) e DB_PASS (senha do banco)"

msg "[5/9] Certificados TLS…"
if [ -f ssl/cert.pem ] && [ -f ssl/key.pem ]; then
  ok "certificados existentes preservados (ssl/cert.pem, ssl/key.pem)"
else
  mkdir -p ssl
  openssl req -x509 -newkey rsa:4096 -nodes -days 365 \
    -subj "/CN=inventory" \
    -out ssl/cert.pem -keyout ssl/key.pem >/dev/null 2>&1
  ok "self-signed gerado para 365 dias (troque pelo seu quando quiser)"
fi

msg "[6/9] Banco de dados (data/postgres)…"
mkdir -p data/postgres
if [ ! -f data/postgres/PG_VERSION ]; then
  find data/postgres -mindepth 1 -maxdepth 1 -exec rm -rf {} +
fi
chown -R 999:999 data/postgres
ok "data/postgres pronto — dono 999:999 (usuário postgres do container)"

msg "[7/9] Ambiente virtual Python (venv)…"
if [ ! -x .venv/bin/python ]; then
  sudo -u "$APP_USER" python3 -m venv .venv
  ok ".venv criado"
else
  ok ".venv existente preservado"
fi
msg "      instalando dependências (pip -r requirements.txt)…"
sudo -u "$APP_USER" .venv/bin/pip install --upgrade pip >/dev/null
sudo -u "$APP_USER" .venv/bin/pip install -r requirements.txt >/dev/null
ok "dependências Python instaladas"

msg "[8/9] Subindo PostgreSQL + Redis (docker compose)…"
docker compose up -d
ok "containers disparados (inventory_postgres, inventory_redis)"

msg "      aguardando o PostgreSQL aceitar conexões…"
DB_OK=0
for _ in $(seq 1 60); do
  if docker exec inventory_postgres pg_isready -U "$DB_USER" -d "$DB_NAME" >/dev/null 2>&1; then
    DB_OK=1; break
  fi
  sleep 2
done
[ "$DB_OK" -eq 1 ] || die "PostgreSQL não ficou saudável a tempo. Veja: docker compose logs db"
ok "PostgreSQL saudável (db: $DB_NAME · usuário: $DB_USER)"

for _ in $(seq 1 15); do
  [ "$(docker exec inventory_redis redis-cli ping 2>/dev/null || true)" = "PONG" ] && break
  sleep 2
done
ok "Redis respondendo (cache)"

RUN_CMD="cd '$APP_DIR' && sudo -u $APP_USER .venv/bin/python app.py"
if [ "$WITH_SERVICE" -eq 1 ] && command -v systemctl >/dev/null 2>&1; then
  msg "[9/9] Serviço systemd (inventory.service)…"
  cat > /etc/systemd/system/inventory.service <<UNIT
[Unit]
Description=Inventory Application
After=network.target docker.service
Wants=network-online.target docker.service

[Service]
Type=simple
WorkingDirectory=$APP_DIR
ExecStart=$APP_DIR/.venv/bin/python $APP_DIR/app.py

User=$APP_USER
Group=$APP_GROUP

Restart=always
RestartSec=5

NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
RestrictSUIDSGID=yes
ReadWritePaths=$APP_DIR

LimitNOFILE=65536
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable inventory.service >/dev/null
  systemctl restart inventory.service
  sleep 3
  if systemctl is-active --quiet inventory.service; then
    ok "serviço inventory.service ATIVO (inicia no boot)"
  else
    warn "serviço não subiu ainda — veja: journalctl -u inventory -n 50"
    warn "para rodar manualmente: $RUN_CMD"
  fi
else
  msg "[9/9] Serviço systemd pulado ($( [ "$WITH_SERVICE" -eq 0 ] && echo '--no-service' || echo 'systemd indisponível'))."
  msg "      rode o Inventory com:"
  msg "        $RUN_CMD"
fi

HOST_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
printf '\n'
msg "═══ INSTALAÇÃO CONCLUÍDA ═══"
msg "  Aplicação ..... https://${HOST_IP:-<ip-do-servidor>}:${APP_PORT} (login: admin / senha do .env: ${ADMIN_PASSWORD_ENV})"
msg "  Pasta ......... $APP_DIR"
msg "  Banco ......... data/postgres (PostgreSQL 16 + Redis, containers locais)"
msg "  Logs .......... $APP_DIR/logs/  ·  journalctl -u inventory -f"
printf '\n'
msg "Comandos úteis:"
msg "  sudo systemctl status|stop|start|restart inventory"
msg "  sudo docker compose ps          (a partir de $APP_DIR)"
msg "  backup: docker exec -t inventory_postgres pg_dump -U $DB_USER $DB_NAME > backup_\$(date +%%Y%%m%%d).sql"
printf '\n'

