#!/bin/bash
set -euo pipefail

C_G='\033[1;32m'; C_Y='\033[1;33m'; C_R='\033[1;31m'; C_B='\033[1;36m'; C_0='\033[0m'
msg()  { printf '%b[uninstall]%b %s\n' "$C_B" "$C_0" "$*"; }
ok()   { printf '%b  ✔%b %s\n' "$C_G" "$C_0" "$*"; }
warn() { printf '%b  ⚠%b %s\n' "$C_Y" "$C_0" "$*"; }
die()  { printf '%b  ✖ %s%b\n' "$C_R" "$*" "$C_0" >&2; exit 1; }

APP_USER="inventory"
APP_DIR="${APP_DIR:-/opt/Inventory}"

usage() {
  cat <<'USO'
INVENTORY - Desinstalador automatico

Uso: sudo bash uninstall.sh [opcoes]

Opcoes:
  --dir /caminho   Define a pasta onde foi instalado (padrao: /opt/Inventory)
  -y, --yes        Pula a confirmacao e apaga TUDO direto
  -h, --help       Mostra esta ajuda
USO
}

AUTO_YES=0

for arg in "$@"; do
  case "$arg" in
    --dir)        APP_DIR="$2"; shift 2 ;;
    -y|--yes)     AUTO_YES=1 ;;
    -h|--help)    usage; exit 0 ;;
    *) if [ "${arg:0:1}" = "-" ]; then die "Argumento desconhecido: $arg"; fi ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "Rode como root: sudo bash uninstall.sh"

printf '\n'
msg "═══ INVENTORY — DESINSTALAÇÃO ═══"
warn "Esta ação irá DESTRUIR:"
warn " - O banco de dados (PostgreSQL local)"
warn " - O serviço systemd"
warn " - Todos os arquivos e logs em: $APP_DIR"
warn " - O usuário de sistema: $APP_USER"
printf '\n'

if [ "$AUTO_YES" -eq 0 ]; then
  read -p "Tem certeza que deseja apagar TUDO? (digite 'sim' para continuar): " confirm
  if [ "$confirm" != "sim" ]; then
    die "Operação cancelada pelo usuário."
  fi
fi
printf '\n'

msg "[1/5] Parando e removendo serviço systemd…"
if systemctl list-unit-files | grep -q "inventory.service"; then
  systemctl stop inventory.service >/dev/null 2>&1 || true
  systemctl disable inventory.service >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/inventory.service
  systemctl daemon-reload
  ok "Serviço inventory.service removido"
else
  ok "Serviço systemd não encontrado (já removido ou não existia)"
fi

msg "[2/5] Removendo containers e banco de dados (Docker)…"
if [ -d "$APP_DIR" ] && [ -f "$APP_DIR/docker-compose.yml" ]; then
  cd "$APP_DIR"
  docker compose down -v >/dev/null 2>&1 || true
  ok "Containers do docker compose removidos"
else
  # Fallback caso a pasta ou o yaml já tenham sumido
  docker rm -f inventory_postgres inventory_redis >/dev/null 2>&1 || true
  ok "Containers forçados a parar/apagar (fallback)"
fi

msg "[3/5] Removendo pasta da aplicação e arquivos…"
if [ -d "$APP_DIR" ]; then
  # Evita apagar a raiz do sistema se houver algum erro de variável
  if [ "$APP_DIR" = "/" ] || [ "$APP_DIR" = "/opt" ] || [ "$APP_DIR" = "/usr" ]; then
    die "Caminho de segurança disparado: Proteção contra exclusão do diretório $APP_DIR. Apague manualmente."
  fi
  rm -rf "$APP_DIR"
  ok "Diretório $APP_DIR apagado completamente"
else
  ok "Diretório $APP_DIR não existe mais"
fi

msg "[4/5] Removendo usuário do sistema…"
if id "$APP_USER" >/dev/null 2>&1; then
  userdel "$APP_USER" >/dev/null 2>&1 || true
  # Tenta remover o grupo caso o userdel não tenha removido
  groupdel "$APP_USER" >/dev/null 2>&1 || true 
  ok "Usuário e grupo '$APP_USER' removidos"
else
  ok "Usuário '$APP_USER' já não existe no sistema"
fi

msg "[5/5] Limpeza de pacotes do sistema (Opcional)"
ok "As dependências do sistema (Docker, Python, etc) NÃO foram removidas para não quebrar outros serviços."

printf '\n'
msg "═══ DESINSTALAÇÃO CONCLUÍDA COM SUCESSO ═══"
printf '\n'
