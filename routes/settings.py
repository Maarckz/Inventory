"""
Inventory v0.18 — Rotas de configurações / MFA / relatório
==========================================================
/settings, /settings/update_sync, /settings/sync_now,
/settings/sync_status (v0.18.21), /settings/change_password,
/settings/assistant_models (v0.18.23 — lista de modelos da Groq),
/get_data, /mfa_status, /toggle_mfa, /verify_mfa_setup,
/export_pdf — portas 1:1 da v0.17.
"""
from __future__ import annotations

import threading
from datetime import datetime
from io import BytesIO

import base64
# pyrefly: ignore [missing-import]
import pyotp
import qrcode
from flask import (
    Blueprint, current_app, flash, jsonify, make_response, redirect,
    render_template, request, session, url_for,
)

from models import User, SystemSetting, Group, db
from core.security import admin_required, login_required, hash_password

ROUTES = [
    ('/settings', 'settings', 'settings', {}),
    ('/settings/update_sync', 'update_sync', 'update_sync', {'methods': ['POST']}),
    ('/settings/update_discovery', 'update_discovery', 'update_discovery', {'methods': ['POST']}),
    ('/settings/update_assistant', 'update_assistant', 'update_assistant', {'methods': ['POST']}),
    ('/settings/test_assistant', 'test_assistant', 'test_assistant', {'methods': ['POST']}),
    # v0.18.23 — lista de modelos REAIS da conta (datalist do painel)
    ('/settings/assistant_models', 'assistant_models', 'assistant_models', {'methods': ['POST']}),
    ('/settings/update_dedup', 'update_dedup', 'update_dedup', {'methods': ['POST']}),
    ('/settings/update_notifications', 'update_notifications', 'update_notifications', {'methods': ['POST']}),
    ('/settings/dashboard_layout', 'save_dashboard_layout', 'save_dashboard_layout', {'methods': ['POST']}),
    ('/settings/sync_now', 'sync_now', 'sync_now', {'methods': ['POST']}),
    ('/settings/sync_status', 'sync_status', 'sync_status', {}),
    ('/settings/change_password', 'change_password', 'change_password', {'methods': ['POST']}),
    ('/get_data', 'get_data', 'get_data', {}),
    ('/mfa_status', 'mfa_status', 'mfa_status', {}),
    ('/toggle_mfa', 'toggle_mfa', 'toggle_mfa', {'methods': ['POST']}),
    ('/verify_mfa_setup', 'verify_mfa_setup', 'verify_mfa_setup', {'methods': ['POST']}),
    ('/export_pdf', 'export_pdf', 'export_pdf', {}),
]



def _app():
    return current_app._get_current_object()


def settings():
    if 'username' not in session:
        return redirect(url_for('login'))

    from services.stats import get_cached_machines
    machines = get_cached_machines()
    users = []
    if session.get('role') == 'admin':
        users = User.query.all()

    # v0.18.13 — valores ATUAIS para o painel de Sincronização (3
    # deslizadores: Wazuh · Ping Sweep · ARP Discovery). Server-rendered
    # para o modal abrir já preenchido, sem endpoint extra de leitura.
    discovery = {
        'auto_scan': {'enabled': False, 'interval_minutes': 5},
        'arp_monitor': {'enabled': True, 'interval_minutes': 5},
    }
    sync_seconds = 3600
    try:
        from services.netscope_core import load_config as _ns_cfg
        _cfg = _ns_cfg()
        _auto = _cfg.get('auto_scan') or {}
        _arp = _cfg.get('arp_monitor') or {}
        discovery['auto_scan'] = {
            'enabled': bool(_auto.get('enabled')),
            'interval_minutes': int(_auto.get('interval_minutes', 5) or 5),
        }
        discovery['arp_monitor'] = {
            'enabled': bool(_arp.get('enabled')),
            'interval_minutes': int(_arp.get('interval_minutes', 5) or 5),
        }
    except Exception:
        pass
    try:
        from core.bootstrap import read_wazuh_interval
        sync_seconds = read_wazuh_interval()
    except Exception:
        pass

    # v0.18.19/20 — Assistente IA: status da configuração (a CHAVE nunca
    # volta ao browser — apenas se existe, o modelo e a FONTE: .env ou painel).
    assistant_cfg = {'configured': False, 'model': '', 'source': ''}
    try:
        from services.assistant import get_settings
        _a = get_settings()
        assistant_cfg = {'configured': bool(_a['api_key']),
                         'model': _a['model'],
                         'source': _a.get('key_source', '')}
    except Exception:
        pass

    # v0.18.20 — toggle "mesclar duplicados automaticamente" (default OFF:
    # duplicados FICAM no NetScope, exclusão é manual — pedido do usuário).
    auto_merge = False
    try:
        from services.netscope_core import load_config as _lm
        auto_merge = bool(_lm().get('auto_merge'))
    except Exception:
        pass

    # v0.18.20 — preferências de notificações (system_settings)
    notif_prefs = {}
    try:
        from services.notifications import get_prefs
        notif_prefs = get_prefs()
    except Exception:
        pass

    return render_template('settings.html', machines=machines, users=users,
                           discovery=discovery, sync_seconds=sync_seconds,
                           assistant_cfg=assistant_cfg,
                           auto_merge=auto_merge, notif_prefs=notif_prefs)


@admin_required
def update_sync():
    data = request.get_json()
    seconds = data.get('seconds')
    if seconds is None:
        return jsonify(success=False, error="Intervalo inválido"), 400

    # v0.18.12 — persistência + reagendamento centralizados no bootstrap
    # (o painel de Sincronização usa o MESMO SystemSetting/job).
    from core.bootstrap import reschedule_wazuh_sync
    reschedule_wazuh_sync(int(seconds), _scheduled_sync())

    return jsonify(success=True)


@admin_required
def update_discovery():
    """v0.18.13 — Painel de Sincronização (Configurações): Ping Sweep +
    ARP Discovery em UMA gravação, com aplicação IMEDIATA.

    Body JSON (todos os campos opcionais — ausente = não muda):
      {"ping_enabled": true, "ping_interval": 15,
       "arp_enabled": true,  "arp_interval": 30}
    Intervalos em MINUTOS (5–360, clamp no backend).

    No fim, os loops de descoberta são ACORDADOS (wake_auto_scan +
    wake_monitor): a nova contagem recomeça do momento do salvamento —
    sem reler config a cada ~10s (pedido do usuário: "definir a
    execução a partir do botão salvar"). O intervalo do Wazuh segue
    sendo gravado pelo /settings/update_sync (o botão Salvar do painel
    chama os dois)."""
    data = request.get_json(silent=True) or {}

    ping_interval = data.get('ping_interval')
    arp_interval = data.get('arp_interval')
    for name, v in (('ping_interval', ping_interval), ('arp_interval', arp_interval)):
        if v is not None:
            try:
                float(v)
            except (TypeError, ValueError):
                return jsonify(success=False, error=f'{name} inválido'), 400

    from services.netscope_engine import set_auto_scan
    from services.netscope_discovery import set_monitor_enabled

    # v0.18.13 — grava só o que veio no corpo (o painel manda os 4
    # campos; corpo vazio = sucesso sem tocar em nada e SEM acordar os
    # loops à toa).
    auto = arp = None
    if 'ping_enabled' in data or ping_interval is not None:
        auto = set_auto_scan(
            enabled=bool(data['ping_enabled']) if 'ping_enabled' in data else None,
            interval_minutes=ping_interval,
        )
    if 'arp_enabled' in data or arp_interval is not None:
        arp = set_monitor_enabled(
            enabled=bool(data['arp_enabled']) if 'arp_enabled' in data else None,
            interval_minutes=arp_interval,
        )

    if auto is not None or arp is not None:
        app = _app()
        app.logger.info(
            "[Discovery] Painel de Sincronização salvou: "
            + (f"ping sweep ({auto.get('enabled')} a cada {auto.get('interval_minutes')} min) "
               if auto else "")
            + (" · " if auto and arp else "")
            + (f"ARP ({arp.get('enabled')} a cada {arp.get('interval_minutes')} min)"
               if arp else "")
            + " — loops reagendados a partir de agora.")

    return jsonify(success=True, auto_scan=auto, arp_monitor=arp)


def _scheduled_sync():
    """Callback do job — mesma composição da v0.17 (Wazuh + ponte NetScope).

    v0.18.29 FIX — "Working outside of application context": o job roda
    na thread do APScheduler, onde NÃO existe contexto Flask. Antes o
    job chamava _app() (current_app) DENTRO de si — estourava
    RuntimeError no primeiro tick após qualquer reagendamento feito pelo
    painel de Sincronização (o job do boot nunca falhava porque lá o app
    é capturado no fechamento). Agora a instância é capturada UMA vez no
    momento do agendamento (update_sync é uma rota — sempre há request
    context) e o job apenas empurra app.app_context(), igual ao boot.
    """
    from utils.collector import sync_wazuh_data
    from services.netscope_wazuh_bridge import sync_from_inventory as netscope_sync

    app = _app()  # captura AQUI — dentro do request que (re)agenda o job

    def scheduled_sync():
        with app.app_context():
            sync_wazuh_data(app)
            try:
                netscope_sync(app)
            except Exception as e:
                app.logger.error(f"[NetScope] Ponte Wazuh falhou após sync agendado: {e}")
    return scheduled_sync


@admin_required
def update_assistant():
    """v0.18.19 — grava a configuração do Assistente IA (FAB/chatbot).

    Body JSON: {"api_key": "gsk_...", "model": "llama-3.3-70b-versatile"}
    Persiste em system_settings (key='ai_assistant', JSONB). A resposta
    NUNCA devolve a chave — apenas configured/model. api_key vazio no
    corpo = remove a chave salva (o chat volta a avisar que falta
    configurar)."""
    data = request.get_json(silent=True) or {}
    api_key = (data.get('api_key') or '').strip()
    model = (data.get('model') or '').strip()
    try:
        from services.assistant import save_settings, get_settings, DEFAULT_MODEL
        saved = save_settings(api_key, model or DEFAULT_MODEL)
        # v0.18.20 — a resposta informa a FONTE efetiva da chave (a do
        # .env tem prioridade sobre a salva aqui)
        eff = get_settings()
        _app().logger.info(
            "[Assistente IA] Configuração atualizada "
            f"(chave {'definida' if saved['api_key'] else 'removida'}, "
            f"modelo {saved['model']}).")
        return jsonify(success=True, configured=bool(eff['api_key']),
                       model=eff['model'],
                       source=eff.get('key_source', ''))
    except Exception as e:
        _app().logger.error(f"[Assistente IA] Erro ao salvar configuração: {e}")
        return jsonify(success=False, error=str(e)), 500


@admin_required
def test_assistant():
    """v0.18.20 — TESTE REAL da configuração do Assistente IA (pedido:
    "pode ate fazer um teste antes pra certificar se esta ok").

    Body JSON OPCIONAL: {"api_key": "...", "model": "..."} — quando a
    chave vem do formulário, testa ANTES de salvar; sem corpo, testa a
    configuração efetiva (.env → painel). NUNCA devolve a chave."""
    data = request.get_json(silent=True) or {}
    try:
        from services.assistant import test_connection
        ok, info = test_connection(data.get('api_key'), data.get('model'))
        if not ok:
            return jsonify(success=False, error=info.get('error', 'error'))
        return jsonify(success=True, models=info.get('models', 0),
                       model=info.get('model', ''),
                       model_available=bool(info.get('model_available')))
    except Exception as e:
        return jsonify(success=False, error=str(e)), 500


@admin_required
def assistant_models():
    """v0.18.23 — MODELOS DISPONÍVEIS na conta do provedor (Groq).

    Cura o erro "O modelo configurado não foi encontrado no provedor":
    em vez de digitar o id às cegas, o admin CLICA no datalist do painel
    e escolhe entre os modelos que EXISTEM na conta (GET /openai/v1/models).

    Body JSON OPCIONAL: {"api_key": "gsk_…"} — quando a chave vem do
    formulário, lista com ela (confere antes de salvar); sem corpo, usa
    a configuração efetiva (.env → painel). NUNCA devolve a chave. Em
    falha devolve success=False + a lista de fallback para o datalist
    continuar utilizável offline."""
    data = request.get_json(silent=True) or {}
    try:
        from services.assistant import list_models
        ok, info = list_models(data.get('api_key'))
        return jsonify(success=bool(ok), models=info.get('models', []),
                       error=info.get('error'))
    except Exception as e:
        _app().logger.error(f"[Assistente IA] Erro ao listar modelos: {e}")
        return jsonify(success=False, models=[], error=str(e)), 500


@admin_required
def update_dedup():
    """v0.18.20 — toggle "Mesclar duplicados automaticamente".

    Pedido do usuário: "OS ATIVOS DUPLICADOS... DEVERIA FICAR SEMPRE NO
    NETSCOPE, A EXCLUSAO SERIA UM PROCESSO MANUAL, OU EXCLUSAO POR
    GRUPOS, COM CAIXA DE SELEÇÃO". Default: OFF — duplicados ficam
    visíveis no NetScope com badge; a exclusão é feita pela seleção com
    checkboxes na Tabela de Ativos (vai para a lixeira, restaurável).
    ON (comportamento antigo): a dedup pós-sync manda o duplicado para
    a lixeira automaticamente com o selo "Mesclado automaticamente"."""
    data = request.get_json(silent=True) or {}
    from services.netscope_core import load_config, save_config
    cfg = load_config()
    cfg['auto_merge'] = bool(data.get('auto_merge'))
    save_config(cfg)
    _app().logger.info(
        f"[NetScope] Mesclagem automática de duplicados: "
        f"{'LIGADA' if cfg['auto_merge'] else 'DESLIGADA (exclusão manual)'}")
    return jsonify(success=True, auto_merge=cfg['auto_merge'])


@login_required
def update_notifications():
    """v0.18.20 — preferências da central de notificações (FAB).

    Body JSON: {"enabled": bool, "security": bool, "asset": bool,
    "compliance": bool, "coverage_min": int}. Salvas em system_settings
    (key='notifications') — "tudo ... configuracoes do sistema, devem
    estar no banco de dados". A leitura é aberta a usuários logados (o
    FAB é de todos); a GRAVAÇÃO exige admin (mesmo padrão dos demais
    painéis — validado aqui dentro, pois o wrapper login_required não
    checa papel)."""
    if session.get('role') != 'admin':
        return jsonify(success=False, error='Somente administrador'), 403
    data = request.get_json(silent=True) or {}
    from services.notifications import save_prefs, DEFAULT_PREFS
    prefs = {k: data[k] for k in DEFAULT_PREFS if k in data}
    if 'coverage_min' in prefs:
        try:
            prefs['coverage_min'] = max(0, min(100, int(prefs['coverage_min'])))
        except (TypeError, ValueError):
            prefs.pop('coverage_min', None)
    saved = save_prefs(prefs)
    return jsonify(success=True, prefs=saved)


@login_required
def save_dashboard_layout():
    """v0.18.20 — layout do dashboard NO BANCO (pedido: "tudo da
    aplicação ... devem estar no banco de dados").

    Body JSON: {"layout": {"v": 1, "containers": [[...], ...]}} —
    gravado em system_settings (key='dashboard_layout') POR USUÁRIO
    (value = {username: layout}). O restore no dashboard prefere o
    layout do banco (segue o usuário entre navegadores/máquinas) e só
    cai para o localStorage quando o banco não tem layout dele."""
    body = request.get_json(silent=True) or {}
    layout = body.get('layout')
    if not isinstance(layout, dict) or not isinstance(layout.get('containers'), list):
        return jsonify(success=False, error='layout inválido'), 400
    username = session.get('username', '')
    row = SystemSetting.query.filter_by(key='dashboard_layout').first()
    value = row.value if (row and isinstance(row.value, dict)) else {}
    # mantém só os layouts dos usuários existentes + o atual (teto 20)
    value = {k: v for k, v in value.items() if isinstance(v, dict)} if isinstance(value, dict) else {}
    value[username] = layout
    if len(value) > 20:
        try:
            value.pop(next(iter(value)))
        except Exception:
            pass
    if row:
        row.value = value
    else:
        db.session.add(SystemSetting(key='dashboard_layout', value=value))
    db.session.commit()
    return jsonify(success=True)


@admin_required
def sync_now():
    """v0.18.18 — o botão "Sincronizar Agora" faz AS 3 AÇÕES (pedido do
    usuário): sync Wazuh + Ping Sweep + ARP Discovery, em sequência, na
    thread de fundo (core.app.run_full_sync). Redes não configuradas
    pulam ping/arp graciosamente; cada etapa isola a própria falha.
    v0.18.21 — devolve também `seq` (identificador do disparo): a UI
    pola /settings/sync_status e recarrega a página quando o motor
    terminar ("após a sincronização atualizar as páginas")."""
    app = _app()
    try:
        from core.app import run_full_sync, FULL_SYNC_STATE
        with FULL_SYNC_STATE['lock']:
            FULL_SYNC_STATE['seq'] += 1
            FULL_SYNC_STATE['running'] = True
            FULL_SYNC_STATE['finished_at'] = None
            from datetime import datetime as _dt
            FULL_SYNC_STATE['started_at'] = _dt.now().strftime('%Y-%m-%d %H:%M:%S')
            seq = FULL_SYNC_STATE['seq']
        threading.Thread(target=run_full_sync, args=(app, seq), daemon=True).start()
        app.MACHINES_CACHE['data'] = None
        app.STATS_CACHE['data'] = None
        from utils import cache as shared_cache
        shared_cache.invalidate('machines', 'stats')

        app.logger.info("Sincronização manual disparada pelo administrador "
                        "(ações: sync Wazuh + Ping Sweep + ARP Discovery).")
        return jsonify(success=True, actions=['sync', 'ping', 'arp'], seq=seq)
    except Exception as e:
        app.logger.error(f"Erro ao disparar sincronização manual: {e}")
        try:
            from core.app import FULL_SYNC_STATE
            with FULL_SYNC_STATE['lock']:
                FULL_SYNC_STATE['running'] = False
        except Exception:
            pass
        return jsonify(success=False, error=str(e))


@login_required
def sync_status():
    """v0.18.21 — estado do "Sincronizar Agora" para a UI: running, seq
    do último disparo e done_seq do último concluído. Quando running==False
    e done_seq >= seq do disparo, a página recarrega com os dados novos."""
    from core.app import full_sync_status
    return jsonify(full_sync_status())


@login_required
def change_password():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_new_password = request.form.get('confirm_new_password')

    # v0.18.4 — a UI nova (estilo MFA) chama via fetch e espera JSON;
    # o POST de formulário clássico segue funcionando igual (flash+redirect).
    wants_json = request.headers.get('X-Requested-With') == 'XMLHttpRequest'

    def _err(msg, code=400):
        if wants_json:
            return jsonify({'success': False, 'error': msg}), code
        flash(msg, "danger")
        return redirect(url_for('settings'))

    if new_password != confirm_new_password:
        return _err("A nova senha e a confirmação não coincidem.")

    from core.security import verify_password
    app = _app()
    user = User.query.filter_by(username=session['username']).first()
    if user and verify_password(app, user.password_hash, current_password):
        user.password_hash = hash_password(new_password)
        # v0.18 — conclui a troca obrigatória do 1º login
        if getattr(user, 'must_change_password', False):
            user.must_change_password = False
        session.pop('must_change_password', None)
        db.session.commit()
        if wants_json:
            return jsonify({'success': True,
                            'message': "Senha alterada com sucesso."})
        flash("Senha alterada com sucesso.", "success")
    else:
        return _err("Senha atual incorreta.", 401)
    return redirect(url_for('settings'))


def get_data():
    if 'username' not in session:
        return redirect(url_for('login'))

    try:
        from core.app import sync_wazuh_and_netscope
        thread = threading.Thread(target=sync_wazuh_and_netscope, args=(_app(),))
        thread.start()
        _app().logger.info("Sincronização iniciada via get_data (fontes: Wazuh e rede)")
        flash(_translate('Sincronização iniciada, aguarde alguns instantes.'), 'success')
        return redirect(url_for('settings'))
    except Exception as e:
        _app().logger.error(f"Erro ao iniciar sincronização: {str(e)}")
        return jsonify({'error': str(e)}), 500


def _translate(key):
    from core.i18n import translate
    return translate(key)


def mfa_status():
    if 'username' not in session:
        # v0.18.18 — flag uniforme p/ o fetch-guard (login expirado)
        return jsonify({'error': 'Não autenticado',
                        'session_expired': True}), 401

    user = User.query.filter_by(username=session['username']).first()

    if user:
        return jsonify({
            'enabled': user.mfa_enabled,
            'configured': bool(user.mfa_secret)
        })
    return jsonify({'error': 'Usuário não encontrado'}), 404


def toggle_mfa():
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Não autenticado',
                        'session_expired': True}), 401

    user = User.query.filter_by(username=session['username']).first()

    if not user:
        return jsonify({'success': False, 'error': 'Usuário não encontrado'}), 404

    action = request.json.get('action')

    if action == 'enable':
        secret = pyotp.random_base32()
        user.mfa_secret = secret
        user.mfa_enabled = False

        try:
            db.session.commit()
            totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
                name=user.username,
                issuer_name="Inventory"
            )
            # v0.18.2 — QR em ALTA RESOLUÇÃO: `qrcode.make()` padrão gera
            # PNG pequeno/serrilhado, que esticado no modal ficava difícil
            # de escanear. QRCode explícito: box_size 12 (módulos maiores),
            # border 2 (menos margem desperdiçada) e correção de erro M
            # (escaneia mesmo com até 15% da imagem encoberta).
            img = qrcode.QRCode(
                error_correction=qrcode.constants.ERROR_CORRECT_M,
                box_size=12,
                border=2,
            )
            img.add_data(totp_uri)
            img.make(fit=True)
            buffered = BytesIO()
            img.make_image(fill_color="black", back_color="white").save(buffered, "PNG")
            img_str = base64.b64encode(buffered.getvalue()).decode()
            qr_code = f"data:image/png;base64,{img_str}"
            return jsonify({'success': True, 'qr_code': qr_code, 'secret': secret})
        except Exception as e:
            db.session.rollback()
            _app().logger.error(f"Erro ao gerar segredo MFA: {str(e)}")
            return jsonify({'success': False, 'error': 'Erro ao gerar segredo MFA'}), 500

    elif action == 'disable':
        user.mfa_enabled = False
        user.mfa_secret = None
        try:
            db.session.commit()
            return jsonify({'success': True})
        except Exception as e:
            db.session.rollback()
            _app().logger.error(f"Erro ao desabilitar MFA: {str(e)}")
            return jsonify({'success': False, 'error': 'Erro ao desabilitar MFA'}), 500

    return jsonify({'success': False, 'error': 'Ação inválida'}), 400


def verify_mfa_setup():
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Não autenticado',
                        'session_expired': True}), 401

    user = User.query.filter_by(username=session['username']).first()
    if not user:
        return jsonify({'success': False, 'error': 'Usuário não encontrado'}), 404

    code = request.json.get('code', '')

    totp = pyotp.TOTP(user.mfa_secret)
    if totp.verify(code, valid_window=1):
        user.mfa_enabled = True

        try:
            db.session.commit()
            return jsonify({'success': True})
        except Exception as e:
            db.session.rollback()
            _app().logger.error(f"Erro ao salvar MFA: {str(e)}")
            return jsonify({'success': False, 'error': 'Erro ao salvar MFA'}), 500
    else:
        return jsonify({'success': False, 'error': 'Código inválido'}), 400


def export_pdf():
    """Gera o relatório PDF do parque completo (v0.14.0 — fluxo idêntico)."""
    if 'username' not in session:
        return redirect(url_for('login'))

    from utils.pdf_export import generate_pdf_report

    app = _app()
    include_details = request.args.get('include_details', '0') == '1'
    from services.stats import get_cached_stats, get_cached_machines
    stats = get_cached_stats()
    machines = get_cached_machines()

    # ── grupos Wazuh (mesma fonte do dashboard) ──
    groups_data = []
    try:
        groups_objs = Group.query.filter_by(is_legacy=False).all()
        groups_data = [g.data for g in groups_objs if g.data]
    except Exception as e:
        app.logger.warning(f"[export_pdf] Grupos indisponíveis: {e}")

    # ── NetScope: dispositivos ativos + estatísticas ──
    ns_devices, ns_stats = [], {}
    try:
        from services.netscope_core import store as _ns_store
        ns_devices = _ns_store.active()
        ns_stats = _ns_store.stats()
    except Exception as e:
        app.logger.warning(f"[export_pdf] NetScope indisponível: {e}")

    # ── NetScope: CONFIGURAÇÃO DE SWITCHES (v0.14.0) ──
    switches = []
    try:
        from services.netscope_switches import get_switches_with_ports
        switches = get_switches_with_ports()
    except Exception as e:
        app.logger.warning(f"[export_pdf] Switches indisponíveis: {e}")

    # ── MERGE de fontes (Wazuh + NetScope) ──
    from utils.report_data import merge_machines_devices
    rows = merge_machines_devices(machines, ns_devices)

    pdf_buffer = generate_pdf_report(
        stats, machines, rows, ns_stats, groups_data,
        switches=switches,
        include_details=include_details,
        generated_by=session.get('username', ''),
        lang=session.get('language', 'pt'),
        devices=ns_devices)

    ts = datetime.now().strftime('%Y%m%d_%H%M')
    file_name = f'relatorio_infraestrutura_{ts}.pdf'

    response = make_response(pdf_buffer.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = (
        f'attachment; filename={file_name}')
    return response
