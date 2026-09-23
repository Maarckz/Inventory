
import json
import logging

from datetime import datetime

def _base_url():
    from core import config as _cfg
    raw = (getattr(_cfg, 'GROQ_BASE_URL', '') or '').strip().rstrip('/')
    if not raw:
        return 'https://api.groq.com/openai/v1'
    if not raw.endswith('/openai/v1'):
        raw += '/openai/v1'
    return raw

DEFAULT_MODEL = 'openai/gpt-oss-20b'
SETTINGS_KEY = 'ai_assistant'

FALLBACK_MODELS = [
    'openai/gpt-oss-20b',
    'openai/gpt-oss-120b',
    'llama-3.3-70b-versatile',
    'llama-3.1-8b-instant',
    'qwen/qwen3-32b',
    'deepseek-r1-distill-llama-70b',
    'moonshotai/kimi-k2-instruct',
]

MAX_HISTORY = 10
MAX_DEVICES_IN_CONTEXT = 80
MAX_HOSTS_IN_CONTEXT = 120
MAX_DIFF_ITEMS = 12

MAX_DETAIL_HOSTS = 3
MAX_DETAIL_PORTS = 40
MAX_DETAIL_PROCS = 40
MAX_DETAIL_PKGS = 12
MAX_PORTSCAN_PORTS = 50

RATE_RETRIES = 2
RATE_BACKOFF_BASE = 1.5
FALLBACK_CHAIN = [
    'llama-3.1-8b-instant',
    'openai/gpt-oss-120b',
    'openai/gpt-oss-20b',
]

LANG_NAME = {
    'pt': 'português (BR)', 'en': 'English', 'es': 'español',
    'hi': 'हिन्दी (Hindi)', 'ru': 'русский (Russian)',
    'zh': '中文 (Mandarin Chinese)', 'ar': 'العربية (Arabic)',
    'fr': 'français (French)',
}

def get_settings():

    from core import config as _cfg
    out = {'api_key': '', 'model': DEFAULT_MODEL,
           'key_source': '', 'db_key': '', 'db_model': ''}
    try:
        from models import SystemSetting
        row = SystemSetting.query.filter_by(key=SETTINGS_KEY).first()
        if row and isinstance(row.value, dict):
            out['db_key'] = (row.value.get('api_key') or '').strip()
            out['db_model'] = (row.value.get('model') or '').strip()
    except Exception:
        pass
    if _cfg.GROQ_API_KEY:
        out['api_key'] = _cfg.GROQ_API_KEY
        out['key_source'] = 'env'
        out['model'] = _cfg.GROQ_MODEL or out['db_model'] or DEFAULT_MODEL
    elif out['db_key']:
        out['api_key'] = out['db_key']
        out['key_source'] = 'painel'
        out['model'] = out['db_model'] or DEFAULT_MODEL
    return out

def save_settings(api_key, model):

    from models import SystemSetting, db
    value = {
        'api_key': (api_key or '').strip(),
        'model': (model or '').strip() or DEFAULT_MODEL,
    }
    row = SystemSetting.query.filter_by(key=SETTINGS_KEY).first()
    if row:
        row.value = value
    else:
        db.session.add(SystemSetting(key=SETTINGS_KEY, value=value))
    db.session.commit()
    return value

HISTORY_LOAD = 60
HISTORY_CHARS = 1500

def get_history(username, limit=HISTORY_LOAD):

    if not username:
        return []
    try:
        from models import ChatMessage
        rows = (ChatMessage.query
                .filter_by(username=username)
                .order_by(ChatMessage.id.desc())
                .limit(max(1, int(limit)))
                .all())
        rows.reverse()
        return [{'role': r.role, 'content': r.content,
                 'created_at': (r.created_at or datetime.utcnow()).isoformat()}
                for r in rows if r.role in ('user', 'assistant')]
    except Exception:
        return []

def add_history(username, role, content):

    if not username or role not in ('user', 'assistant') or not (content or '').strip():
        return
    try:
        from models import ChatMessage, db
        db.session.add(ChatMessage(username=username, role=role,
                                   content=str(content).strip()[:8000]))
        db.session.commit()
    except Exception:
        try:
            from models import db as _db
            _db.session.rollback()
        except Exception:
            pass

def clear_history(username):

    if not username:
        return 0
    try:
        from models import ChatMessage, db
        n = ChatMessage.query.filter_by(username=username).delete()
        db.session.commit()
        return int(n or 0)
    except Exception:
        try:
            from models import db as _db
            _db.session.rollback()
        except Exception:
            pass
        return 0

def list_models(api_key=None):

    cfg = get_settings()
    key = (api_key or '').strip() or cfg['api_key']
    if not key:
        return False, {'error': 'no_api_key',
                       'models': list(FALLBACK_MODELS)}

    import requests
    try:
        r = requests.get(
            _base_url() + '/models',
            headers={'Authorization': 'Bearer ' + key},
            timeout=15,
        )
    except Exception as e:
        return False, {'error': 'connection_error: ' + str(e),
                       'models': list(FALLBACK_MODELS)}

    if r.status_code == 401:
        return False, {'error': 'invalid_api_key',
                       'models': list(FALLBACK_MODELS)}
    if r.status_code == 429:
        return False, {'error': 'rate_limited',
                       'models': list(FALLBACK_MODELS)}
    if r.status_code != 200:
        try:
            detail = (r.json() or {}).get('error', {}).get('message', '')
        except Exception:
            detail = ''
        return False, {'error': 'api_error: ' + (detail or ('HTTP ' + str(r.status_code))),
                       'models': list(FALLBACK_MODELS)}

    try:
        data = r.json()
        ids = sorted({(m.get('id') or '').strip()
                      for m in (data.get('data') or [])} - {''})
    except Exception:
        return False, {'error': 'bad_response',
                       'models': list(FALLBACK_MODELS)}
    if not ids:
        return False, {'error': 'bad_response',
                       'models': list(FALLBACK_MODELS)}
    return True, {'models': ids}

def test_connection(api_key=None, model=None):

    cfg = get_settings()
    key = (api_key or '').strip() or cfg['api_key']
    model = (model or '').strip() or cfg['model']
    if not key:
        return False, {'error': 'no_api_key'}

    import requests
    try:
        r = requests.get(
            _base_url() + '/models',
            headers={'Authorization': 'Bearer ' + key},
            timeout=15,
        )
    except Exception as e:
        return False, {'error': 'connection_error: ' + str(e)}

    if r.status_code == 401:
        return False, {'error': 'invalid_api_key'}
    if r.status_code == 429:
        return False, {'error': 'rate_limited'}
    if r.status_code != 200:
        try:
            detail = (r.json() or {}).get('error', {}).get('message', '')
        except Exception:
            detail = ''
        return False, {'error': 'api_error: ' + (detail or ('HTTP ' + str(r.status_code)))}

    try:
        data = r.json()
        ids = {m.get('id') for m in (data.get('data') or [])}
    except Exception:
        return False, {'error': 'bad_response'}
    return True, {'models': len(ids), 'model': model,
                  'model_available': model in ids}

def _ports_summary(inv):

    tcp, udp = [], []
    for p in inv.get('ports', []) or []:
        if not isinstance(p, dict):
            continue
        try:
            port = int(float((p.get('local') or {}).get('port') or 0))
        except (TypeError, ValueError):
            continue
        if not 0 < port <= 65535:
            continue
        proto = (p.get('protocol') or '').strip().lower()
        proc = str(p.get('process') or '').strip()
        state = (p.get('state') or '').strip().lower()
        label = (f"{port}({proc})" if proc
                 and proc.lower() not in ('n/a', 'unknown', '-')
                 else str(port))
        if proto == 'udp':
            if len(udp) < MAX_DETAIL_PORTS and label not in udp:
                udp.append(label)
        elif state in ('listening', ''):
            if len(tcp) < MAX_DETAIL_PORTS and label not in tcp:
                tcp.append(label)
    return tcp, udp

def _count_key(inv, key):

    try:
        return len(inv.get(key) or [])
    except Exception:
        return 0

def _wazuh_block(app):

    try:
        from models import HostInventory
        hosts = HostInventory.query.filter_by(is_legacy=False).all()
        status = {}
        groups = {}
        os_count = {}
        rows = []
        for h in hosts:
            data = h.data or {}
            ai = data.get('agent_info', {}) or {}
            inv = data.get('inventory', {}) or {}
            st = (ai.get('status') or 'unknown').strip() or 'unknown'
            status[st] = status.get(st, 0) + 1
            hgroups = [g for g in (data.get('groups') or ai.get('group') or []) if g]
            for g in hgroups:
                groups[g] = groups.get(g, 0) + 1

            os_host = inv.get('os', []) or [{}]
            os_name = ''
            os_ver = ''
            if os_host:
                os_data = os_host[0].get('os', {}) or {}
                os_name = os_data.get('name') or ''
                os_ver = os_data.get('version') or ''
            if os_name:
                os_count[os_name] = os_count.get(os_name, 0) + 1

            ip = (ai.get('ip') or '').strip()
            if ip in ('', '127.0.0.1', 'N/A', 'n/a', 'unknown', 'localhost'):
                for addr in inv.get('netaddr', []) or []:
                    a = (addr.get('address') or '').strip()
                    if a and a not in ('127.0.0.1',) and '.' in a:
                        ip = a
                        break

            cpu, ram = '', ''
            hw = inv.get('hardware', []) or [{}]
            if hw:
                cpu = str((hw[0].get('cpu') or {}).get('name') or '')[:40]
                try:
                    ram_total = int(float((hw[0].get('ram') or {}).get('total') or 0))
                    ram = str(round(ram_total / (1024 * 1024), 1)) if ram_total else ''
                except (TypeError, ValueError):
                    ram = ''

            ka = (ai.get('lastKeepAlive') or '')[:10]

            tcp_l, udp_l = _ports_summary(inv)
            n_listen = len(tcp_l) + len(udp_l)
            n_procs = _count_key(inv, 'processes')
            n_pkgs = _count_key(inv, 'packages')

            if len(rows) < MAX_HOSTS_IN_CONTEXT:
                rows.append([h.hostname or ai.get('name') or '?',
                             str(ai.get('id') or ''), st, ip,
                             (os_name + (' ' + os_ver if os_ver else '')).strip(),
                             ','.join(hgroups[:4]), cpu, ram, ka,
                             n_listen, n_procs, n_pkgs])

        return {
            'hosts_total': len(hosts),
            'agents_status': status,
            'top_groups': sorted(groups.items(), key=lambda kv: -kv[1])[:8],
            'top_os': sorted(os_count.items(), key=lambda kv: -kv[1])[:8],
            'hosts': rows,
            'hosts_truncated': max(0, len(hosts) - len(rows)),
        }
    except Exception as e:
        return {'error': str(e)}

_QUESTION_STOPWORDS = {
    'host', 'hosts', 'com', 'para', 'uma', 'tem', 'qual', 'quais', 'que',
    'dos', 'das', 'como', 'onde', 'sobre', 'tipo', 'mais', 'esta', 'está',
    'esse', 'essa', 'pelo', 'pela', 'tudo', 'todo', 'nao', 'não', 'meu',
    'minha', 'the', 'and', 'have', 'has', 'what', 'which', 'does', 'are',
    'there', 'any', 'são', 'sao', 'existe', 'existem', 'show', 'me',
    'list', 'lista', 'todos', 'todas', 'outro', 'outra', 'antes', 'depois',
}

def _host_detail_dict(h):

    data = h.data or {}
    ai = data.get('agent_info', {}) or {}
    inv = data.get('inventory', {}) or {}

    ip = (ai.get('ip') or '').strip()
    if ip in ('', '127.0.0.1', 'N/A', 'n/a', 'unknown', 'localhost'):
        for addr in inv.get('netaddr', []) or []:
            a = (addr.get('address') or '').strip()
            if a and a not in ('127.0.0.1',) and '.' in a:
                ip = a
                break

    os_host = inv.get('os', []) or [{}]
    os_data = (os_host[0].get('os', {}) or {}) if os_host else {}
    os_name = (str(os_data.get('name') or '') +
               ((' ' + str(os_data.get('version', '')))
                if os_data.get('version') else '')).strip()

    tcp_l, udp_l = _ports_summary(inv)

    ifaces = []
    for nif in (inv.get('netiface', []) or [])[:8]:
        if not isinstance(nif, dict):
            continue
        mac = (nif.get('mac') or '').strip()
        if mac in ('n/a', '00:00:00:00:00:00', ''):
            mac = ''
        ifaces.append({'name': (nif.get('name') or '')[:16], 'mac': mac})

    procs = []
    for pr in inv.get('processes', []) or []:
        if not isinstance(pr, dict):
            continue
        try:
            pid = int(float(pr.get('pid') or 0))
        except (TypeError, ValueError):
            pid = 0
        procs.append((pid, {
            'pid': pid or None,
            'name': str(pr.get('name') or '')[:40],
            'user': str(pr.get('euser') or '')[:24],
            'cmd': str(pr.get('cmd') or '')[:70],
        }))
    procs.sort(key=lambda t: t[0])

    pkgs = []
    for pk in inv.get('packages', []) or []:
        if not isinstance(pk, dict):
            continue
        pkgs.append((str(pk.get('install_time') or ''),
                     str(pk.get('name') or '')[:40],
                     str(pk.get('version') or '')[:20]))
    pkgs.sort(key=lambda t: t[0], reverse=True)

    return {
        'hostname': h.hostname or ai.get('name') or '?',
        'agent_id': str(ai.get('id') or ''),
        'status': (ai.get('status') or 'unknown'),
        'ip': ip,
        'os': os_name,
        'groups': [g for g in (data.get('groups') or ai.get('group') or []) if g][:6],
        'last_keepalive': (ai.get('lastKeepAlive') or '')[:19],
        'interfaces': ifaces,
        'listening_tcp': tcp_l,
        'udp': udp_l,
        'processes': {'total': _count_key(inv, 'processes'),
                      'items': [p for _, p in procs[:MAX_DETAIL_PROCS]]},
        'packages': {'total': _count_key(inv, 'packages'),
                     'recent': [{'name': n, 'version': v}
                                for _, n, v in pkgs[:MAX_DETAIL_PKGS]]},
    }

def _wazuh_detail_block(question=''):

    q = (question or '').strip().lower()
    if not q:
        return {}
    import re as _re
    qtokens = set(t for t in _re.split(r'[^a-z0-9_.:-]+', q) if t)

    try:
        from models import HostInventory
        hosts = HostInventory.query.filter_by(is_legacy=False).all()
    except Exception:
        return {}

    def _matches(h):
        data = h.data or {}
        ai = data.get('agent_info', {}) or {}
        inv = data.get('inventory', {}) or {}
        for cand in (h.hostname or '', ai.get('name') or ''):
            c = (cand or '').strip().lower()
            if not c:
                continue
            base = c.split('.')[0]
            if (len(base) >= 3 and base not in _QUESTION_STOPWORDS
                    and (base in qtokens or base in q)):
                return True
        ip = (ai.get('ip') or '').strip()
        for addr in inv.get('netaddr', []) or []:
            a = (addr.get('address') or '').strip()
            if a and a not in ('127.0.0.1',) and '.' in a:
                ip = ip if ip and ip != '127.0.0.1' else a
                break
        if ip and ip in q:
            return True
        os_host = inv.get('os', []) or [{}]
        if os_host:
            os_name = str(((os_host[0].get('os', {}) or {}).get('name')) or '')
            first = os_name.strip().lower().split()[0] if os_name.strip() else ''
            if (len(first) >= 3 and first not in _QUESTION_STOPWORDS
                    and first in qtokens):
                return True
        return False

    matched = [h for h in hosts if _matches(h)]
    if not matched:
        generic = any(t in q for t in ('porta', 'portas', 'processo',
                                       'processos', 'pacote', 'pacotes',
                                       'escutando', 'escuta', 'port',
                                       'process', 'package', 'listening',
                                       'servico', 'serviço'))
        if generic and len(hosts) <= MAX_DETAIL_HOSTS:
            matched = list(hosts)
    if not matched:
        return {}

    detail = {}
    for h in matched[:MAX_DETAIL_HOSTS]:
        try:
            d = _host_detail_dict(h)
        except Exception:
            continue
        detail[d.get('hostname') or '?'] = d
    if len(matched) > MAX_DETAIL_HOSTS:
        detail['_note'] = (f'{len(matched)} hosts casaram com a pergunta — '
                           f'detalhe limitado a {MAX_DETAIL_HOSTS}.')
    return detail

def _netscope_block(app):

    out = {}
    try:
        from services.netscope_core import store, load_config
        act = store.active()
        out['stats'] = store.stats()
        out['stats']['trash_count'] = len(store.trashed())
        out['stats']['trash_merged'] = sum(
            1 for d in store.trashed() if d.get('merged_into'))
        out['conflicts'] = store.ip_conflicts()
        cfg = load_config()
        out['networks'] = [
            {'subnet': n.get('subnet', ''), 'gateway': n.get('gateway', '')}
            for n in (cfg.get('networks') or [])]
        devs = []
        for d in act[:MAX_DEVICES_IN_CONTEXT]:
            devs.append({
                'name': d.get('hostname') or d.get('dns_name') or d.get('ip', ''),
                'ip': d.get('ip', ''), 'mac': d.get('mac', ''),
                'type': d.get('type', ''), 'status': d.get('status', ''),
                'has_agent': bool(d.get('has_agent')),
                'user': d.get('user', ''), 'department': d.get('department', ''),
                'switch': (d.get('switch_port') or {}).get('switch_mac', ''),
                'port': (d.get('switch_port') or {}).get('port'),
                'vlan': (d.get('switch_port') or {}).get('vlan', ''),
            })
        out['devices'] = devs
        out['devices_total'] = len(act)
        out['devices_truncated'] = max(0, len(act) - len(devs))
        out['switches'] = _switches_block(cfg)
    except Exception as e:
        out['error'] = str(e)
    return out

def _switches_block(cfg):

    out = []
    try:
        from services.netscope_switches import get_switches_with_ports
        for sw in get_switches_with_ports():
            ports = sw.get('ports', {}) or {}
            used = sum(1 for p in ports.values() if (p.get('device_mac') or '').strip())
            vlans = sorted({str(p.get('vlan')) for p in ports.values()
                            if (p.get('vlan') or '').strip()})
            out.append({
                'name': sw.get('name') or sw.get('mac', ''),
                'mac': sw.get('mac', ''),
                'port_count': sw.get('port_count', 0),
                'ports_used': used,
                'ports_free': max(0, int(sw.get('port_count', 0)) - used),
                'vlans': vlans[:12],
            })
    except Exception:
        pass
    return out

def _diff_block():

    try:
        from services.netscope_snapshots import get_instance
        snaps = get_instance().list_snapshots()
        if len(snaps) < 2:
            return {'available': False,
                    'reason': 'menos de 2 snapshots no histórico'}
        newest, previous = snaps[0], snaps[1]
        cmp = get_instance().compare_snapshots(previous.get('snap_id'),
                                               newest.get('snap_id'))
        if not cmp:
            return {'available': False, 'reason': 'comparação indisponível'}

        def _short(items, kind):
            out = []
            for it in items[:MAX_DIFF_ITEMS]:
                row = {'name': it.get('hostname') or it.get('ip') or it.get('mac', ''),
                       'ip': it.get('ip', '')}
                if kind == 'changed':
                    row['fields'] = sorted((it.get('diffs') or {}).keys())
                out.append(row)
            return out

        return {
            'available': True,
            'previous': {'label': cmp['a'].get('label', ''),
                         'created_at': cmp['a'].get('created_at', '')},
            'current': {'label': cmp['b'].get('label', ''),
                        'created_at': cmp['b'].get('created_at', '')},
            'added': _short(cmp.get('added', []), 'added'),
            'removed': _short(cmp.get('removed', []), 'removed'),
            'changed': _short(cmp.get('changed', []), 'changed'),
            'counts': {'added': len(cmp.get('added', [])),
                       'removed': len(cmp.get('removed', [])),
                       'changed': len(cmp.get('changed', []))},
        }
    except Exception as e:
        return {'available': False, 'reason': str(e)}

def _fmt_ports(entries, cap):

    rows = []
    for e in (entries or [])[:cap]:
        if not isinstance(e, dict):
            continue
        try:
            p = int(float(e.get('port') or 0))
        except (TypeError, ValueError):
            continue
        if not p:
            continue
        name = str(e.get('name') or '').strip()
        rows.append(f"{p}({name})" if name and name.lower() != 'unknown'
                    else str(p))
    return rows

def _portscan_block():

    try:
        from models import NetscopeScanHistory
        rows = (NetscopeScanHistory.query
                .order_by(NetscopeScanHistory.id.desc())
                .limit(3).all())
        out = []
        for r in rows:
            res = r.results if isinstance(r.results, dict) else {}
            tcp = res.get('tcp') or []
            udp_o = res.get('udp_open') or []
            udp_f = res.get('udp_open_filtered') or []
            entry = {'device': r.hostname or r.ip, 'ip': r.ip,
                     'status': r.status, 'started_at': r.started_at,
                     'finished_at': r.finished_at,
                     'tcp_open': r.tcp_count, 'udp_open': r.udp_count}
            if r.status == 'done':
                tcp_list = _fmt_ports(tcp, MAX_PORTSCAN_PORTS)
                if len(tcp) > MAX_PORTSCAN_PORTS:
                    tcp_list.append(f'+{len(tcp) - MAX_PORTSCAN_PORTS} '
                                    'outras portas altas')
                entry['tcp_ports'] = tcp_list
                entry['udp_ports'] = _fmt_ports(udp_o + udp_f, 20)
            if r.error:
                entry['error'] = str(r.error)[:120]
            out.append(entry)
        return out
    except Exception:
        return []

def build_context(question=''):

    return {
        'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'wazuh': _wazuh_block(None),
        'wazuh_detail': _wazuh_detail_block(question),
        'netscope': _netscope_block(None),
        'network_diff': _diff_block(),
        'recent_portscans': _portscan_block(),
    }

def _format_context(ctx):
    try:
        return json.dumps(ctx, ensure_ascii=False, default=str)
    except Exception:
        return json.dumps({'error': 'context serialization failed'},
                          ensure_ascii=False)

def build_system_prompt(lang, question=''):
    ctx = _format_context(build_context(question))
    lang_name = LANG_NAME.get(lang, 'português (BR)')
    return (
        "Você é o assistente IA integrado ao Inventory, um sistema de "
        "inventário de TI que monitora hosts Wazuh e dispositivos de rede "
        "(módulo NetScope), incluindo switches, portas, VLANs, varreduras "
        "de portas e snapshots de topologia.\n\n"
        "DADOS ATUAIS DO BANCO (fonte única de verdade — use APENAS estes "
        "dados para números, nomes e comparações; nunca invente "
        "dispositivos, IPs ou estatísticas):\n"
        + ctx +
        "\n\nREGRAS:\n"
        "1. Responda SEMPRE no idioma " + lang_name + ".\n"
        "2. Seja conciso e objetivo: respostas curtas com números exatos, "
        "listas com nomes/IPs quando útil.\n"
        "3. Quando perguntarem sobre mudanças/diferenças, compare os "
        "bloco 'network_diff' (added/removed/changed entre os dois "
        "snapshots mais recentes) e cite os dispositivos.\n"
        "4. Se o dado pedido não existir no contexto, diga honestamente "
        "que não tem essa informação no banco agora.\n"
        "5. v0.18.24 — a interface RENDERIZA markdown: negrito, itálico, "
        "listas (- item), títulos (##), código e TABELAS (| a | b |) são "
        "bem-vindos. Use tabelas só para comparações curtas de até 3-4 "
        "colunas; para enumerações longas prefira listas. Não use "
        "cercas ``` para texto comum — apenas para código/JSON.\n"
        "6. v0.18.26 — o bloco 'wazuh' traz a LISTA POR HOST ('hosts'): "
        "cada item é [hostname, id_agente, status, ip, sistema_operacional, "
        "grupos, cpu, ram_gb, último_keepalive, portas_escuta, processos, "
        "pacotes]. Use-a para responder perguntas sobre hosts ESPECÍFICOS "
        "(nome, SO, IP, grupos, hardware) — não cite apenas agregados. Os "
        "3 últimos números são contadores do inventário sincronizado do "
        "Wazuh: quando forem maiores que zero, OS DADOS EXISTEM no banco "
        "— nunca diga que não há dados de portas/processos/pacotes.\n"
        "7. v0.18.26 — o bloco 'wazuh_detail' traz o DETALHE COMPLETO dos "
        "hosts citados na pergunta: interfaces (nome/MAC), portas TCP em "
        "escuta e UDP ('porta(processo)'), processos (pid, nome, usuário, "
        "comando) e pacotes (total + recentes). Use-o para responder "
        "sobre portas abertas, processos em execução, usuários e software "
        "instalado DE CADA HOST. O bloco 'recent_portscans' traz as "
        "PORTAS abertas reais das últimas varreduras do NetScope (listas "
        "tcp_ports/udp_ports, não só contagens). Perguntas sobre conversas "
        "anteriores usam o histórico de mensagens enviado junto.\n"
    )

def _extra_api_keys():

    import os
    primary = (os.getenv('GROQ_API_KEY') or '').strip()
    out = []
    sources = [os.getenv('GROQ_API_KEYS') or '']
    sources += [os.getenv(f'GROQ_API_KEY_{i}') or '' for i in (2, 3, 4)]
    for raw in sources:
        for k in str(raw).split(','):
            k = k.strip()
            if k and k != primary and k not in out:
                out.append(k)
    return out

def _provider_call(api_key, model, messages, timeout=45):

    import requests
    log = logging.getLogger('inventory.assistant')
    try:
        r = requests.post(
            _base_url() + '/chat/completions',
            headers={'Authorization': 'Bearer ' + api_key,
                     'Content-Type': 'application/json'},
            json={'model': model, 'messages': messages,
                  'temperature': 0.3, 'max_tokens': 1000},
            timeout=timeout,
        )
    except Exception as e:
        log.error("[Assistente IA] Falha de comunicação com %s: %s",
                  _base_url(), e)
        return {'ok': False, 'kind': 'connection_error',
                'detail': str(e), 'retry_after': 2.0}

    if r.status_code == 401:
        return {'ok': False, 'kind': 'invalid_api_key',
                'detail': None, 'retry_after': None}
    if r.status_code == 429:
        ra = None
        try:
            ra = float(r.headers.get('Retry-After') or r.headers.get('retry-after'))
        except (TypeError, ValueError):
            ra = None
        try:
            detail = (r.json() or {}).get('error', {}).get('message', '')
        except Exception:
            detail = ''
        return {'ok': False, 'kind': 'rate_limited',
                'detail': detail or None, 'retry_after': ra}
    if r.status_code == 404:
        try:
            detail = (r.json() or {}).get('error', {}).get('message', '')
        except Exception:
            detail = ''
        return {'ok': False, 'kind': 'model_not_found',
                'detail': detail or None, 'retry_after': None}
    if r.status_code != 200:
        try:
            detail = (r.json() or {}).get('error', {}).get('message', '')
        except Exception:
            detail = ''
        detail = detail or ('HTTP ' + str(r.status_code))
        log.error("[Assistente IA] Erro HTTP %s do provedor: %s",
                  r.status_code, detail)
        return {'ok': False, 'kind': 'api_error', 'detail': detail,
                'retry_after': 2.0}

    try:
        data = r.json()
        reply = (data.get('choices') or [{}])[0].get('message', {}).get('content', '')
    except Exception as e:
        return {'ok': False, 'kind': 'bad_response',
                'detail': str(e), 'retry_after': None}
    reply = (reply or '').strip()
    if not reply:
        return {'ok': False, 'kind': 'empty_response',
                'detail': None, 'retry_after': None}
    return {'ok': True, 'reply': reply, 'detail': None, 'retry_after': None}

def chat(message, history=None, lang='pt', username=None):

    cfg = get_settings()
    if not cfg['api_key']:
        return None, 'no_api_key', None
    if not (message or '').strip():
        return None, 'empty_message', None

    if username:
        hist = get_history(username, limit=MAX_HISTORY * 2)
    else:
        hist = [h for h in (history or []) if isinstance(h, dict)]
    messages = [{'role': 'system',
                 'content': build_system_prompt(lang, question=message)}]
    for h in hist[-MAX_HISTORY * 2:]:
        role = h.get('role') if isinstance(h, dict) else None
        content = (h.get('content') or '').strip() if isinstance(h, dict) else ''
        if role in ('user', 'assistant') and content:
            messages.append({'role': role, 'content': content[:HISTORY_CHARS]})
    messages.append({'role': 'user', 'content': message.strip()[:4000]})

    import time
    primary_model = cfg['model']
    attempts = []
    for _ in range(RATE_RETRIES + 1):
        attempts.append((cfg['api_key'], primary_model))
    for fb in FALLBACK_CHAIN:
        if fb and fb != primary_model:
            attempts.append((cfg['api_key'], fb))
    for extra in _extra_api_keys():
        attempts.append((extra, primary_model))

    last = None
    waited = 0.0
    log = logging.getLogger('inventory.assistant')
    for idx, (key, model) in enumerate(attempts):
        last = _provider_call(key, model, messages)
        if last.get('ok'):
            reply = last['reply']
            if username:
                add_history(username, 'user', message)
                add_history(username, 'assistant', reply)
            if idx:
                log.info("[Assistente IA] respondido pela tentativa %d "
                         "(modelo %s) após limite no primário.", idx + 1, model)
            return reply, None, None

        kind = last.get('kind')
        if kind in ('invalid_api_key', 'bad_response', 'empty_response'):
            break

        ra = last.get('retry_after')
        if idx < len(attempts) - 1 and kind in ('rate_limited', 'connection_error',
                                                'api_error', 'model_not_found'):
            pause = max(0.0, float(ra)) if ra else (RATE_BACKOFF_BASE * (2 ** (idx % RATE_RETRIES)))
            pause = min(pause, 8.0)
            if pause > 0:
                time.sleep(pause)
                waited += pause

    kind = (last or {}).get('kind') or 'api_error'
    detail = (last or {}).get('detail')
    if kind == 'rate_limited' and waited:
        detail = (detail + ' — ' if detail else '') + f'retry_after≈{int(waited)}s'
    return None, kind, detail
