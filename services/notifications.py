
from datetime import datetime, timedelta
import hashlib
import json
import threading

SETTINGS_KEY = 'notifications'
RULES_KEY = 'notif_rules'
STATE_KEY = 'notif_state'
STATE_MAX = 800
MAX_RULES = 20

DEFAULT_PREFS = {
    'enabled': True,
    'security': True,
    'asset': True,
    'compliance': True,
    'coverage_min': 80,
}

RULE_FIELDS = {
    'hostname': 'Nome/hostname',
    'ip': 'Endereço IP',
    'mac': 'MAC',
    'type': 'Tipo do dispositivo',
    'os': 'Sistema operacional',
    'user': 'Responsável',
    'department': 'Departamento',
    'status': 'Status',
    'open_ports': 'Portas TCP abertas',
}

RULE_OPS = {
    'contains': 'contém',
    'equals': 'igual a',
    'not_equals': 'diferente de',
    'starts_with': 'começa com',
    'ends_with': 'termina com',
}

RULE_SEVERITIES = ('info', 'warning', 'critical')

def _field_value(d, field):

    if field == 'open_ports':
        ports = d.get('open_ports') or []
        out = []
        for p in ports:
            try:
                out.append(int(p))
            except (TypeError, ValueError):
                pass
        return out
    if field == 'hostname':
        return str(d.get('hostname') or d.get('dns_name') or '')
    return str(d.get(field) or '')

def _rule_matches(d, rule):

    field = rule.get('field') or ''
    op = rule.get('op') or 'contains'
    value = str(rule.get('value') or '').strip()
    if field not in RULE_FIELDS or not value:
        return False

    if field == 'open_ports':
        try:
            port = int(float(value))
        except (TypeError, ValueError):
            return False
        ports = _field_value(d, field)
        if op in ('contains', 'equals'):
            return port in ports
        if op == 'not_equals':
            return port not in ports
        return False

    fval = _field_value(d, field)
    fl, vl = fval.strip().lower(), value.lower()
    if op == 'contains':
        return bool(fl) and vl in fl
    if op == 'equals':
        return fl == vl
    if op == 'not_equals':
        return fl != vl
    if op == 'starts_with':
        return bool(fl) and fl.startswith(vl)
    if op == 'ends_with':
        return bool(fl) and fl.endswith(vl)
    return False

RISKY_PORTS = {
    21: 'FTP', 23: 'Telnet', 139: 'NetBIOS', 445: 'SMB', 3389: 'RDP',
}

EOL_OS = [
    'WINDOWS XP', 'WINDOWS VISTA', 'WINDOWS 7', 'WINDOWS 8 ',
    'WINDOWS SERVER 2003', 'WINDOWS SERVER 2008', 'WINDOWS SERVER 2012',
    'UBUNTU 16.04', 'UBUNTU 18.04', 'CENTOS 7', 'CENTOS 6', 'DEBIAN 9',
    'DEBIAN 10', 'RED HAT ENTERPRISE LINUX 6', 'RHEL 6',
]

COOLDOWN_H = {
    'new_device': 20,
    'device_missing': 168,
    'ip_conflict': 20,
    'mac_conflict': 20,
    'risky_ports': 168,
    'agent_offline': 72,
    'eol_os': 720,
    'duplicates': 168,
    'topology_change': 20,
    'agent_coverage': 168,
    'undocumented': 168,
}

def get_prefs():
    out = dict(DEFAULT_PREFS)
    try:
        from models import SystemSetting
        row = SystemSetting.query.filter_by(key=SETTINGS_KEY).first()
        if row and isinstance(row.value, dict):
            out.update({k: v for k, v in row.value.items() if k in out})
    except Exception:
        pass
    return out

def save_prefs(prefs):
    from models import SystemSetting, db
    clean = {k: prefs[k] for k in DEFAULT_PREFS if k in prefs}
    row = SystemSetting.query.filter_by(key=SETTINGS_KEY).first()
    if row:
        row.value = clean
    else:
        db.session.add(SystemSetting(key=SETTINGS_KEY, value=clean))
    db.session.commit()
    return clean

def get_rules():

    try:
        from models import SystemSetting
        row = SystemSetting.query.filter_by(key=RULES_KEY).first()
        data = row.value if (row and isinstance(row.value, list)) else []
    except Exception:
        return []
    out = []
    for r in data:
        if not isinstance(r, dict):
            continue
        if not str(r.get('name') or '').strip():
            continue
        if (r.get('field') or '') not in RULE_FIELDS:
            continue
        if (r.get('op') or '') not in RULE_OPS:
            continue
        out.append(r)
    return out

def validate_rule(data, rules=None):

    import re as _re
    name = str((data or {}).get('name') or '').strip()[:80]
    field = str((data or {}).get('field') or '').strip()
    op = str((data or {}).get('op') or 'contains').strip()
    value = str((data or {}).get('value') or '').strip()[:160]
    severity = str((data or {}).get('severity') or 'warning').strip()
    enabled = bool((data or {}).get('enabled', True))
    try:
        cooldown = int(float((data or {}).get('cooldown_h', 24) or 24))
    except (TypeError, ValueError):
        cooldown = 24
    cooldown = max(1, min(720, cooldown))

    if not name:
        return None, 'missing_name'
    if not value:
        return None, 'missing_value'
    if field not in RULE_FIELDS:
        return None, 'bad_field'
    if op not in RULE_OPS:
        return None, 'bad_op'
    if severity not in RULE_SEVERITIES:
        severity = 'warning'
    if field == 'open_ports' and not _re.fullmatch(r'\d{1,5}', value):
        return None, 'bad_port'

    rid = str((data or {}).get('id') or '').strip()
    if rid:
        rules = rules if rules is not None else get_rules()
        if not any(str(r.get('id')) == rid for r in rules):
            return None, 'not_found'
    else:
        rid = ('r' + datetime.utcnow().strftime('%Y%m%d%H%M%S')
               + ('%x' % (datetime.utcnow().microsecond % 16)))
    return ({'id': rid, 'name': name, 'field': field, 'op': op,
             'value': value, 'severity': severity,
             'cooldown_h': cooldown, 'enabled': enabled}, None)

def upsert_rule(data):

    from models import SystemSetting, db
    rules = get_rules()
    rule, err = validate_rule(data, rules)
    if err:
        return None, err
    is_new = not str((data or {}).get('id') or '').strip()
    if is_new and len(rules) >= MAX_RULES:
        return None, 'too_many_rules'
    rules = [r for r in rules if str(r.get('id')) != rule['id']]
    rules.append(rule)
    row = SystemSetting.query.filter_by(key=RULES_KEY).first()
    if row:
        row.value = rules
    else:
        db.session.add(SystemSetting(key=RULES_KEY, value=rules))
    db.session.commit()
    return rule, None

def delete_rule(rule_id):

    from models import SystemSetting, db
    rules = get_rules()
    keep = [r for r in rules if str(r.get('id')) != str(rule_id)]
    if len(keep) == len(rules):
        return False, 'not_found'
    row = SystemSetting.query.filter_by(key=RULES_KEY).first()
    if row:
        row.value = keep
        db.session.commit()
    return True, None

_STATE_LOCK = threading.Lock()
_ROUND = {'state': None, 'active': None, 'seed': False, 'dirty': False}

def _fingerprint(params, fp=None):

    if fp is not None:
        return str(fp)[:120]
    try:
        raw = json.dumps(params or {}, sort_keys=True,
                         ensure_ascii=False, default=str)
    except Exception:
        raw = str(sorted((params or {}).items()))
    return hashlib.sha1(raw.encode('utf-8', 'replace')).hexdigest()[:24]

def _state_load():

    try:
        from models import SystemSetting
        row = SystemSetting.query.filter_by(key=STATE_KEY).first()
        if row and isinstance(row.value, dict):
            return dict(row.value)
    except Exception:
        pass
    return None

def _state_save(state, seed=False):

    try:
        from models import SystemSetting, db
        clean = {k: v for k, v in state.items() if isinstance(v, dict)}
        row = SystemSetting.query.filter_by(key=STATE_KEY).first()
        if row:
            row.value = clean
        else:
            db.session.add(SystemSetting(key=STATE_KEY, value=clean))
        db.session.commit()
    except Exception:
        try:
            from models import db as _db
            _db.session.rollback()
        except Exception:
            pass

def _emit(kind, category, severity, key, params, cooldown_h=None, fp=None):

    try:
        from models import Notification, db
        now = datetime.utcnow()
        sig = _fingerprint(params, fp)

        state = _ROUND.get('state')
        standalone = state is None
        if standalone:
            state = _state_load() or {}

        entry = dict(state.get(key) or {})
        prev_fp = str(entry.get('fp') or '')
        resolved = bool(entry.get('resolved'))
        emit_ts = None
        try:
            if entry.get('emit_ts'):
                emit_ts = datetime.fromisoformat(str(entry['emit_ts']))
        except (ValueError, TypeError):
            emit_ts = None

        if _ROUND.get('active') is not None:
            _ROUND['active'].add(key)

        if _ROUND.get('seed'):
            entry.update({'fp': sig, 'emit_ts': entry.get('emit_ts') or '',
                          'seen_ts': now.isoformat(), 'resolved': False})
            state[key] = entry
            _ROUND['dirty'] = True
            return False

        if prev_fp == sig and not resolved:
            entry['seen_ts'] = now.isoformat()
            state[key] = entry
            _ROUND['dirty'] = True
            if standalone:
                _state_save(state)
            return False

        existing = (Notification.query
                    .filter_by(key=key[:160])
                    .order_by(Notification.id.desc())
                    .first())
        if existing and not existing.read:
            existing.kind = kind
            existing.params = params or {}
            existing.category = category
            existing.severity = severity
            existing.created_at = now
            db.session.commit()
            entry.update({'fp': sig, 'emit_ts': now.isoformat(),
                          'seen_ts': now.isoformat(), 'resolved': False})
            state[key] = entry
            _ROUND['dirty'] = True
            if standalone:
                _state_save(state)
            return False

        cd = cooldown_h if cooldown_h else COOLDOWN_H.get(kind, 24)
        if emit_ts and (now - emit_ts).total_seconds() < cd * 3600:
            entry['seen_ts'] = now.isoformat()
            state[key] = entry
            _ROUND['dirty'] = True
            if standalone:
                _state_save(state)
            return False

        db.session.add(Notification(
            key=key[:160], kind=kind, params=params or {},
            category=category, severity=severity))
        db.session.commit()
        state[key] = {'fp': sig, 'emit_ts': now.isoformat(),
                      'seen_ts': now.isoformat(), 'resolved': False}
        _ROUND['dirty'] = True
        if standalone:
            _state_save(state)
        return True
    except Exception:
        try:
            from models import db as _db
            _db.session.rollback()
        except Exception:
            pass
        return False

def _dname(d):
    return (d.get('hostname') or d.get('dns_name')
            or d.get('ip') or d.get('mac') or '?')

def _mac_conflict_groups():

    groups = {}

    def _add(mac, ip, name=''):
        mac = (mac or '').strip().lower()
        ip = (ip or '').strip()
        if not mac or mac == '00:00:00:00:00:00' or not ip:
            return
        if ip in ('127.0.0.1', 'localhost', '::1', '0.0.0.0'):
            return
        g = groups.setdefault(mac, {'mac': mac, 'ips': [], 'names': []})
        if ip not in g['ips']:
            g['ips'].append(ip)
        if name and name not in g['names']:
            g['names'].append(name)

    try:
        from services.netscope_discovery import read_arp_table
        own_macs = set()
        try:
            from pathlib import Path as _Path
            net_dir = _Path('/sys/class/net')
            if net_dir.is_dir():
                for iface in net_dir.iterdir():
                    try:
                        own_macs.add(
                            (iface / 'address').read_text().strip().lower())
                    except (IOError, OSError):
                        pass
        except Exception:
            pass
        for ip, mac in (read_arp_table() or {}).items():
            if str(mac).lower() in own_macs:
                continue
            _add(mac, ip)
    except Exception:
        pass

    try:
        from models import HostInventory
        from services.netscope_wazuh_bridge import _extract_host_info
        for h in HostInventory.query.filter_by(is_legacy=False).all():
            info = _extract_host_info(h)
            for mac in info['macs']:
                _add(mac, info['agent_ip'], info['hostname'])
    except Exception:
        pass

    try:
        from services.netscope_core import store
        for grp in store.mac_conflicts() or []:
            for d in grp.get('devices', []):
                _add(grp.get('mac'), d.get('ip'), d.get('name') or '')
    except Exception:
        pass

    return [g for g in groups.values() if len(g['ips']) >= 2]

def _net_rules(prefs, today):
    created = {}
    try:
        from services.netscope_core import store
        act = store.active()
    except Exception:
        return created

    if prefs.get('asset', True):
        n_new = 0
        for d in act:
            fs = (d.get('first_seen') or '')[:10]
            if fs == today and (d.get('source') or '') != 'manual':
                if _emit('new_device', 'asset', 'info',
                         f"new_device:{d.get('uid') or d.get('mac')}",
                         {'name': _dname(d), 'ip': d.get('ip', ''),
                          'seen': fs}):
                    n_new += 1
        if n_new:
            created['new_device'] = n_new

        n_miss = 0
        limit = (datetime.utcnow() - timedelta(days=7)).strftime('%Y-%m-%d')
        for d in act:
            if not d.get('user'):
                continue
            ls = (d.get('last_seen') or '')[:10]
            if ls and ls < limit:
                if _emit('device_missing', 'asset', 'warning',
                         f"device_missing:{d.get('uid') or d.get('mac')}",
                         {'name': _dname(d), 'ip': d.get('ip', ''),
                          'days': '7+', 'last_seen': ls}):
                    n_miss += 1
        if n_miss:
            created['device_missing'] = n_miss

        try:
            from services.netscope_wazuh_bridge import duplicate_marks
            marks = duplicate_marks()
            if marks:
                total = len(marks)
                if _emit('duplicates', 'asset', 'info',
                         'duplicates',
                         {'n': str(total)},
                         fp=','.join(sorted(marks.keys()))):
                    created['duplicates'] = 1
        except Exception:
            pass

        try:
            from services.netscope_snapshots import get_instance
            snaps = get_instance().list_snapshots()
            if len(snaps) >= 2:
                cmp = get_instance().compare_snapshots(
                    snaps[1].get('snap_id'), snaps[0].get('snap_id'))
                if cmp:
                    a, r, ch = (len(cmp.get('added', [])),
                                len(cmp.get('removed', [])),
                                len(cmp.get('changed', [])))
                    if a or r or ch:
                        pair = '-'.join(sorted([snaps[0].get('snap_id', '')[:8],
                                                snaps[1].get('snap_id', '')[:8]]))
                        if _emit('topology_change', 'asset', 'info',
                                 f"topology_change:{pair}",
                                 {'added': str(a), 'removed': str(r),
                                  'changed': str(ch)}):
                            created['topology_change'] = 1
        except Exception:
            pass

    if prefs.get('security', True):
        try:
            conflicts = store.ip_conflicts()
            n = 0
            for grp in conflicts or []:
                ip = grp.get('ip', '') if isinstance(grp, dict) else ''
                devs = grp.get('devices') or [] if isinstance(grp, dict) else []
                names = [str(x.get('name') or '') for x in devs
                         if isinstance(x, dict)]
                if _emit('ip_conflict', 'security', 'warning',
                         f"ip_conflict:{ip}",
                         {'ip': ip, 'n': str(len(names)),
                          'names': ', '.join([x for x in names if x][:4])}):
                    n += 1
            if n:
                created['ip_conflict'] = n
        except Exception:
            pass

        n_m = 0
        try:
            for grp in _mac_conflict_groups():
                n_ips = len(grp['ips'])
                disp = ', '.join(
                    f"{ip}{(' (' + n + ')') if n else ''}"
                    for ip, n in zip(
                        grp['ips'][:4],
                        (grp.get('names') or [''] * 4)[:4]))
                if _emit('mac_conflict', 'security', 'warning',
                         f"mac_conflict:{grp['mac']}",
                         {'mac': grp['mac'], 'n': str(n_ips),
                          'ips': disp}):
                    n_m += 1
            if n_m:
                created['mac_conflict'] = n_m
        except Exception:
            pass

        n_r = 0
        for d in act:
            ports = d.get('open_ports') or []
            risky = sorted({p for p in ports if p in RISKY_PORTS})
            if not risky:
                continue
            labels = ', '.join(f"{RISKY_PORTS[p]} {p}" for p in risky)
            portsig = '-'.join(str(p) for p in risky)
            if _emit('risky_ports', 'security',
                     'critical' if set(risky) & {23, 445, 3389} else 'warning',
                     f"risky_ports:{d.get('uid') or d.get('mac')}:{portsig}",
                     {'name': _dname(d), 'ip': d.get('ip', ''),
                      'ports': labels}):
                n_r += 1
        if n_r:
            created['risky_ports'] = n_r

        n_e = 0
        for d in act:
            os_name = (d.get('os') or '').upper()
            if not os_name:
                continue
            hit = next((e for e in EOL_OS if e in os_name), None)
            if hit:
                if _emit('eol_os', 'security', 'critical',
                         f"eol_os:{d.get('uid') or d.get('mac')}",
                         {'name': _dname(d), 'os': (d.get('os') or '').strip()}):
                    n_e += 1
        if n_e:
            created['eol_os'] = n_e

    if prefs.get('compliance', True):
        total = len(act)
        if total:
            exempt = sum(1 for d in act
                         if not d.get('has_agent') and d.get('agent_exempt'))
            with_agent = sum(1 for d in act if d.get('has_agent'))
            supported = total - exempt
            coverage = round(100 * with_agent / supported) if supported else 100
            minimum = int(prefs.get('coverage_min', 80) or 80)
            if coverage < minimum:
                if _emit('agent_coverage', 'compliance', 'warning',
                         'agent_coverage',
                         {'pct': str(coverage), 'min': str(minimum),
                          'without': str(supported - with_agent)}):
                    created['agent_coverage'] = 1
            undoc = sum(1 for d in act if not d.get('user'))
            if total and (100 * undoc / total) >= 30:
                if _emit('undocumented', 'compliance', 'info',
                         'undocumented',
                         {'n': str(undoc), 'total': str(total),
                          'pct': str(round(100 * undoc / total))}):
                    created['undocumented'] = 1
    return created

def _wazuh_rules(prefs, today):
    created = 0
    if not prefs.get('security', True):
        return created
    try:
        from models import HostInventory
        hosts = HostInventory.query.filter_by(is_legacy=False).all()
    except Exception:
        return 0
    for h in hosts:
        ai = (h.data or {}).get('agent_info', {}) or {}
        status = (ai.get('status') or '').strip()
        if not ai.get('id') or status == 'active':
            continue
        if _emit('agent_offline', 'security', 'warning',
                 f"agent_offline:{ai.get('id')}",
                 {'name': (ai.get('name') or h.hostname or '?'),
                  'status': status or '?'}):
            created += 1
    return created

def _custom_rules(today):

    created = {}
    rules = [r for r in get_rules() if r.get('enabled', True)]
    if not rules:
        return created
    try:
        from services.netscope_core import store
        act = store.active()
    except Exception:
        return created

    for rule in rules:
        rid = str(rule.get('id') or '')
        if not rid:
            continue
        n = 0
        for d in act:
            if not _rule_matches(d, rule):
                continue
            if _emit('custom', 'system', rule.get('severity') or 'warning',
                     f"custom:{rid}:{d.get('uid') or d.get('mac') or d.get('ip', '')}",
                     {'rule': rule.get('name') or rid,
                      'name': _dname(d), 'ip': d.get('ip', ''),
                      'field': rule.get('field') or '',
                      'op': rule.get('op') or 'contains',
                      'value': str(rule.get('value') or '')},
                     cooldown_h=int(rule.get('cooldown_h') or 24)):
                n += 1
        if n:
            created[rid] = n
    return created

def evaluate_all(app=None, logger=None):

    prefs = get_prefs()
    out = {'created': 0, 'rules': {}, 'enabled': bool(prefs.get('enabled', True))}
    if not out['enabled']:
        return out

    with _STATE_LOCK:
        today = datetime.utcnow().strftime('%Y-%m-%d')
        state = _state_load()
        seed = state is None
        if seed:
            state = {}
        _ROUND['state'] = state
        _ROUND['active'] = set()
        _ROUND['seed'] = seed
        _ROUND['dirty'] = False

        try:
            rules = {}
            try:
                rules.update(_net_rules(prefs, today))
            except Exception as e:
                if logger:
                    logger.warning(f"[Notificações] regras NetScope falharam: {e}")
            try:
                n = _wazuh_rules(prefs, today)
                if n:
                    rules['agent_offline'] = n
            except Exception as e:
                if logger:
                    logger.warning(f"[Notificações] regras Wazuh falharam: {e}")
            try:
                custom = _custom_rules(today)
                if custom:
                    rules['custom'] = sum(custom.values())
            except Exception as e:
                if logger:
                    logger.warning(f"[Notificações] regras personalizadas falharam: {e}")
            out['rules'] = rules
            out['created'] = sum(rules.values())

            active = _ROUND['active'] or set()
            for k, entry in state.items():
                if k not in active and isinstance(entry, dict) \
                        and not entry.get('resolved'):
                    entry['resolved'] = True
                    _ROUND['dirty'] = True

            if len(state) > STATE_MAX:
                keep = sorted(state.items(),
                              key=lambda kv: str((kv[1] or {}).get('seen_ts') or ''),
                              reverse=True)[:STATE_MAX]
                state.clear()
                state.update(dict(keep))
                _ROUND['dirty'] = True
            if _ROUND['dirty'] or seed:
                _state_save(state)
                if logger and seed:
                    logger.info(
                        "[Notificações] linha de base do registro de estado "
                        f"gravada ({len(state)} evento(s) conhecido(s)) — "
                        "eventos já visíveis NÃO serão recriados.")
        finally:
            _ROUND['state'] = None
            _ROUND['active'] = None
            _ROUND['seed'] = False
            _ROUND['dirty'] = False
    return out

KIND_I18N = {
    'new_device': 'Novo dispositivo detectado: {name} ({ip})',
    'device_missing': 'Dispositivo ausente há {days} dias: {name} ({ip})',
    'ip_conflict': 'Conflito de IP: {ip} usado por {n} dispositivos ({names})',
    'mac_conflict': 'Conflito de MAC: {mac} está em {n} IPs ao mesmo tempo ({ips})',
    'risky_ports': '{name} expõe portas de risco: {ports}',
    'agent_offline': 'Agente Wazuh offline: {name} (status: {status})',
    'eol_os': 'Sistema sem suporte (EOL): {name} — {os}',
    'duplicates': '{n} dispositivos duplicados detectados no NetScope',
    'topology_change': 'Mudança na topologia: {added} novos, {removed} removidos, {changed} alterados',
    'agent_coverage': 'Cobertura de agentes abaixo do mínimo: {pct}% (mínimo {min}%)',
    'undocumented': '{n} de {total} dispositivos sem responsável documentado ({pct}%)',
    'custom': 'Regra "{rule}" correspondeu: {name} ({ip}) — {detail}',
}

def _fmt(kind, params):

    from core.i18n import translate
    if kind == 'custom':
        params = dict(params or {})
        field = str(params.get('field') or '')
        op = str(params.get('op') or 'contains')
        value = str(params.get('value') or '')
        field_label = translate(RULE_FIELDS.get(field, field))
        op_label = translate(RULE_OPS.get(op, op))
        params['detail'] = f"{field_label} {op_label} \"{value}\""
    tmpl = translate(KIND_I18N.get(kind, kind))
    try:
        return tmpl.format(**(params or {}))
    except (KeyError, IndexError, ValueError):
        text = tmpl
        for k, v in (params or {}).items():
            text = text.replace('{' + str(k) + '}', str(v))
        return text

CATEGORY_I18N = {
    'security': 'Segurança',
    'asset': 'Parque',
    'compliance': 'Compliance',
    'system': 'Sistema',
}

def list_notifications(limit=60, unread_only=False):

    from models import Notification
    from core.i18n import translate
    q = Notification.query
    if unread_only:
        q = q.filter_by(read=False)
    rows = (q.order_by(Notification.id.desc()).limit(limit).all())
    items = []
    for n in rows:
        params = n.params if isinstance(n.params, dict) else {}
        items.append({
            'id': n.id,
            'kind': n.kind,
            'category': n.category,
            'category_label': translate(CATEGORY_I18N.get(n.category, n.category)),
            'severity': n.severity,
            'message': _fmt(n.kind, params),
            'created_at': (n.created_at or datetime.utcnow()).isoformat(),
            'read': bool(n.read),
        })
    unread = Notification.query.filter_by(read=False).count()
    return items, unread
