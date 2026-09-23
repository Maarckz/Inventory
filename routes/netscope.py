
import re
from datetime import datetime
from functools import wraps

from flask import (
    Blueprint, jsonify, redirect, render_template, request, session, Response,
    url_for,
)

from services.netscope_core import store, load_config, save_config, dev_key
from services.netscope_engine import scan_status, start_scan, scan_tcp_ports
from services.netscope_export import export_assets_csv, export_full_json
from services.netscope_portscan import job_status, start_portscan
from services.netscope_snapshots import get_instance
from services.netscope_switches import get_switches_with_ports, update_switch_config
from services.netscope_wazuh_bridge import sync_from_inventory

ns_bp = Blueprint('netscope', __name__, url_prefix='/netscope')

def ns_login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session:
            if request.path.startswith('/netscope/api/'):
                return jsonify({'error': 'Não autenticado',
                                'session_expired': True}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def _wake_discovery_loops():

    try:
        from services.netscope_discovery import wake_monitor
        wake_monitor()
    except Exception:
        pass
    try:
        from services.netscope_engine import wake_auto_scan
        wake_auto_scan()
    except Exception:
        pass

@ns_bp.route('')
@ns_bp.route('/')
@ns_login_required
def page():
    from utils.language import LANGUAGES
    lang = session.get('language', 'pt')
    ns_i18n = dict(LANGUAGES.get('pt', {}))
    ns_i18n.update(LANGUAGES.get(lang, {}))
    return render_template('netscope.html', ns_i18n=ns_i18n)

@ns_bp.route('/api/devices')
@ns_login_required
def api_devices():
    devs = store.active()
    try:
        from services.netscope_wazuh_bridge import duplicate_marks
        marks = duplicate_marks()
        if marks:
            for d in devs:
                reasons = marks.get(dev_key(d)) or []
                if reasons:
                    d['dup'] = ','.join(reasons)
    except Exception:
        pass
    return jsonify({'devices': devs})

@ns_bp.route('/api/devices/bulk-delete', methods=['POST'])
@ns_login_required
def api_devices_bulk_delete():

    body = request.get_json(silent=True) or {}
    uids = body.get('uids')
    if not isinstance(uids, list) or not uids:
        return jsonify({'error': 'uids obrigatórios'}), 400
    deleted, skipped = 0, 0
    for u in uids[:500]:
        try:
            ok, _code = store.soft_delete(str(u))
            if ok:
                deleted += 1
            else:
                skipped += 1
        except Exception:
            skipped += 1
    return jsonify({'ok': True, 'deleted': deleted, 'skipped': skipped})

@ns_bp.route('/api/stats')
@ns_login_required
def api_stats():
    stats = store.stats()
    try:
        from services.netscope_wazuh_bridge import find_duplicates
        stats['duplicates'] = sum(len(g['uids']) for g in find_duplicates())
    except Exception:
        stats['duplicates'] = 0
    try:
        from models import HostInventory
        hosts = HostInventory.query.filter_by(is_legacy=False).all()
        stats['wazuh_total'] = len(hosts)
        stats['wazuh_active'] = sum(
            1 for h in hosts
            if (h.data or {}).get('agent_info', {}).get('status') == 'active'
        )
        stats['wazuh_synced_at'] = max(
            (h.last_updated.isoformat() for h in hosts if h.last_updated), default=None
        )
    except Exception:
        stats['wazuh_total'] = 0
        stats['wazuh_active'] = 0
        stats['wazuh_synced_at'] = None
    return jsonify(stats)

@ns_bp.route('/api/conflicts')
@ns_login_required
def api_conflicts():

    return jsonify({'conflicts': store.ip_conflicts()})

@ns_bp.route('/api/config')
@ns_login_required
def api_config():
    return jsonify(load_config())

@ns_bp.route('/api/subnets')
@ns_login_required
def api_subnets():
    cfg = load_config()
    return jsonify({'subnets': cfg.get('networks', [])})

import ipaddress

def _normalize_subnet(raw):

    value = (raw or '').strip()
    if not value:
        return None, 'Subnet obrigatória'

    if '/' not in value:
        if len(value.split('.')) == 3:
            try:
                ipaddress.IPv4Network(value + '.0/24')
                return value, None
            except ValueError:
                return None, 'Prefixo de rede inválido'
        try:
            ip = ipaddress.IPv4Address(value)
            return str(ip).rsplit('.', 1)[0], None
        except ValueError:
            return None, 'Endereço IPv4 inválido'

    try:
        net = ipaddress.IPv4Network(value, strict=False)
    except ValueError:
        return None, 'CIDR inválido — use o formato 192.168.1.0/24'
    if net.prefixlen != 24:
        return None, 'Somente redes /24 são suportadas na varredura'
    return str(net.network_address).rsplit('.', 1)[0], None

@ns_bp.route('/api/subnets', methods=['POST'])
@ns_login_required
def api_subnets_add():

    body = request.get_json(silent=True) or {}
    subnet, err = _normalize_subnet(body.get('subnet'))
    if err:
        return jsonify({'error': err}), 400

    gateway = (body.get('gateway') or '').strip()
    if gateway:
        try:
            ipaddress.IPv4Address(gateway)
        except ValueError:
            return jsonify({'error': 'Gateway inválido'}), 400
    else:
        gateway = subnet + '.1'

    cfg = load_config()
    nets = cfg.get('networks', [])
    if any(n['subnet'] == subnet for n in nets):
        return jsonify({'error': f'Rede {subnet}.0/24 já configurada'}), 409
    nets.append({'subnet': subnet, 'gateway': gateway})
    cfg['networks'] = nets
    save_config(cfg)
    _wake_discovery_loops()
    return jsonify({'ok': True, 'subnet': subnet, 'gateway': gateway})

@ns_bp.route('/api/subnets', methods=['PATCH'])
@ns_login_required
def api_subnets_edit():

    body = request.get_json(silent=True) or {}
    original = (body.get('original') or '').strip()
    if not original:
        return jsonify({'error': 'Rede original obrigatória'}), 400
    subnet, err = _normalize_subnet(body.get('subnet'))
    if err:
        return jsonify({'error': err}), 400

    gateway = (body.get('gateway') or '').strip()
    if gateway:
        try:
            ipaddress.IPv4Address(gateway)
        except ValueError:
            return jsonify({'error': 'Gateway inválido'}), 400
    else:
        gateway = subnet + '.1'

    cfg = load_config()
    nets = cfg.get('networks', [])
    idx = next((i for i, n in enumerate(nets)
                if n.get('subnet') == original), None)
    if idx is None:
        return jsonify({'error': f'Rede {original} não encontrada'}), 404
    if any(n.get('subnet') == subnet for i, n in enumerate(nets) if i != idx):
        return jsonify({'error': f'Rede {subnet}.0/24 já configurada'}), 409
    nets[idx] = {'subnet': subnet, 'gateway': gateway}
    cfg['networks'] = nets
    save_config(cfg)
    _wake_discovery_loops()
    return jsonify({'ok': True, 'subnet': subnet, 'gateway': gateway})

@ns_bp.route('/api/subnets', methods=['DELETE'])
@ns_login_required
def api_subnets_del():
    body = request.get_json(silent=True) or {}
    subnet = (body.get('subnet') or '').strip()
    if not subnet:
        return jsonify({'error': 'Subnet obrigatória'}), 400
    cfg = load_config()
    cfg['networks'] = [n for n in cfg.get('networks', []) if n['subnet'] != subnet]
    save_config(cfg)
    _wake_discovery_loops()
    return jsonify({'ok': True})

@ns_bp.route('/api/trash')
@ns_login_required
def api_trash():
    items = store.trashed()
    for d in items:
        d['deleted_at_fmt'] = ''
        if d.get('deleted_at'):
            try:
                dt = datetime.fromisoformat(d['deleted_at'])
                d['deleted_at_fmt'] = dt.strftime('%d/%m %H:%M')
            except (ValueError, TypeError):
                pass
        if d.get('merged_into'):
            s = store.find(d['merged_into'], include_deleted=True)
            d['merged_into_name'] = (s.get('hostname') or s.get('ip')
                                     or d['merged_into']) if s else d['merged_into']
        else:
            d['merged_into_name'] = ''
    return jsonify({'devices': items})

@ns_bp.route('/api/trash/<path:mac>/restore', methods=['POST'])
@ns_login_required
def api_trash_restore(mac):
    try:
        ok, code = store.restore(mac)
    except Exception as e:
        try:
            from flask import current_app
            current_app.logger.error(f"[NetScope] restore falhou para {mac}: {e!r}")
        except Exception:
            pass
        return jsonify({'error': 'Falha ao restaurar dispositivo',
                        'detail': str(e)[:300]}), 500
    if not ok:
        return jsonify({'error': 'Não encontrado na lixeira'}), code
    return jsonify({'ok': True})

@ns_bp.route('/api/trash/<path:mac>', methods=['DELETE'])
@ns_login_required
def api_trash_delete(mac):
    try:
        ok, code = store.permanent_delete(mac)
    except Exception as e:
        try:
            from flask import current_app
            current_app.logger.error(f"[NetScope] permanent_delete falhou para {mac}: {e!r}")
        except Exception:
            pass
        return jsonify({'error': 'Falha ao excluir permanentemente',
                        'detail': str(e)[:300]}), 500
    if not ok:
        return jsonify({'error': 'Não encontrado'}), code
    return jsonify({'ok': True})

@ns_bp.route('/api/devices', methods=['POST'])
@ns_login_required
def api_device_create():
    body = request.get_json(silent=True) or {}
    cfg = load_config()
    dev, code, err = store.create_device(body, cfg)
    if err:
        return jsonify({'error': err}), code
    return jsonify(dev), code

@ns_bp.route('/api/devices/<path:mac>', methods=['PUT'])
@ns_login_required
def api_device_update(mac):
    body = request.get_json(silent=True) or {}
    dev, code, err = store.update_device(mac, body)
    if err:
        return jsonify({'error': err}), code
    return jsonify(dev)

@ns_bp.route('/api/devices/<path:mac>', methods=['DELETE'])
@ns_login_required
def api_device_delete(mac):
    try:
        ok, code = store.soft_delete(mac)
    except Exception as e:
        # soft_delete() calls _flush() which re-raises DB errors. Without
        # this catch the global 500 handler kicks in and (previously)
        # returned HTML, breaking the frontend's r.json() call.
        try:
            from flask import current_app
            current_app.logger.error(f"[NetScope] soft_delete falhou para {mac}: {e!r}")
        except Exception:
            pass
        return jsonify({'error': 'Falha ao excluir dispositivo',
                        'detail': str(e)[:300]}), 500
    if not ok:
        return jsonify({'error': 'Não encontrado'}), code
    return jsonify({'ok': True})

@ns_bp.route('/api/devices/<path:mac>/ping', methods=['POST'])
@ns_login_required
def api_device_ping(mac):
    import subprocess
    dev = store.find(mac)
    if not dev:
        return jsonify({'error': 'Não encontrado'}), 404
    try:
        r = subprocess.run(
            ['ping', '-c', '3', '-W', '1', dev['ip']],
            capture_output=True, text=True, timeout=10
        )
        rm = re.search(r'rtt min/avg/max/mdev = [\d.]+/([\d.]+)/', r.stdout)
        avg_rtt = round(float(rm.group(1)), 1) if rm else None
        ttl_m = re.search(r'ttl=(\d+)', r.stdout, re.IGNORECASE)
        ttl = int(ttl_m.group(1)) if ttl_m else None
        dev['status'] = 'online' if r.returncode == 0 else 'offline'
        dev['last_seen'] = datetime.now().isoformat()
        if avg_rtt is not None:
            dev['avg_rtt'] = avg_rtt
        if ttl is not None:
            dev['ttl'] = ttl
        with store._lock:
            store._flush()
        return jsonify({'reachable': r.returncode == 0, 'avg_rtt': avg_rtt, 'ttl': ttl})
    except subprocess.TimeoutExpired:
        return jsonify({'reachable': False, 'avg_rtt': None, 'ttl': None})

@ns_bp.route('/api/devices/<path:mac>/ports', methods=['POST'])
@ns_login_required
def api_device_ports(mac):
    dev = store.find(mac)
    if not dev:
        return jsonify({'error': 'Não encontrado'}), 404
    cfg = load_config()
    port_map = cfg.get('ports', {})
    port_timeout = cfg.get('port_timeout', 0.3)
    open_ports = scan_tcp_ports(dev['ip'], port_map, port_timeout)
    dev['open_ports'] = open_ports
    with store._lock:
        store._flush()
    return jsonify({'ports': open_ports, 'names': port_map})

@ns_bp.route('/api/devices/<path:mac>/portscan', methods=['POST'])
@ns_login_required
def api_device_portscan(mac):
    from flask import current_app
    dev = store.find(mac)
    if not dev:
        return jsonify({'error': 'Não encontrado'}), 404
    ok, payload, code = start_portscan(current_app._get_current_object(), mac)
    return jsonify(payload), code

@ns_bp.route('/api/portscan/status')
@ns_login_required
def api_portscan_status():
    return jsonify(job_status())

@ns_bp.route('/api/links', methods=['POST'])
@ns_login_required
def api_link_create():
    body = request.get_json(silent=True) or {}
    child = (body.get('child') or '').strip().lower()
    parent = (body.get('parent') or '').strip().lower()
    if not child or not parent:
        return jsonify({'error': 'child e parent obrigatórios'}), 400
    ok, code, err = store.create_link(child, parent)
    if err:
        return jsonify({'error': err}), code
    return jsonify({'ok': True})

@ns_bp.route('/api/links', methods=['DELETE'])
@ns_login_required
def api_link_delete():
    body = request.get_json(silent=True) or {}
    mac = (body.get('mac') or '').strip().lower()
    try:
        ok, code = store.remove_link(mac)
    except Exception as e:
        return jsonify({'error': 'Falha ao desassociar',
                        'detail': str(e)[:300]}), 500
    if not ok:
        return jsonify({'error': 'Não encontrado'}), code
    return jsonify({'ok': True})

@ns_bp.route('/api/infer', methods=['POST'])
@ns_login_required
def api_infer():
    cfg = load_config()
    changed = store.infer_links(cfg)
    return jsonify({'changed': changed})

@ns_bp.route('/api/scan', methods=['POST'])
@ns_login_required
def api_scan():
    body = request.get_json(silent=True) or {}
    auto_snap = body.get('auto_snapshot', False) if isinstance(body, dict) else False
    ok, payload, code = start_scan(auto_snapshot=auto_snap)
    return jsonify(payload), code

@ns_bp.route('/api/scan/status')
@ns_login_required
def api_scan_status():
    return jsonify(scan_status())

@ns_bp.route('/api/switches')
@ns_login_required
def api_switches():
    return jsonify({'switches': get_switches_with_ports()})

@ns_bp.route('/api/switches/<path:mac>', methods=['POST'])
@ns_login_required
def api_switch_update(mac):
    switch_mac = mac.lower()
    body = request.get_json(silent=True) or {}
    port_count = body.get('port_count')
    ports = body.get('ports')
    if port_count is None and ports is None:
        return jsonify({'error': 'Nada para atualizar'}), 400
    sw = update_switch_config(switch_mac, port_count, ports)
    return jsonify({'ok': True, 'switch': sw})

@ns_bp.route('/api/snapshots')
@ns_login_required
def api_snapshots_list():
    return jsonify({'snapshots': get_instance().list_snapshots()})

@ns_bp.route('/api/snapshots', methods=['POST'])
@ns_login_required
def api_snapshot_create():
    body = request.get_json(silent=True) or {}
    label = (body.get('label') or '').strip()
    notes = (body.get('notes') or '').strip()
    snap = get_instance().create_snapshot(label, notes, auto=False)
    return jsonify(snap), 201

@ns_bp.route('/api/snapshots/<path:snap_id>')
@ns_login_required
def api_snapshot_get(snap_id):
    snap = get_instance().load_snapshot(snap_id)
    if not snap:
        return jsonify({'error': 'Snapshot não encontrado'}), 404
    return jsonify(snap)

@ns_bp.route('/api/snapshots/<path:snap_id>', methods=['DELETE'])
@ns_login_required
def api_snapshot_delete(snap_id):
    try:
        ok = get_instance().delete_snapshot(snap_id)
    except Exception as e:
        return jsonify({'error': 'Falha ao excluir snapshot',
                        'detail': str(e)[:300]}), 500
    if not ok:
        return jsonify({'error': 'Snapshot não encontrado'}), 404
    return jsonify({'ok': True})

@ns_bp.route('/api/snapshots/<path:a>/compare/<path:b>')
@ns_login_required
def api_snapshot_compare(a, b):
    cmp = get_instance().compare_snapshots(a, b)
    if not cmp:
        return jsonify({'error': 'Snapshots não encontrados'}), 404
    return jsonify(cmp)

@ns_bp.route('/api/export/csv')
@ns_login_required
def api_export_csv():
    csv_data = export_assets_csv()
    filename = f'netscope_assets_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    return Response(
        csv_data,
        mimetype='text/csv; charset=utf-8',
        headers={'Content-Disposition': f'attachment; filename="{filename}"'}
    )

@ns_bp.route('/api/export/json')
@ns_login_required
def api_export_json():
    import json
    data = export_full_json()
    filename = f'netscope_full_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
    return Response(
        json.dumps(data, indent=2, default=str),
        mimetype='application/json',
        headers={'Content-Disposition': f'attachment; filename="{filename}"'}
    )

@ns_bp.route('/api/wazuh_sync', methods=['POST'])
@ns_login_required
def api_wazuh_sync():

    from flask import current_app
    try:
        stats = sync_from_inventory(current_app._get_current_object())
        return jsonify({'ok': True, **stats})
    except Exception as e:
        current_app.logger.error(f"[NetScope] Erro na sincronização Wazuh: {e}")
        return jsonify({'ok': False, 'error': str(e)}), 500

@ns_bp.route('/api/wazuh_agents')
@ns_login_required
def api_wazuh_agents():

    try:
        from models import HostInventory
        hosts = HostInventory.query.filter_by(is_legacy=False).order_by(HostInventory.hostname).all()
    except Exception as e:
        return jsonify({'error': str(e)}), 500

    agents = []
    for h in hosts:
        data = h.data or {}
        ai = data.get('agent_info', {}) or {}
        inv = data.get('inventory', {}) or {}
        macs = [nif.get('mac', '').lower() for nif in inv.get('netiface', []) or []
                if nif.get('mac') and nif.get('mac') not in ('N/A', '00:00:00:00:00:00')]
        ip = ai.get('ip', '')
        in_netscope = any(store.find(m) for m in macs) or (bool(ip) and store.find_by_ip(ip) is not None)
        agents.append({
            'hostname': h.hostname,
            'agent_id': ai.get('id', ''),
            'ip': ip,
            'mac': macs[0] if macs else '',
            'status': ai.get('status', ''),
            'last_keepalive': ai.get('lastKeepAlive', ''),
            'groups': data.get('groups') or ai.get('group') or [],
            'in_netscope': in_netscope,
        })
    return jsonify({'agents': agents})

import re
from datetime import datetime
from functools import wraps

from flask import (
    Blueprint, jsonify, redirect, render_template, request, session, Response,
    url_for,
)

from services.netscope_core import store, load_config, save_config, dev_key
from services.netscope_engine import scan_status, start_scan, scan_tcp_ports
from services.netscope_export import export_assets_csv, export_full_json
from services.netscope_portscan import job_status, start_portscan
from services.netscope_snapshots import get_instance
from services.netscope_switches import get_switches_with_ports, update_switch_config
from services.netscope_wazuh_bridge import sync_from_inventory

ns_bp = Blueprint('netscope', __name__, url_prefix='/netscope')

def ns_login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session:
            if request.path.startswith('/netscope/api/'):
                return jsonify({'error': 'Não autenticado',
                                'session_expired': True}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def _wake_discovery_loops():

    try:
        from services.netscope_discovery import wake_monitor
        wake_monitor()
    except Exception:
        pass
    try:
        from services.netscope_engine import wake_auto_scan
        wake_auto_scan()
    except Exception:
        pass

@ns_bp.route('')
@ns_bp.route('/')
@ns_login_required
def page():
    from utils.language import LANGUAGES
    lang = session.get('language', 'pt')
    ns_i18n = dict(LANGUAGES.get('pt', {}))
    ns_i18n.update(LANGUAGES.get(lang, {}))
    return render_template('netscope.html', ns_i18n=ns_i18n)

@ns_bp.route('/api/devices')
@ns_login_required
def api_devices():
    devs = store.active()
    try:
        from services.netscope_wazuh_bridge import duplicate_marks
        marks = duplicate_marks()
        if marks:
            for d in devs:
                reasons = marks.get(dev_key(d)) or []
                if reasons:
                    d['dup'] = ','.join(reasons)
    except Exception:
        pass
    return jsonify({'devices': devs})

@ns_bp.route('/api/devices/bulk-delete', methods=['POST'])
@ns_login_required
def api_devices_bulk_delete():

    body = request.get_json(silent=True) or {}
    uids = body.get('uids')
    if not isinstance(uids, list) or not uids:
        return jsonify({'error': 'uids obrigatórios'}), 400
    deleted, skipped = 0, 0
    for u in uids[:500]:
        try:
            ok, _code = store.soft_delete(str(u))
            if ok:
                deleted += 1
            else:
                skipped += 1
        except Exception:
            skipped += 1
    return jsonify({'ok': True, 'deleted': deleted, 'skipped': skipped})

@ns_bp.route('/api/stats')
@ns_login_required
def api_stats():
    stats = store.stats()
    try:
        from services.netscope_wazuh_bridge import find_duplicates
        stats['duplicates'] = sum(len(g['uids']) for g in find_duplicates())
    except Exception:
        stats['duplicates'] = 0
    try:
        from models import HostInventory
        hosts = HostInventory.query.filter_by(is_legacy=False).all()
        stats['wazuh_total'] = len(hosts)
        stats['wazuh_active'] = sum(
            1 for h in hosts
            if (h.data or {}).get('agent_info', {}).get('status') == 'active'
        )
        stats['wazuh_synced_at'] = max(
            (h.last_updated.isoformat() for h in hosts if h.last_updated), default=None
        )
    except Exception:
        stats['wazuh_total'] = 0
        stats['wazuh_active'] = 0
        stats['wazuh_synced_at'] = None
    return jsonify(stats)

@ns_bp.route('/api/conflicts')
@ns_login_required
def api_conflicts():

    return jsonify({'conflicts': store.ip_conflicts()})

@ns_bp.route('/api/config')
@ns_login_required
def api_config():
    return jsonify(load_config())

@ns_bp.route('/api/subnets')
@ns_login_required
def api_subnets():
    cfg = load_config()
    return jsonify({'subnets': cfg.get('networks', [])})

import ipaddress

def _normalize_subnet(raw):

    value = (raw or '').strip()
    if not value:
        return None, 'Subnet obrigatória'

    if '/' not in value:
        if len(value.split('.')) == 3:
            try:
                ipaddress.IPv4Network(value + '.0/24')
                return value, None
            except ValueError:
                return None, 'Prefixo de rede inválido'
        try:
            ip = ipaddress.IPv4Address(value)
            return str(ip).rsplit('.', 1)[0], None
        except ValueError:
            return None, 'Endereço IPv4 inválido'

    try:
        net = ipaddress.IPv4Network(value, strict=False)
    except ValueError:
        return None, 'CIDR inválido — use o formato 192.168.1.0/24'
    if net.prefixlen != 24:
        return None, 'Somente redes /24 são suportadas na varredura'
    return str(net.network_address).rsplit('.', 1)[0], None

@ns_bp.route('/api/subnets', methods=['POST'])
@ns_login_required
def api_subnets_add():

    body = request.get_json(silent=True) or {}
    subnet, err = _normalize_subnet(body.get('subnet'))
    if err:
        return jsonify({'error': err}), 400

    gateway = (body.get('gateway') or '').strip()
    if gateway:
        try:
            ipaddress.IPv4Address(gateway)
        except ValueError:
            return jsonify({'error': 'Gateway inválido'}), 400
    else:
        gateway = subnet + '.1'

    cfg = load_config()
    nets = cfg.get('networks', [])
    if any(n['subnet'] == subnet for n in nets):
        return jsonify({'error': f'Rede {subnet}.0/24 já configurada'}), 409
    nets.append({'subnet': subnet, 'gateway': gateway})
    cfg['networks'] = nets
    save_config(cfg)
    _wake_discovery_loops()
    return jsonify({'ok': True, 'subnet': subnet, 'gateway': gateway})

@ns_bp.route('/api/subnets', methods=['PATCH'])
@ns_login_required
def api_subnets_edit():

    body = request.get_json(silent=True) or {}
    original = (body.get('original') or '').strip()
    if not original:
        return jsonify({'error': 'Rede original obrigatória'}), 400
    subnet, err = _normalize_subnet(body.get('subnet'))
    if err:
        return jsonify({'error': err}), 400

    gateway = (body.get('gateway') or '').strip()
    if gateway:
        try:
            ipaddress.IPv4Address(gateway)
        except ValueError:
            return jsonify({'error': 'Gateway inválido'}), 400
    else:
        gateway = subnet + '.1'

    cfg = load_config()
    nets = cfg.get('networks', [])
    idx = next((i for i, n in enumerate(nets)
                if n.get('subnet') == original), None)
    if idx is None:
        return jsonify({'error': f'Rede {original} não encontrada'}), 404
    if any(n.get('subnet') == subnet for i, n in enumerate(nets) if i != idx):
        return jsonify({'error': f'Rede {subnet}.0/24 já configurada'}), 409
    nets[idx] = {'subnet': subnet, 'gateway': gateway}
    cfg['networks'] = nets
    save_config(cfg)
    _wake_discovery_loops()
    return jsonify({'ok': True, 'subnet': subnet, 'gateway': gateway})

@ns_bp.route('/api/subnets', methods=['DELETE'])
@ns_login_required
def api_subnets_del():
    body = request.get_json(silent=True) or {}
    subnet = (body.get('subnet') or '').strip()
    if not subnet:
        return jsonify({'error': 'Subnet obrigatória'}), 400
    cfg = load_config()
    cfg['networks'] = [n for n in cfg.get('networks', []) if n['subnet'] != subnet]
    save_config(cfg)
    _wake_discovery_loops()
    return jsonify({'ok': True})

@ns_bp.route('/api/trash')
@ns_login_required
def api_trash():
    items = store.trashed()
    for d in items:
        d['deleted_at_fmt'] = ''
        if d.get('deleted_at'):
            try:
                dt = datetime.fromisoformat(d['deleted_at'])
                d['deleted_at_fmt'] = dt.strftime('%d/%m %H:%M')
            except (ValueError, TypeError):
                pass
        if d.get('merged_into'):
            s = store.find(d['merged_into'], include_deleted=True)
            d['merged_into_name'] = (s.get('hostname') or s.get('ip')
                                     or d['merged_into']) if s else d['merged_into']
        else:
            d['merged_into_name'] = ''
    return jsonify({'devices': items})

@ns_bp.route('/api/trash/<path:mac>/restore', methods=['POST'])
@ns_login_required
def api_trash_restore(mac):
    try:
        ok, code = store.restore(mac)
    except Exception as e:
        try:
            from flask import current_app
            current_app.logger.error(f"[NetScope] restore falhou para {mac}: {e!r}")
        except Exception:
            pass
        return jsonify({'error': 'Falha ao restaurar dispositivo',
                        'detail': str(e)[:300]}), 500
    if not ok:
        return jsonify({'error': 'Não encontrado na lixeira'}), code
    return jsonify({'ok': True})

@ns_bp.route('/api/trash/<path:mac>', methods=['DELETE'])
@ns_login_required
def api_trash_delete(mac):
    try:
        ok, code = store.permanent_delete(mac)
    except Exception as e:
        try:
            from flask import current_app
            current_app.logger.error(f"[NetScope] permanent_delete falhou para {mac}: {e!r}")
        except Exception:
            pass
        return jsonify({'error': 'Falha ao excluir permanentemente',
                        'detail': str(e)[:300]}), 500
    if not ok:
        return jsonify({'error': 'Não encontrado'}), code
    return jsonify({'ok': True})

@ns_bp.route('/api/devices', methods=['POST'])
@ns_login_required
def api_device_create():
    body = request.get_json(silent=True) or {}
    cfg = load_config()
    dev, code, err = store.create_device(body, cfg)
    if err:
        return jsonify({'error': err}), code
    return jsonify(dev), code

@ns_bp.route('/api/devices/<path:mac>', methods=['PUT'])
@ns_login_required
def api_device_update(mac):
    body = request.get_json(silent=True) or {}
    dev, code, err = store.update_device(mac, body)
    if err:
        return jsonify({'error': err}), code
    return jsonify(dev)

@ns_bp.route('/api/devices/<path:mac>', methods=['DELETE'])
@ns_login_required
def api_device_delete(mac):
    try:
        ok, code = store.soft_delete(mac)
    except Exception as e:
        # soft_delete() calls _flush() which re-raises DB errors. Without
        # this catch the global 500 handler kicks in and (previously)
        # returned HTML, breaking the frontend's r.json() call.
        try:
            from flask import current_app
            current_app.logger.error(f"[NetScope] soft_delete falhou para {mac}: {e!r}")
        except Exception:
            pass
        return jsonify({'error': 'Falha ao excluir dispositivo',
                        'detail': str(e)[:300]}), 500
    if not ok:
        return jsonify({'error': 'Não encontrado'}), code
    return jsonify({'ok': True})

@ns_bp.route('/api/devices/<path:mac>/ping', methods=['POST'])
@ns_login_required
def api_device_ping(mac):
    import subprocess
    dev = store.find(mac)
    if not dev:
        return jsonify({'error': 'Não encontrado'}), 404
    try:
        r = subprocess.run(
            ['ping', '-c', '3', '-W', '1', dev['ip']],
            capture_output=True, text=True, timeout=10
        )
        rm = re.search(r'rtt min/avg/max/mdev = [\d.]+/([\d.]+)/', r.stdout)
        avg_rtt = round(float(rm.group(1)), 1) if rm else None
        ttl_m = re.search(r'ttl=(\d+)', r.stdout, re.IGNORECASE)
        ttl = int(ttl_m.group(1)) if ttl_m else None
        dev['status'] = 'online' if r.returncode == 0 else 'offline'
        dev['last_seen'] = datetime.now().isoformat()
        if avg_rtt is not None:
            dev['avg_rtt'] = avg_rtt
        if ttl is not None:
            dev['ttl'] = ttl
        with store._lock:
            store._flush()
        return jsonify({'reachable': r.returncode == 0, 'avg_rtt': avg_rtt, 'ttl': ttl})
    except subprocess.TimeoutExpired:
        return jsonify({'reachable': False, 'avg_rtt': None, 'ttl': None})

@ns_bp.route('/api/devices/<path:mac>/ports', methods=['POST'])
@ns_login_required
def api_device_ports(mac):
    dev = store.find(mac)
    if not dev:
        return jsonify({'error': 'Não encontrado'}), 404
    cfg = load_config()
    port_map = cfg.get('ports', {})
    port_timeout = cfg.get('port_timeout', 0.3)
    open_ports = scan_tcp_ports(dev['ip'], port_map, port_timeout)
    dev['open_ports'] = open_ports
    with store._lock:
        store._flush()
    return jsonify({'ports': open_ports, 'names': port_map})

@ns_bp.route('/api/devices/<path:mac>/portscan', methods=['POST'])
@ns_login_required
def api_device_portscan(mac):
    from flask import current_app
    dev = store.find(mac)
    if not dev:
        return jsonify({'error': 'Não encontrado'}), 404
    ok, payload, code = start_portscan(current_app._get_current_object(), mac)
    return jsonify(payload), code

@ns_bp.route('/api/portscan/status')
@ns_login_required
def api_portscan_status():
    return jsonify(job_status())

@ns_bp.route('/api/links', methods=['POST'])
@ns_login_required
def api_link_create():
    body = request.get_json(silent=True) or {}
    child = (body.get('child') or '').strip().lower()
    parent = (body.get('parent') or '').strip().lower()
    if not child or not parent:
        return jsonify({'error': 'child e parent obrigatórios'}), 400
    ok, code, err = store.create_link(child, parent)
    if err:
        return jsonify({'error': err}), code
    return jsonify({'ok': True})

@ns_bp.route('/api/links', methods=['DELETE'])
@ns_login_required
def api_link_delete():
    body = request.get_json(silent=True) or {}
    mac = (body.get('mac') or '').strip().lower()
    try:
        ok, code = store.remove_link(mac)
    except Exception as e:
        return jsonify({'error': 'Falha ao desassociar',
                        'detail': str(e)[:300]}), 500
    if not ok:
        return jsonify({'error': 'Não encontrado'}), code
    return jsonify({'ok': True})

@ns_bp.route('/api/infer', methods=['POST'])
@ns_login_required
def api_infer():
    cfg = load_config()
    changed = store.infer_links(cfg)
    return jsonify({'changed': changed})

@ns_bp.route('/api/scan', methods=['POST'])
@ns_login_required
def api_scan():
    body = request.get_json(silent=True) or {}
    auto_snap = body.get('auto_snapshot', False) if isinstance(body, dict) else False
    ok, payload, code = start_scan(auto_snapshot=auto_snap)
    return jsonify(payload), code

@ns_bp.route('/api/scan/status')
@ns_login_required
def api_scan_status():
    return jsonify(scan_status())

@ns_bp.route('/api/switches')
@ns_login_required
def api_switches():
    return jsonify({'switches': get_switches_with_ports()})

@ns_bp.route('/api/switches/<path:mac>', methods=['POST'])
@ns_login_required
def api_switch_update(mac):
    switch_mac = mac.lower()
    body = request.get_json(silent=True) or {}
    port_count = body.get('port_count')
    ports = body.get('ports')
    if port_count is None and ports is None:
        return jsonify({'error': 'Nada para atualizar'}), 400
    sw = update_switch_config(switch_mac, port_count, ports)
    return jsonify({'ok': True, 'switch': sw})

@ns_bp.route('/api/snapshots')
@ns_login_required
def api_snapshots_list():
    return jsonify({'snapshots': get_instance().list_snapshots()})

@ns_bp.route('/api/snapshots', methods=['POST'])
@ns_login_required
def api_snapshot_create():
    body = request.get_json(silent=True) or {}
    label = (body.get('label') or '').strip()
    notes = (body.get('notes') or '').strip()
    snap = get_instance().create_snapshot(label, notes, auto=False)
    return jsonify(snap), 201

@ns_bp.route('/api/snapshots/<path:snap_id>')
@ns_login_required
def api_snapshot_get(snap_id):
    snap = get_instance().load_snapshot(snap_id)
    if not snap:
        return jsonify({'error': 'Snapshot não encontrado'}), 404
    return jsonify(snap)

@ns_bp.route('/api/snapshots/<path:snap_id>', methods=['DELETE'])
@ns_login_required
def api_snapshot_delete(snap_id):
    try:
        ok = get_instance().delete_snapshot(snap_id)
    except Exception as e:
        return jsonify({'error': 'Falha ao excluir snapshot',
                        'detail': str(e)[:300]}), 500
    if not ok:
        return jsonify({'error': 'Snapshot não encontrado'}), 404
    return jsonify({'ok': True})

@ns_bp.route('/api/snapshots/<path:a>/compare/<path:b>')
@ns_login_required
def api_snapshot_compare(a, b):
    cmp = get_instance().compare_snapshots(a, b)
    if not cmp:
        return jsonify({'error': 'Snapshots não encontrados'}), 404
    return jsonify(cmp)

@ns_bp.route('/api/export/csv')
@ns_login_required
def api_export_csv():
    csv_data = export_assets_csv()
    filename = f'netscope_assets_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    return Response(
        csv_data,
        mimetype='text/csv; charset=utf-8',
        headers={'Content-Disposition': f'attachment; filename="{filename}"'}
    )

@ns_bp.route('/api/export/json')
@ns_login_required
def api_export_json():
    import json
    data = export_full_json()
    filename = f'netscope_full_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
    return Response(
        json.dumps(data, indent=2, default=str),
        mimetype='application/json',
        headers={'Content-Disposition': f'attachment; filename="{filename}"'}
    )

@ns_bp.route('/api/wazuh_sync', methods=['POST'])
@ns_login_required
def api_wazuh_sync():

    from flask import current_app
    try:
        stats = sync_from_inventory(current_app._get_current_object())
        return jsonify({'ok': True, **stats})
    except Exception as e:
        current_app.logger.error(f"[NetScope] Erro na sincronização Wazuh: {e}")
        return jsonify({'ok': False, 'error': str(e)}), 500

@ns_bp.route('/api/wazuh_agents')
@ns_login_required
def api_wazuh_agents():

    try:
        from models import HostInventory
        hosts = HostInventory.query.filter_by(is_legacy=False).order_by(HostInventory.hostname).all()
    except Exception as e:
        return jsonify({'error': str(e)}), 500

    agents = []
    for h in hosts:
        data = h.data or {}
        ai = data.get('agent_info', {}) or {}
        inv = data.get('inventory', {}) or {}
        macs = [nif.get('mac', '').lower() for nif in inv.get('netiface', []) or []
                if nif.get('mac') and nif.get('mac') not in ('N/A', '00:00:00:00:00:00')]
        ip = ai.get('ip', '')
        in_netscope = any(store.find(m) for m in macs) or (bool(ip) and store.find_by_ip(ip) is not None)
        agents.append({
            'hostname': h.hostname,
            'agent_id': ai.get('id', ''),
            'ip': ip,
            'mac': macs[0] if macs else '',
            'status': ai.get('status', ''),
            'last_keepalive': ai.get('lastKeepAlive', ''),
            'groups': data.get('groups') or ai.get('group') or [],
            'in_netscope': in_netscope,
        })
    return jsonify({'agents': agents})
