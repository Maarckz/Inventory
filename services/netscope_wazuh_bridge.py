
import hashlib
from datetime import datetime

from services.netscope_core import (store, load_config, save_config, guess_vendor, infer_type, mac_from_agent, dev_key, AGENT_FIELDS, _plausible_hostname, _implausible)

def _query_hosts():
    from models import HostInventory
    return HostInventory.query.filter_by(is_legacy=False).all()

def _norm_host(name):
    return (name or '').strip().upper().split('.')[0]

def _extract_host_info(host):

    data = host.data or {}
    agent_info = data.get('agent_info', {}) or {}
    inv = data.get('inventory', {}) or {}

    macs = []
    for nif in inv.get('netiface', []) or []:
        mac = (nif.get('mac') or '').strip().lower()
        if mac and mac not in ('n/a', '00:00:00:00:00:00', 'unknown') and mac not in macs:
            macs.append(mac)

    def _ip_usable(ip):
        return ip and ip not in ('N/A', 'n/a', 'unknown', '127.0.0.1', 'localhost') and '.' in ip

    ip = (agent_info.get('ip') or '').strip()
    if not _ip_usable(ip):
        ip = ''
        for addr in inv.get('netaddr', []) or []:
            a = (addr.get('address') or '').strip()
            if _ip_usable(a) and not a.startswith('127.'):
                ip = a
                break
        if not ip:
            ip = (agent_info.get('ip') or '').strip() if _ip_usable(agent_info.get('ip')) else ''

    hostname = ''
    os_host = inv.get('os', []) or [{}]
    if os_host:
        hostname = (os_host[0].get('hostname') or '').strip()
    hostname = hostname or (agent_info.get('name') or '').strip() or host.hostname

    os_name = ''
    os_platform = ''
    if os_host:
        os_data = os_host[0].get('os', {}) or {}
        os_name = (os_data.get('name') or '') + ((' ' + os_data.get('version', '')) if os_data.get('version') else '')
        os_platform = os_data.get('platform') or ''

    return {
        'agent_id': str(agent_info.get('id', '') or ''),
        'agent_name': (agent_info.get('name') or '').strip(),
        'agent_status': (agent_info.get('status') or '').strip(),
        'agent_ip': ip,
        'last_keepalive': (agent_info.get('lastKeepAlive') or '').strip(),
        'groups': [g for g in (data.get('groups') or agent_info.get('group') or []) if g] or [],
        'macs': macs,
        'hostname': hostname,
        'os': os_name.strip(),
        'os_platform': os_platform,
    }

def _apply_agent_fields(dev, info, fill_doc=True):

    dev['has_agent'] = True
    dev['agent_id'] = info['agent_id']
    dev['agent_name'] = info['hostname'] or info['agent_name']
    dev['agent_status'] = info['agent_status']
    dev['agent_last_keepalive'] = info['last_keepalive']
    dev['agent_groups'] = info['groups']
    dev['agent_ip'] = info['agent_ip']

    if info['agent_status'] == 'active':
        dev['status'] = 'online'
        dev['last_seen'] = datetime.now().isoformat()

    if info['agent_ip'] and (not dev.get('ip') or dev['ip'] in ('', 'N/A', '127.0.0.1')):
        dev['ip'] = info['agent_ip']
    if (info['hostname'] and _plausible_hostname(info['hostname'])
            and not dev.get('name_manual')
            and (_implausible(dev.get('hostname'))
                 or (info['agent_status'] == 'active'
                     and info['hostname'] != dev.get('hostname')))):
        dev['hostname'] = info['hostname']
    if fill_doc:
        if info['os'] and not dev.get('os'):
            dev['os'] = info['os']
        if not dev.get('vendor') and info['macs']:
            dev['vendor'] = guess_vendor(info['macs'][0])
    if not dev.get('source'):
        dev['source'] = 'wazuh'
    if not dev.get('type') or dev.get('type') == 'desktop':
        dev['type'] = infer_type(dev.get('ip', ''), dev.get('vendor', ''), None, info['os_platform'])

def _mac_prefix(mac, n=5):

    parts = (mac or '').replace(':', '-').split('-')
    return ':'.join(parts[:n])

def _doc_score(dev):

    score = 0
    for f in ('user', 'department', 'location', 'asset_tag', 'model',
              'serial_number', 'os', 'seal_number', 'notes'):
        if dev.get(f):
            score += 1
    if dev.get('hostname'):
        score += 1
    if dev.get('dns_name'):
        score += 1
    if dev.get('switch_port'):
        score += 1
    return score

def _is_synthetic_mac(mac):

    try:
        first = int((mac or ':').split(':')[0], 16)
        return bool(first & 0x02)
    except (ValueError, IndexError):
        return False

def _survivor_rank(dev):

    return (
        0 if dev.get('has_agent') else 1,
        0 if dev.get('mac') else 1,
        0 if not _is_synthetic_mac(dev.get('mac')) else 1,
        -_doc_score(dev),
        dev.get('first_seen') or '9999',
    )

def _dup(a, b):

    ipa, ipb = (a.get('ip') or ''), (b.get('ip') or '')
    if ipa and ipa == ipb and ipa not in ('127.0.0.1', 'localhost'):
        return 'ip'
    pa, pb = _mac_prefix(a.get('mac')), _mac_prefix(b.get('mac'))
    sa, sb = (a.get('subnet') or ''), (b.get('subnet') or '')
    if pa and pa == pb and sa and sa == sb:
        return 'mac-prefix'
    na, nb = _norm_host(a.get('hostname')), _norm_host(b.get('hostname'))
    if na and na == nb:
        return 'hostname'
    return None

def _merge_pair(keep, dup, reason=''):

    FILL = ('hostname', 'dns_name', 'ip', 'vendor', 'type', 'user', 'department',
            'location', 'asset_tag', 'model', 'serial_number', 'os', 'seal_number',
            'subnet', 'notes')
    if not keep.get('mac') and dup.get('mac'):
        keep['mac'] = dup['mac']
    for f in FILL:
        if not keep.get(f) and dup.get(f):
            keep[f] = dup[f]
    if keep.get('notes') and dup.get('notes') and dup['notes'] not in keep['notes']:
        keep['notes'] = (keep['notes'] + ' | ' + dup['notes'])[:1000]
    for f in ('pos', 'switch_port'):
        if not keep.get(f) and dup.get(f):
            keep[f] = dup[f]
    if not keep.get('parent_id') and dup.get('parent_id'):
        keep['parent_id'] = dup['parent_id']
    if (dup.get('last_seen') or '') > (keep.get('last_seen') or ''):
        keep['last_seen'] = dup.get('last_seen')
        keep['status'] = dup.get('status') or keep.get('status')
    if dup.get('ttl') and not keep.get('ttl'):
        keep['ttl'] = dup['ttl']
    if dup.get('open_ports'):
        merged_ports = list(keep.get('open_ports') or [])
        for p in dup['open_ports']:
            if p not in merged_ports:
                merged_ports.append(p)
        keep['open_ports'] = merged_ports
    if dup.get('avg_rtt') is not None and keep.get('avg_rtt') is None:
        keep['avg_rtt'] = dup['avg_rtt']
    if dup.get('source') and dup['source'] not in (keep.get('source') or ''):
        keep['source'] = (keep.get('source') or '') + '+' + dup['source']
    if (dup.get('first_seen') or '9999') < (keep.get('first_seen') or '9999'):
        keep['first_seen'] = dup.get('first_seen')
    dup_key = dev_key(dup)
    dup['deleted'] = True
    dup['deleted_at'] = datetime.now().isoformat()
    dup['merged_into'] = dev_key(keep)
    dup['merge_reason'] = reason or ''
    try:
        from services.netscope_core import load_config, save_config
        cfg = load_config()
        changed = False
        for _sw in (cfg.get('switches', {}) or {}).values():
            if not isinstance(_sw, dict):
                continue
            for p_info in (_sw.get('ports', {}) or {}).values():
                if (p_info.get('device_mac') or '').lower() == dup_key.lower():
                    p_info['device_mac'] = ''
                    changed = True
        if changed:
            save_config(cfg)
    except Exception:
        pass
    return dup_key

def _remap_parents(removed_key, survivor_key):

    for d in store._cache['devices']:
        if (d.get('parent_id') or '').lower() == removed_key.lower():
            d['parent_id'] = survivor_key

def dedup_devices():

    try:
        auto = bool(load_config().get('auto_merge'))
    except Exception:
        auto = False
    if not auto:
        return 0
    return _dedup_devices_locked()

def _dedup_devices_locked():

    merged = 0
    changed = True
    while changed:
        changed = False
        active = [d for d in store._cache['devices'] if not d.get('deleted')]
        for ii in range(len(active)):
            if changed:
                break
            a = active[ii]
            for jj in range(ii + 1, len(active)):
                b = active[jj]
                reason = _dup(a, b)
                if reason:
                    keep, dup = (a, b) if _survivor_rank(a) <= _survivor_rank(b) else (b, a)
                    dup_key = _merge_pair(keep, dup, reason)
                    _remap_parents(dup_key, dev_key(keep))
                    merged += 1
                    changed = True
                    break
    return merged

def find_duplicates():

    act = store.active()
    groups = []
    n = len(act)
    for ii in range(n):
        a = act[ii]
        for jj in range(ii + 1, n):
            b = act[jj]
            reason = _dup(a, b)
            if reason:
                ka, kb = dev_key(a), dev_key(b)
                for g in groups:
                    if g['reason'] == reason and (ka in g['uids'] or kb in g['uids']):
                        g['uids'].extend([u for u in (ka, kb) if u not in g['uids']])
                        break
                else:
                    groups.append({'reason': reason, 'uids': [ka, kb]})
    return groups

def duplicate_marks():

    marks = {}
    try:
        for g in find_duplicates():
            for u in g['uids']:
                marks.setdefault(u, [])
                if g['reason'] not in marks[u]:
                    marks[u].append(g['reason'])
    except Exception:
        pass
    return marks

def sync_from_inventory(app, logger=None):

    log = logger or app.logger
    stats = {'hosts': 0, 'created': 0, 'updated': 0, 'matched': 0,
             'without_agent': 0, 'merged': 0}

    try:
        hosts = _query_hosts()
    except Exception as e:
        log.error(f"[NetScope] Falha ao consultar host_inventory: {e}")
        return stats

    infos = [_extract_host_info(h) for h in hosts]
    infos = [i for i in infos if i['agent_id'] or i['hostname'] or i['agent_ip']]
    stats['hosts'] = len(infos)

    with store._lock:
        store._load()

        mac_map = {}
        ip_map = {}
        name_map = {}
        for i, info in enumerate(infos):
            for mac in info['macs']:
                mac_map[mac] = i
            if info['agent_ip']:
                ip_map[info['agent_ip']] = i
            if info['hostname']:
                name_map[_norm_host(info['hostname'])] = i

        matched_indices = set()

        for dev in store.active():
            idx = None
            if dev.get('mac') and dev['mac'] in mac_map:
                idx = mac_map[dev['mac']]
            if idx is None and dev.get('ip') and dev['ip'] in ip_map:
                idx = ip_map[dev['ip']]
            if idx is None and dev.get('hostname'):
                n = _norm_host(dev['hostname'])
                if n and n in name_map:
                    idx = name_map[n]

            if idx is not None:
                info = infos[idx]
                matched_indices.add(idx)
                _apply_agent_fields(dev, info)
                stats['matched'] += 1
                stats['updated'] += 1
            else:
                dev['has_agent'] = False
                dev['agent_id'] = ''
                dev['agent_name'] = ''
                dev['agent_status'] = ''
                dev['agent_last_keepalive'] = ''
                dev['agent_groups'] = []
                dev['agent_ip'] = ''
                if not dev.get('agent_exempt'):
                    stats['without_agent'] += 1

        for i, info in enumerate(infos):
            if i in matched_indices:
                continue

            mac = None
            for m in info['macs']:
                if not store.find(m, include_deleted=True):
                    mac = m
                    break
            if mac is None and info['macs']:
                existing = store.find(info['macs'][0], include_deleted=True)
                if existing and not existing.get('deleted'):
                    if existing.get('ip') == info['agent_ip'] or not existing.get('ip'):
                        _apply_agent_fields(existing, info)
                        stats['matched'] += 1
                        continue
                mac = info['macs'][0]

            if mac is None:
                mac = mac_from_agent(info['agent_id'] or info['hostname'] or 'wazuh')

            if store.find(mac, include_deleted=True):
                continue

            subnet = '.'.join(info['agent_ip'].split('.')[:3]) if info['agent_ip'] and '.' in info['agent_ip'] else ''
            dev = store._new_device(mac, info['agent_ip'], guess_vendor(mac), subnet, None, source='wazuh')
            _apply_agent_fields(dev, info)
            if info['agent_status'] != 'active':
                dev['status'] = 'offline'
            dev['hostname'] = info['hostname'] or info['agent_name']
            store._cache['devices'].append(dev)
            stats['created'] += 1

        stats['merged'] = dedup_devices()

        store._flush()

    log.info(
        "[NetScope] Ponte Wazuh concluída: {hosts} hosts, {matched} com agente casados, "
        "{created} criados, {without_agent} sem agente, {merged} duplicatas mescladas.".format(**stats)
    )
    return stats
