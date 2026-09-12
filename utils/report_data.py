
from collections import Counter

COMMON_SERVICES = {
    '22': 'SSH', '80': 'HTTP', '443': 'HTTPS', '21': 'FTP', '53': 'DNS',
    '3306': 'MySQL', '5432': 'PostgreSQL', '27017': 'MongoDB', '6379': 'Redis',
}

_LOOPBACK = {'127.0.0.1', 'localhost', '::1'}

def _norm_host(h):

    return str(h or '').strip().lower()

def _valid_ip(ip):

    ip = str(ip or '').strip()
    return ip if ip and ip not in _LOOPBACK else None

def _dev_key(dev):

    return str(dev.get('uid') or dev.get('mac') or '').lower()

def _machine_macs(machine):

    macs = []
    for iface in (machine.get('netiface') or []):
        mac = str(iface.get('mac') or '').strip().lower()
        if mac and mac not in ('n/a', 'none', 'unknown'):
            macs.append(mac)
    return macs

def merge_machines_devices(machines, devices):

    by_host, by_ip, by_mac = {}, {}, {}
    for d in devices:
        h = _norm_host(d.get('hostname') or d.get('agent_name'))
        if h:
            by_host.setdefault(h, d)
        for ip_field in ('ip', 'agent_ip'):
            ip = _valid_ip(d.get(ip_field))
            if ip:
                by_ip.setdefault(ip, d)
        mac = str(d.get('mac') or '').strip().lower()
        if mac:
            by_mac.setdefault(mac, d)

    matched = set()
    rows = []

    for m in machines:
        dev = None
        host = _norm_host(m.get('hostname'))
        if host and host in by_host:
            dev = by_host[host]
        if dev is None:
            for mac in _machine_macs(m):
                if mac in by_mac:
                    dev = by_mac[mac]
                    break
        if dev is None:
            ip = _valid_ip(m.get('ip_address'))
            if ip and ip in by_ip:
                dev = by_ip[ip]

        if dev is not None:
            matched.add(_dev_key(dev))

        rows.append(_build_row(m, dev))

    for d in devices:
        if _dev_key(d) not in matched:
            rows.append(_build_row(None, d))

    rows.sort(key=lambda r: r['hostname'].lower())
    return rows

def _build_row(machine, dev):

    hostname = (machine or {}).get('hostname') or (dev or {}).get('hostname') or '—'
    ip = ((machine or {}).get('ip_address')
          or (dev or {}).get('ip') or '—')
    if ip in ('N/A', ''):
        ip = (dev or {}).get('ip') or '—'

    has_agent = bool(machine) or bool(dev and dev.get('has_agent'))
    if machine and dev:
        source = 'wazuh+netcope'
    elif machine:
        source = 'wazuh'
    else:
        source = 'netcope'

    agent_exempt = bool(dev and dev.get('agent_exempt') and not has_agent)

    return {
        'hostname': str(hostname),
        'ip': str(ip),
        'source': source,
        'has_agent': has_agent,
        'agent_exempt': agent_exempt,
        'machine': machine,
        'ns': dev,
    }

def top_processes(machines, n=10):

    machines_by_proc = {}
    for m in machines:
        host = str(m.get('hostname') or id(m))
        for proc in (m.get('processes') or []):
            name = str(proc.get('name') or '').strip()
            if name and name not in ('N/A', 'Unknown', 'unknown'):
                machines_by_proc.setdefault(name, set()).add(host)
    return [(name, len(hosts))
            for name, hosts in sorted(machines_by_proc.items(),
                                      key=lambda x: -len(x[1]))[:n]]

def top_packages(machines, n=10):

    machines_by_pkg = {}
    for m in machines:
        host = str(m.get('hostname') or id(m))
        for pkg in (m.get('packages') or []):
            name = str(pkg.get('name') or '').strip()
            if name and name not in ('N/A', 'Unknown', 'unknown'):
                machines_by_pkg.setdefault(name, set()).add(host)
    return [(name, len(hosts))
            for name, hosts in sorted(machines_by_pkg.items(),
                                      key=lambda x: -len(x[1]))[:n]]

def top_ports(machines, n=10):

    machines_by_port = {}
    protocols = {}
    for m in machines:
        host = str(m.get('hostname') or id(m))
        for port in (m.get('ports') or []):
            if not isinstance(port, dict):
                continue
            p_num = str(port.get('local', {}).get('port') or '')
            if not p_num or p_num in ('N/A', 'Unknown'):
                continue
            machines_by_port.setdefault(p_num, set()).add(host)
            if str(port.get('protocol', '')).lower() == 'udp':
                protocols[p_num] = 'udp'
    out = []
    for p_num, hosts in sorted(machines_by_port.items(),
                               key=lambda x: -len(x[1]))[:n]:
        proto = protocols.get(p_num, 'tcp')
        service = COMMON_SERVICES.get(p_num, '')
        label = (f'{service} - {p_num}/{proto.upper()}' if service
                 else f'{p_num}/{proto.upper()}')
        out.append((label, len(hosts)))
    return out

def os_distribution(machines):

    counts = Counter()
    for m in machines:
        name = str(m.get('os_name') or 'Unknown').strip() or 'Unknown'
        counts[name] += 1
    return counts.most_common()

def os_version_kernel(machines):

    counts = Counter()
    for m in machines:
        name = str(m.get('os_name') or '').strip()
        if not name or name in ('Unknown', 'N/A'):
            name = 'Unknown'
        ver = str(m.get('os_version') or '').strip()
        if ver in ('N/A', 'unknown', 'Unknown'):
            ver = ''
        kern = str(m.get('os_kernel') or '').strip()
        if kern in ('N/A', 'unknown', 'Unknown'):
            kern = ''
        counts[(name, ver, kern)] += 1
    return [(k[0], k[1], k[2], n)
            for k, n in sorted(counts.items(),
                               key=lambda x: (-x[1], x[0]))]

def cpu_top(machines, n=10):

    counts = Counter()
    for m in machines:
        name = str(m.get('cpu_name') or 'Unknown').strip() or 'Unknown'
        counts[name] += 1
    return counts.most_common(n)

def ram_distribution(machines):

    ranges = [
        (2, '0-2GB'), (4, '3-4GB'), (8, '5-8GB'),
        (16, '9-16GB'), (32, '17-32GB'), (64, '33-64GB'),
    ]
    counts = Counter()
    for m in machines:
        gb = m.get('ram_gb')
        gb = gb if isinstance(gb, (int, float)) else 0
        label = '64+GB' if gb > 64 else next(
            (lbl for lim, lbl in ranges if gb <= lim), '64+GB' if gb > 0 else 'Unknown')
        counts[label] += 1
    order = [lbl for _, lbl in ranges] + ['64+GB', 'Unknown']
    return [(lbl, counts[lbl]) for lbl in order if counts.get(lbl)]

def ram_usage_top(machines, n=10):

    entries = []
    for m in machines:
        usage = m.get('ram_usage')
        if isinstance(usage, (int, float)) and m.get('hostname'):
            entries.append({
                'name': m['hostname'],
                'usage': round(float(usage), 1),
                'total_gb': m.get('ram_gb') if isinstance(m.get('ram_gb'), (int, float)) else None,
            })
    return sorted(entries, key=lambda x: -x['usage'])[:n]

def keepalive_buckets(machines):

    from datetime import datetime
    buckets = {'Hoje': 0, '1-7 dias': 0, '8-30 dias': 0, 'Mais de 30 dias': 0}
    now = datetime.now()
    for m in machines:
        ls = m.get('last_seen')
        if not ls or not isinstance(ls, str) or ls == 'N/A':
            continue
        try:
            dt = datetime.fromisoformat(ls.replace('Z', '+00:00')).replace(tzinfo=None)
        except ValueError:
            continue
        age = (now - dt).days
        if age <= 0:
            buckets['Hoje'] += 1
        elif age <= 7:
            buckets['1-7 dias'] += 1
        elif age <= 30:
            buckets['8-30 dias'] += 1
        else:
            buckets['Mais de 30 dias'] += 1
    return buckets

def agent_status_detail(machines):

    detail = {'active': 0, 'disconnected': 0, 'never_connected': 0}
    for m in machines:
        st = str(m.get('agent_status_raw') or '').strip().lower()
        if st in detail:
            detail[st] += 1
        elif st and st != 'unknown':
            detail['disconnected'] += 1
    return detail

def ns_type_distribution(devices):

    counts = Counter()
    for d in devices:
        counts[str(d.get('type') or 'desktop')] += 1
    return counts.most_common()
