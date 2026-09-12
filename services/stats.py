
from __future__ import annotations

import time
from collections import defaultdict
from datetime import datetime, timedelta

from flask import current_app

from models import HostInventory, Group
from utils.machine_handler import process_machine_data, get_machine_fallback
from utils import cache as shared_cache

CACHE_TIMEOUT = 40

def get_ram_range(ram_gb):
    ranges = [
        (2, "0-2GB"), (4, "3-4GB"), (8, "5-8GB"),
        (16, "9-16GB"), (32, "17-32GB"), (64, "33-64GB")
    ]
    for limit, label in ranges:
        if ram_gb <= limit:
            return label
    return "64+GB" if ram_gb > 0 else "Unknown"

def get_machine_stats(machines):
    os_counts = {}
    cpu_counts = {}
    ram_counts = {}
    status_counts = {'Ativo': 0, 'Inativo': 0}
    port_counts = {}
    proc_counts = {}
    software_counts = {}
    total = 0

    for machine in machines:
        name = machine.get('os_name', 'Unknown')
        os_counts[name] = os_counts.get(name, 0) + 1

        cpu = machine.get('cpu_name', 'Unknown')
        cpu_counts[cpu] = cpu_counts.get(cpu, 0) + 1

        ram_gb = machine.get('ram_gb', 0)
        range_key = get_ram_range(ram_gb)
        ram_counts[range_key] = ram_counts.get(range_key, 0) + 1

        status = machine.get('device_status', 'Inativo')
        status_counts[status] = status_counts.get(status, 0) + 1

        for port in machine.get('ports', []):
            local = port.get('local', {})
            ip = local.get('ip', '')
            if ip and ('.' in ip or ':' in ip):
                p_num = str(local.get('port', 'Unknown'))
                if p_num not in ('N/A', 'Unknown'):
                    port_counts[p_num] = port_counts.get(p_num, 0) + 1

        for proc in machine.get('processes', []):
            p_name = proc.get('name', 'Unknown')
            if p_name not in ('N/A', 'Unknown'):
                proc_counts[p_name] = proc_counts.get(p_name, 0) + 1

        for pkg in machine.get('packages', []):
            pkg_name = pkg.get('name', 'Unknown')
            if pkg_name not in ('N/A', 'Unknown'):
                software_counts[pkg_name] = software_counts.get(pkg_name, 0) + 1

        total += 1

    return {
        'os': os_counts,
        'cpu': cpu_counts,
        'ram': ram_counts,
        'status': status_counts,
        'ports': port_counts,
        'processes': proc_counts,
        'software': software_counts,
        'total': total
    }

def get_all_machines():
    app = current_app._get_current_object()
    try:
        hosts = HostInventory.query.filter_by(is_legacy=False).all()
        machines_list = []
        for h in hosts:
            try:
                processed = process_machine_data(h.data)
                if processed:
                    machines_list.append(processed)
            except Exception as e:
                app.logger.error(f"Erro ao processar máquina: {e}")

        app.logger.info(
            f"[Dashboard] Carregados {len(machines_list)} hosts do banco de "
            f"dados para o cache.")
        return machines_list
    except Exception as e:
        app.logger.error(f"Erro fatal ao buscar máquinas do banco: {e}")
        return []

def get_cached_machines():

    app = current_app._get_current_object()
    if not hasattr(app, 'MACHINES_CACHE'):
        app.MACHINES_CACHE = {'data': None, 'last_update': 0}

    shared = shared_cache.get_json('machines')
    if shared is not None:
        app.MACHINES_CACHE['data'] = shared
        app.MACHINES_CACHE['last_update'] = time.time()
        return shared

    if app.MACHINES_CACHE['data'] is not None:
        return app.MACHINES_CACHE['data']

    machines = get_all_machines()
    app.MACHINES_CACHE['data'] = machines
    app.MACHINES_CACHE['last_update'] = time.time()
    shared_cache.set_json('machines', machines, ttl=shared_cache.TTL_MACHINES)
    return machines

def get_cached_stats():

    app = current_app._get_current_object()
    current_time = time.time()
    shared = shared_cache.get_json('stats')
    if shared is not None:
        app.STATS_CACHE['data'] = shared
        app.STATS_CACHE['last_update'] = current_time
        return shared
    if app.STATS_CACHE['data'] and (current_time - app.STATS_CACHE['last_update']) <= CACHE_TIMEOUT:
        return app.STATS_CACHE['data']
    machines = get_cached_machines()
    stats = get_machine_stats(machines)
    app.STATS_CACHE['data'] = stats
    app.STATS_CACHE['last_update'] = current_time
    shared_cache.set_json('stats', stats, ttl=shared_cache.TTL_STATS)
    return stats

def build_chart_response(stats, machines):

    app = current_app._get_current_object()
    from core.i18n import translate

    common_services = {
        '22': 'SSH', '80': 'HTTP', '443': 'HTTPS', '21': 'FTP', '53': 'DNS',
        '3306': 'MySQL', '5432': 'PostgreSQL', '27017': 'MongoDB', '6379': 'Redis'
    }

    port_details = defaultdict(lambda: {'count': 0, 'protocol': 'tcp'})
    for machine in machines:
        try:
            for port in machine.get('ports', []):
                if isinstance(port, dict):
                    port_num = str(port.get('local', {}).get('port', ''))
                    if port_num and port_num != 'N/A':
                        port_details[port_num]['count'] += 1
                        if port.get('protocol', '').lower() == 'udp':
                            port_details[port_num]['protocol'] = 'udp'
        except Exception as e:
            app.logger.error(f"Erro ao processar portas de uma máquina: {e}")

    sorted_ports = sorted(port_details.items(), key=lambda x: x[1]['count'], reverse=True)[:10]
    port_labels = []
    port_data = []
    port_protocols = []
    for port, details in sorted_ports:
        service = common_services.get(port, '')
        label = f"{service} - {port}/{details['protocol'].upper()}" if service else f"{port}/{details['protocol'].upper()}"
        port_labels.append(label)
        port_data.append(details['count'])
        port_protocols.append(details['protocol'])

    sorted_processes = sorted(stats.get('processes', {}).items(), key=lambda x: x[1], reverse=True)[:10]
    process_labels = [proc for proc, count in sorted_processes]
    process_data = [count for proc, count in sorted_processes]

    groups_data = []
    try:
        groups_objs = Group.query.filter_by(is_legacy=False).all()
        groups_data = [g.data for g in groups_objs if g.data]
    except Exception:
        pass

    timeline_data = {'dates': [], 'active': [], 'inactive': []}
    today = datetime.now().date()
    for i in range(6, -1, -1):
        date = today - timedelta(days=i)
        timeline_data['dates'].append(date.strftime('%d/%m'))
        a, inat = 0, 0
        for machine in machines:
            ls = machine.get('last_seen')
            if ls and ls != 'N/A':
                try:
                    m_date = datetime.fromisoformat(ls).date() if isinstance(ls, str) else ls.date()
                    if m_date == date:
                        if machine.get('device_status') == 'Ativo':
                            a += 1
                        else:
                            inat += 1
                except Exception:
                    continue
        timeline_data['active'].append(a)
        timeline_data['inactive'].append(inat)

    ns_types = {}
    ns_total = ns_with_agent = ns_without_agent = ns_agent_exempt = 0
    try:
        from services.netscope_core import store as _ns_store
        for d in _ns_store.active():
            ns_total += 1
            if d.get('has_agent'):
                ns_with_agent += 1
            elif d.get('agent_exempt'):
                ns_agent_exempt += 1
            else:
                ns_without_agent += 1
            t = d.get('type') or 'desktop'
            ns_types[t] = ns_types.get(t, 0) + 1
    except Exception as e:
        app.logger.debug(f"[Dashboard] NetScope extra indisponível: {e}")

    agent_status_detail = {'active': 0, 'disconnected': 0, 'never_connected': 0}
    keepalive_buckets = {'today': 0, 'week': 0, 'month': 0, 'old': 0}
    ram_usage_list = []
    now_dt = datetime.now()
    for m in machines:
        raw_st = str(m.get('agent_status_raw', '')).strip().lower()
        if raw_st in agent_status_detail:
            agent_status_detail[raw_st] += 1
        elif raw_st and raw_st != 'unknown':
            agent_status_detail['disconnected'] += 1

        ls = m.get('last_seen')
        if ls and isinstance(ls, str) and ls != 'N/A':
            try:
                m_dt = datetime.fromisoformat(ls.replace('Z', '+00:00')).replace(tzinfo=None)
                age_days = (now_dt - m_dt).days
                if age_days <= 0:
                    keepalive_buckets['today'] += 1
                elif age_days <= 7:
                    keepalive_buckets['week'] += 1
                elif age_days <= 30:
                    keepalive_buckets['month'] += 1
                else:
                    keepalive_buckets['old'] += 1
            except (ValueError, TypeError):
                continue

        ru = m.get('ram_usage')
        if isinstance(ru, (int, float)) and m.get('hostname'):
            ram_usage_list.append({
                'name': m['hostname'],
                'usage': round(float(ru), 1),
                'total_gb': m.get('ram_gb') if isinstance(m.get('ram_gb'), (int, float)) else None,
            })

    ram_usage_top = sorted(ram_usage_list, key=lambda x: -x['usage'])[:10]

    software_top = [
        {'name': name, 'count': cnt}
        for name, cnt in sorted(stats.get('software', {}).items(), key=lambda x: -x[1])[:10]
    ]

    return {
        'os_labels': list(stats.get('os', {}).keys()),
        'os_data': list(stats.get('os', {}).values()),
        'cpu_labels': [k for k, _ in sorted(stats.get('cpu', {}).items(), key=lambda x: -x[1])[:10]],
        'cpu_data': [v for _, v in sorted(stats.get('cpu', {}).items(), key=lambda x: -x[1])[:10]],
        'ram_labels': list(stats.get('ram', {}).keys()),
        'ram_data': list(stats.get('ram', {}).values()),
        'port_labels': port_labels,
        'port_data': port_data,
        'port_protocols': port_protocols,
        'process_labels': process_labels,
        'process_data': process_data,
        'active_count': stats.get('status', {}).get('Ativo', 0),
        'inactive_count': stats.get('status', {}).get('Inativo', 0),
        'last_update': [m.get('last_seen', 0) for m in machines[:5]],
        'groups': groups_data,
        'timeline_dates': timeline_data['dates'],
        'timeline_active': timeline_data['active'],
        'timeline_inactive': timeline_data['inactive'],
        'recent_machines': [
            {'name': m.get('hostname', 'N/A'),
             'agent_id': m.get('id', 'N/A'),
             'ip': m.get('ip_address', 'N/A'),
             'os': m.get('os_name', 'N/A'),
             'status': translate(m.get('device_status', 'N/A')),
             'status_key': m.get('device_status', 'N/A')}
            for m in sorted(machines, key=lambda x: str(x.get('last_seen', '')), reverse=True)[:5]
        ],
        'ns_total': ns_total,
        'ns_with_agent': ns_with_agent,
        'ns_without_agent': ns_without_agent,
        'ns_agent_exempt': ns_agent_exempt,
        'ns_agent_coverage': round(
            100.0 * ns_with_agent / (ns_with_agent + ns_without_agent), 1
        ) if (ns_with_agent + ns_without_agent) else 0,
        'ns_types': ns_types,
        'agent_status_detail': agent_status_detail,
        'keepalive_buckets': keepalive_buckets,
        'ram_usage_top': ram_usage_top,
        'software_top': software_top,
    }
