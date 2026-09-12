
from __future__ import annotations

from flask import Blueprint, flash, redirect, render_template, request, session, url_for

from core.security import login_required
from services.stats import get_cached_machines, get_machine_fallback

ROUTES = [
    ('/painel', 'painel', 'painel', {}),
    ('/search', 'search', 'search', {}),
    ('/machine/<hostname>', 'machine_details', 'machine_details', {}),
]

@login_required
def painel():
    if 'username' not in session:
        return redirect(url_for('login'))

    page = request.args.get('page', 1, type=int)
    per_page = 50

    machines = get_cached_machines()
    total_machines = len(machines)

    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    paginated_machines = machines[start_idx:end_idx]

    return render_template('painel.html',
                           machines=paginated_machines,
                           page=page,
                           per_page=per_page,
                           total=total_machines)

@login_required
def search():
    if 'username' not in session:
        return redirect(url_for('login'))

    query = request.args.get('query', '')[:100].strip().lower()
    machines = get_cached_machines()
    results = []
    added_hostnames = set()

    if not query:
        return render_template('search.html', results=machines, query="")

    if query.startswith('ram_gb:'):
        ram_query = query.replace('ram_gb:', '').replace('gb', '').strip()

        ram_ranges = {
            "0-2": (0, 2),
            "3-4": (3, 4),
            "5-6": (5, 6),
            "7-8": (7, 8),
            "9-12": (9, 12),
            "13-16": (13, 16),
            "17-24": (17, 24),
            "25-32": (25, 32),
            "33-64": (33, 64)
        }

        for m in machines:
            try:
                ram_val = float(m.get('ram_gb', 0))

                if "-" in ram_query:
                    if ram_query in ram_ranges:
                        min_r, max_r = ram_ranges[ram_query]
                    else:
                        parts = ram_query.split('-')
                        min_r, max_r = float(parts[0]), float(parts[1])

                    if min_r <= ram_val <= max_r:
                        results.append(m)

                elif ram_query.startswith('>'):
                    limit = float(ram_query.replace('>', ''))
                    if ram_val > limit:
                        results.append(m)

                elif ram_query.startswith('<'):
                    limit = float(ram_query.replace('<', ''))
                    if ram_val < limit:
                        results.append(m)

                else:
                    if float(ram_query) == ram_val:
                        results.append(m)
            except (ValueError, IndexError):
                continue

        return render_template('search.html', results=results, query=query)

    if ':' in query:
        tag_parts = query.split(':')
        tag = tag_parts[0].strip()

        search_term = tag_parts[-1].strip()
        sub_tag = tag_parts[1].strip() if len(tag_parts) > 2 else None

        for m in machines:
            hostname = m.get('hostname', '')
            if hostname in added_hostnames:
                continue
            found = False

            if tag in ['groups', 'group']:
                candidate_groups = []

                if m.get('groups'):
                    candidate_groups.extend(m['groups'] if isinstance(m['groups'], list) else [m['groups']])

                agent_info = m.get('agent_info', {})
                if isinstance(agent_info, dict):
                    raw_g = agent_info.get('group')
                    if raw_g:
                        candidate_groups.extend(raw_g if isinstance(raw_g, list) else [raw_g])

                for g in candidate_groups:
                    if search_term in str(g).lower():
                        found = True
                        break

            if tag == 'ports':
                for port in m.get('ports', []):
                    if search_term == str(port.get('local', {}).get('port', '')):
                        found = True
                        break

            elif tag == 'agent_info':
                if (search_term in m.get('hostname', '').lower() or
                    search_term in m.get('ip_address', '').lower() or
                    search_term in m.get('id', '').lower() or
                        search_term in m.get('group', '').lower()):
                    found = True
                elif sub_tag == 'status':
                    status_map = {'active': 'ativo', 'disconnected': 'inativo'}
                    if status_map.get(search_term) == m.get('device_status', '').lower():
                        found = True

            elif tag == 'inventory' and sub_tag:
                if sub_tag == 'os':
                    if any(search_term in str(m.get(k, '')).lower() for k in ['os_name', 'os_version', 'os_architecture', 'os_kernel', 'os_platform']):
                        found = True
                elif sub_tag == 'hardware':
                    if (search_term in m.get('cpu_name', '').lower() or
                        search_term in str(m.get('cpu_cores', '')) or
                            search_term in m.get('board_serial', '').lower()):
                        found = True
                elif sub_tag == 'packages':
                    for pkg in m.get('packages', []):
                        if search_term in pkg.get('name', '').lower() or search_term in pkg.get('version', '').lower():
                            found = True
                            break
                elif sub_tag == 'processes':
                    for proc in m.get('processes', []):
                        if search_term in proc.get('name', '').lower() or search_term in str(proc.get('pid', '')):
                            found = True
                            break

            if found:
                results.append(m)
                added_hostnames.add(hostname)

    else:
        for m in machines:
            hostname = m.get('hostname', '')
            if hostname in added_hostnames:
                continue

            if any(query in str(m.get(k, '')).lower() for k in ['hostname', 'ip_address', 'os_name', 'cpu_name', 'device_status', 'ram_gb']):
                results.append(m)
                added_hostnames.add(hostname)
                continue

            found_in_sub = False
            for iface in m.get('netiface', []):
                if query in iface.get('name', '').lower() or query in iface.get('mac', '').lower():
                    found_in_sub = True
                    break
            if not found_in_sub:
                for addr in m.get('netaddr', []):
                    if query in addr.get('address', '').lower():
                        found_in_sub = True
                        break
            if not found_in_sub:
                for port in m.get('ports', []):
                    if query in str(port.get('local', {}).get('port', '')) or query in port.get('process', '').lower():
                        found_in_sub = True
                        break
            if not found_in_sub:
                for pkg in m.get('packages', []):
                    if query in pkg.get('name', '').lower() or query in pkg.get('description', '').lower():
                        found_in_sub = True
                        break

            if found_in_sub:
                results.append(m)
                added_hostnames.add(hostname)

    return render_template('search.html', results=results, query=query)

def _find_machine(machines, hostname):

    if not hostname:
        return None
    target = str(hostname).strip()
    low = target.lower()
    first_label = low.split('.', 1)[0]

    for m in machines:
        if m.get('hostname') == target:
            return m
    for m in machines:
        h = str(m.get('hostname') or '').strip().lower()
        if h == low:
            return m
    for m in machines:
        h = str(m.get('hostname') or '').strip().lower()
        if h.split('.', 1)[0] == first_label:
            return m
    return None

def machine_details(hostname):
    if 'username' not in session:
        return redirect(url_for('login'))

    if not hostname.replace('.', '').replace('-', '').isalnum():
        flash('Nome de host inválido', 'error')
        return redirect(url_for('painel'))

    machines = get_cached_machines()
    machine = _find_machine(machines, hostname)

    if not machine:
        machine = get_machine_fallback(hostname)

    if not machine:
        flash('Máquina não encontrada', 'error')
        return redirect(url_for('painel'))

    return render_template('machine_details.html', machine=machine)
