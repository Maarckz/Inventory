def process_machine_data(raw_data):
    if not raw_data:
        return None
        
    if 'agent_info' in raw_data:
        processed = {
            'hostname': raw_data['agent_info'].get('name', 'N/A'),
            'ip_address': raw_data['agent_info'].get('ip', 'N/A'),
            'device_status': 'Ativo' if raw_data['agent_info'].get('status') == 'active' else 'Inativo',
            'last_seen': raw_data['agent_info'].get('lastKeepAlive', 'N/A'),
            'id': raw_data['agent_info'].get('id', 'N/A'),
            'groups': raw_data.get('groups', []),
        }
    else:
        hostname = raw_data.get('hostname') or raw_data.get('inventory', {}).get('os', [{}])[0].get('hostname', 'N/A')
        processed = {
            'hostname': hostname,
            'ip_address': raw_data.get('ip_address', 'N/A'),
            'device_status': raw_data.get('device_status', 'Desconhecido'),
            'last_seen': raw_data.get('last_seen', 'N/A'),
            'id': raw_data.get('id', 'N/A'),
            'groups': raw_data.get('groups', []),
        }
    
    if raw_data.get('inventory', {}).get('hardware'):
        hardware = raw_data['inventory']['hardware'][0]
        processed['cpu_name'] = hardware.get('cpu', {}).get('name', 'Unknown')
        processed['cpu_cores'] = hardware.get('cpu', {}).get('cores', 'N/A')
        
        ram_total = hardware.get('ram', {}).get('total', 0)
        processed['ram_total'] = round(ram_total / (1024 * 1024), 2) if ram_total else 0
        processed['ram_gb'] = round(ram_total / (1024 * 1024)) if ram_total else 0
        processed['ram_usage'] = hardware.get('ram', {}).get('usage', 'N/A')
        processed['board_serial'] = hardware.get('board_serial', 'N/A')
    
    if raw_data.get('inventory', {}).get('os'):
        os_info = raw_data['inventory']['os'][0]
        processed['os_sysname'] = os_info.get('sysname', 'N/A')
        processed['os_name'] = os_info.get('os', {}).get('name', 'Unknown')
        processed['os_version'] = os_info.get('os', {}).get('version', 'N/A')
        processed['os_codename'] = os_info.get('os', {}).get('codename', '')
        processed['os_platform'] = os_info.get('os', {}).get('platform', 'N/A')
        processed['os_architecture'] = os_info.get('architecture', 'N/A')
        processed['os_full'] = f"{processed['os_name']} {processed['os_version']} ({processed['os_codename']})"
        processed['os_kernel'] = os_info.get('release', os_info.get('os_release', 'N/A'))
    
    processed['netiface'] = []
    if raw_data.get('inventory', {}).get('netiface'):
        for iface in raw_data['inventory']['netiface']:
            processed['netiface'].append({
                'name': iface.get('name', 'N/A'),
                'mac': iface.get('mac', 'N/A'),
                'state': iface.get('state', 'N/A'),
                'mtu': iface.get('mtu', 'N/A'),
                'type': iface.get('type', 'N/A')
            })
    
    processed['ports'] = []
    if raw_data.get('inventory', {}).get('ports'):
        for port in raw_data['inventory']['ports']:
            processed['ports'].append({
                'local': {
                    'port': port.get('local', {}).get('port', 'N/A'),
                    'ip': port.get('local', {}).get('ip', 'N/A')
                },
                'process': port.get('process', 'N/A'),
                'pid': port.get('pid', 'N/A'),
                'state': port.get('state', 'N/A'),
                'protocol': port.get('protocol', 'N/A')
            })
    
    processed['netaddr'] = []
    if raw_data.get('inventory', {}).get('netaddr'):
        for addr in raw_data['inventory']['netaddr']:
            processed['netaddr'].append({
                'iface': addr.get('iface', 'N/A'),
                'address': addr.get('address', 'N/A'),
                'netmask': addr.get('netmask', 'N/A'),
                'proto': addr.get('proto', 'N/A'),
                'broadcast': addr.get('broadcast', 'N/A')
            })
    processed['packages'] = []
    if raw_data.get('inventory', {}).get('packages'):
        for pkg in raw_data['inventory']['packages']:
            processed['packages'].append({
                'name': pkg.get('name', 'N/A'),
                'version': pkg.get('version', 'N/A'),
                'description': pkg.get('description', 'N/A'),
                'install_time': pkg.get('install_time', 'N/A'),
                'architecture': pkg.get('architecture', 'N/A'),
                'format': pkg.get('format', 'N/A')
            })

    processed['processes'] = []
    if raw_data.get('inventory', {}).get('processes'):
        for proc in raw_data['inventory']['processes']:
            processed['processes'].append({
                'pid': proc.get('pid', 'N/A'),
                'name': proc.get('name', 'N/A'),
                'state': proc.get('state', 'N/A'),
                'euser': proc.get('euser', 'N/A'),
                'cmd': proc.get('cmd', 'N/A')
            })
    
    return processed

def get_machine_fallback(hostname):
    from models import HostInventory
    h = HostInventory.query.filter_by(hostname=hostname).first()
    if h:
        machine = process_machine_data(h.data)
        if machine:
            machine['is_legacy'] = h.is_legacy
        return machine
    return None
