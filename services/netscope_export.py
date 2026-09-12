
import csv
import io
from datetime import datetime

from services.netscope_core import store

def export_assets_csv():
    out = io.StringIO()
    writer = csv.writer(out, delimiter=';')
    writer.writerow([
        'MAC', 'IP', 'Hostname', 'DNS', 'Tipo', 'Fabricante', 'Modelo', 'Subnet',
        'Status', 'Agente Wazuh', 'ID Agente', 'Status Agente', 'Ultimo KeepAlive',
        'Usuario', 'Departamento', 'Local', 'Asset Tag',
        'Serial', 'OS', 'Numero de Lacre',
        'Switch', 'Porta', 'VLAN', 'Velocidade', 'Duplex',
        'Pai (MAC)', 'Notas', 'Primeira Vez', 'Ultima Vez'
    ])
    for d in store.active():
        sp = d.get('switch_port') or {}
        sw_dev = store.find(sp.get('switch_mac', '')) if sp.get('switch_mac') else None
        sw_name = sw_dev.get('hostname') or sw_dev.get('ip', '') if sw_dev else ''
        writer.writerow([
            d.get('mac', ''), d.get('ip', ''), d.get('hostname', ''),
            d.get('dns_name', ''), d.get('type', ''), d.get('vendor', ''),
            d.get('model', ''),
            d.get('subnet', ''), d.get('status', ''),
            'Sim' if d.get('has_agent') else 'Nao',
            d.get('agent_id', ''), d.get('agent_status', ''),
            (d.get('agent_last_keepalive', '') or '')[:19].replace('T', ' '),
            d.get('user', ''), d.get('department', ''), d.get('location', ''),
            d.get('asset_tag', ''), d.get('serial_number', ''),
            d.get('os', ''), d.get('seal_number', ''),
            sw_name, sp.get('port', ''), sp.get('vlan', ''),
            sp.get('speed', ''), sp.get('duplex', ''),
            d.get('parent_id', ''), d.get('notes', ''),
            d.get('first_seen', '')[:19].replace('T', ' '),
            d.get('last_seen', '')[:19].replace('T', ' '),
        ])
    return out.getvalue()

def export_full_json():
    from services.netscope_switches import get_switches_with_ports
    from services.netscope_core import load_config
    data = {
        'exported_at': datetime.now().isoformat(),
        'devices': store.active(),
        'switches': get_switches_with_ports(),
        'config': load_config(),
    }
    return data
