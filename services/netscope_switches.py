
from services.netscope_core import store, load_config, save_config, dev_key

def get_switches_with_ports():

    cfg = load_config()
    sws = cfg.get('switches', {})
    result = []
    for d in store.active():
        if d.get('type') != 'switch':
            continue
        sw_key = dev_key(d)
        sw_cfg = sws.get(sw_key, {})
        port_count = sw_cfg.get('port_count', 24)
        ports = sw_cfg.get('ports', {})
        port_list = []
        for i in range(1, port_count + 1):
            p = ports.get(str(i), {})
            dev_key_ref = p.get('device_mac', '')
            dev = store.find(dev_key_ref) if dev_key_ref else None
            port_list.append({
                'port': i,
                'label': p.get('label', f'Fa0/{i}'),
                'device_mac': dev_key_ref,
                'device_name': dev.get('hostname') or dev.get('name') or dev.get('ip', '') if dev else '',
                'device_ip': dev.get('ip', '') if dev else '',
                'vlan': p.get('vlan', ''),
                'speed': p.get('speed', ''),
                'duplex': p.get('duplex', ''),
                'notes': p.get('notes', ''),
            })
        result.append({
            'mac': sw_key,
            'ip': d['ip'],
            'hostname': d.get('hostname', ''),
            'name': d.get('name', ''),
            'port_count': port_count,
            'ports': port_list,
        })
    return result

def update_switch_config(switch_mac, port_count=None, ports=None):
    cfg = load_config()
    sws = cfg.get('switches', {})
    sw = sws.get(switch_mac, {'port_count': 24, 'ports': {}})
    if port_count is not None:
        sw['port_count'] = max(1, int(port_count))
    if ports is not None and isinstance(ports, dict):
        sw['ports'] = {}
        for p_str, p_info in ports.items():
            sw['ports'][str(p_str)] = {
                'label': p_info.get('label', ''),
                'vlan': p_info.get('vlan', ''),
                'speed': p_info.get('speed', ''),
                'duplex': p_info.get('duplex', ''),
                'device_mac': p_info.get('device_mac', '').lower(),
                'notes': p_info.get('notes', ''),
            }
        for p_str, p_info in sw['ports'].items():
            dev_mac = p_info['device_mac']
            if dev_mac:
                dev = store.find(dev_mac)
                if dev:
                    dev['switch_port'] = {
                        'switch_mac': switch_mac.lower(),
                        'port': int(p_str),
                        'label': p_info['label'],
                        'vlan': p_info['vlan'],
                        'speed': p_info['speed'],
                        'duplex': p_info['duplex'],
                    }
        for d in store.active():
            sp = d.get('switch_port')
            if sp and sp.get('switch_mac', '').lower() == switch_mac.lower():
                if str(sp.get('port')) not in sw['ports'] or sw['ports'][str(sp.get('port'))].get('device_mac', '').lower() != dev_key(d):
                    d['switch_port'] = None
        with store._lock:
            store._flush()
    sws[switch_mac] = sw
    cfg['switches'] = sws
    save_config(cfg)
    return sw
