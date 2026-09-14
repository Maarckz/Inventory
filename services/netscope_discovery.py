
import socket
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

from services.netscope_core import guess_vendor, load_config, save_config, store

def read_arp_table():

    entries = {}
    proc = Path('/proc/net/arp')
    if proc.exists():
        try:
            with open(proc) as f:
                for line in f.readlines()[1:]:
                    parts = line.strip().split()
                    if len(parts) >= 4 and parts[3] not in ('00:00:00:00:00:00', ''):
                        entries[parts[0]] = parts[3].lower()
        except (IOError, IndexError, OSError):
            pass
    if not entries:
        import subprocess
        try:
            r = subprocess.run(['ip', 'neigh', 'show'], capture_output=True,
                               text=True, timeout=5)
            import re
            for line in r.stdout.splitlines():
                m = re.match(r'(\S+) .* lladdr ([0-9a-fA-F:]+)', line)
                if m and m.group(2) != '00:00:00:00:00:00':
                    entries[m.group(1)] = m.group(2).lower()
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass
    return entries

def get_default_iface():

    try:
        with open('/proc/net/route') as f:
            for line in f.readlines()[1:]:
                parts = line.strip().split()
                if len(parts) > 1 and parts[1] == '00000000':
                    return parts[0]
    except (IOError, OSError):
        pass
    return None

def get_iface_info(iface):

    mac = ''
    try:
        p = Path('/sys/class/net') / str(iface) / 'address'
        if p.exists():
            mac = p.read_text().strip().lower()
    except (IOError, OSError):
        pass
    ip = ''
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            ip = socket.inet_ntoa(s.ioctl(
                0x8915,
                struct.pack('256s', str(iface)[:15].encode('utf-8'))
            )[20:24])
        finally:
            s.close()
    except (OSError, struct.error, IndexError, AttributeError):
        pass
    return ip, mac

def _in_subnet(ip, prefix):
    value = str(prefix)
    try:
        import ipaddress
        net = ipaddress.IPv4Network(
            value if '/' in value else value + '.0/24', strict=False)
        return ipaddress.IPv4Address(str(ip)) in net
    except (ValueError, TypeError):
        # Fallback: comparação textual (comportamento antigo)
        return str(ip).startswith(str(prefix) + '.')

def list_ifaces():

    try:
        return sorted(p.name for p in Path('/sys/class/net').iterdir())
    except (OSError, AttributeError):
        return []

def find_iface_for_subnet(prefix):

    """Escolhe a interface cujo IP pertence à sub-rede alvo (servidores
    multihomed têm mais de uma NIC; a rota padrão nem sempre é a certa)."""

    default = get_default_iface()
    candidates = []
    for iface in list_ifaces():
        try:
            ip, _mac = get_iface_info(iface)
        except Exception:
            continue
        if ip and _in_subnet(ip, prefix):
            candidates.append(iface)
    if not candidates:
        return None
    if default in candidates:
        return default
    return candidates[0]

ETH_BROADCAST = 'ff:ff:ff:ff:ff:ff'

def build_arp_request(src_mac, src_ip, target_ip):

    smac = bytes.fromhex(src_mac.replace(':', ''))
    eth = bytes.fromhex(ETH_BROADCAST.replace(':', '')) + smac + \
        struct.pack('!H', 0x0806)
    arp = struct.pack('!HHBBH', 1, 0x0800, 6, 4, 1)
    arp += smac
    arp += socket.inet_aton(src_ip)
    arp += b'\x00' * 6
    arp += socket.inet_aton(target_ip)
    return eth + arp

def parse_arp_reply(frame):

    try:
        if len(frame) < 42:
            return None
        ethertype = struct.unpack('!H', frame[12:14])[0]
        if ethertype != 0x0806:
            return None
        arp = frame[14:42]
        htype, ptype, hlen, plen, op = struct.unpack('!HHBBH', arp[:8])
        if op != 2 or ptype != 0x0800 or hlen != 6 or plen != 4:
            return None
        sha = arp[8:14]
        spa = arp[14:18]
        return ':'.join(f'{b:02x}' for b in sha), socket.inet_ntoa(spa)
    except (struct.error, OSError, ValueError):
        return None

def raw_arp_sweep(iface, ips, timeout=1.5):

    src_ip, src_mac = get_iface_info(iface)
    if not src_mac or len(src_mac) != 17:
        raise OSError(f'Interface {iface} sem MAC utilizável')
    if not src_ip:
        raise OSError(f'Interface {iface} sem IPv4')
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                         socket.htons(0x0806))
    try:
        sock.bind((iface, 0x0806))
        sock.settimeout(0.2)
        target_set = set(ips)
        for ip in ips:
            try:
                sock.send(build_arp_request(src_mac, src_ip, ip))
            except OSError:
                break
        found = {}
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data = sock.recv(2048)
            except socket.timeout:
                continue
            except OSError:
                break
            parsed = parse_arp_reply(data)
            if not parsed:
                continue
            mac, ip = parsed
            if mac == src_mac or ip not in target_set:
                continue
            found[ip] = mac
        return found
    finally:
        try:
            sock.close()
        except OSError:
            pass

UDP_TRIGGER_PORT = 9

def udp_arp_trigger(ips, settle=2.0):

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except OSError:
        return
    try:
        for ip in ips:
            try:
                s.sendto(b'\x00', (ip, UDP_TRIGGER_PORT))
            except OSError:
                continue
    finally:
        try:
            s.close()
        except OSError:
            pass
    if settle > 0:
        time.sleep(settle)

def arp_discover_subnet(subnet, networks=None, exclude=(),
                        timeout=1.5, settle=2.0):

    prefix = str(subnet)
    excl = set(exclude or ())
    target = [f'{prefix}.{i}' for i in range(1, 255)]
    ips = [ip for ip in target if ip not in excl]
    if not ips:
        return {}, 'nenhum'
    iface = find_iface_for_subnet(prefix)
    if not iface:
        return {}, 'indisponivel'
    try:
        return raw_arp_sweep(iface, ips, timeout=timeout), 'arp-raw'
    except (PermissionError, OSError):
        pass
    # Sem acesso a socket raw (ex.: serviço sem CAP_NET_RAW): dispara
    # tráfego UDP para provocar respostas ARP e coleta a tabela do kernel
    # de forma paciente (vários ciclos), em vez de uma única leitura.
    udp_arp_trigger(ips, settle=0)
    target_set = set(ips)
    found = {}
    for _ in range(4):
        time.sleep(max(0.75, settle / 2.0))
        table = read_arp_table()
        for ip, mac in table.items():
            if ip in target_set and mac:
                found[ip] = mac
        if len(found) >= len(target_set):
            break
    return found, 'arp-udp' if found else 'arp-udp-vazio'

ARP_INTERVAL_MIN = 5
ARP_INTERVAL_MAX = 360

DNS_RERESOLVE_MIN = 360

def clamp_interval(value):

    try:
        v = int(float(value))
    except (TypeError, ValueError):
        return ARP_INTERVAL_MIN
    return max(ARP_INTERVAL_MIN, min(ARP_INTERVAL_MAX, v))

_monitor_state = {
    'thread_alive': False,
    'last_run': None,
    'last_new': 0,
    'last_total': 0,
    'method': '',
    'last_error': '',
    'last_dns_refresh': 0.0,
    'lock': threading.Lock(),
}
_monitor_stop = threading.Event()
_monitor_wake = threading.Event()
_app_ref = None
_pass_lock = threading.Lock()

def wake_monitor():

    _monitor_wake.set()

def _resolve_dns_safe(ip):

    try:
        from services.netscope_engine import _resolve_dns
        return _resolve_dns(ip)
    except Exception:
        return ''

def _dns_refresh_known(app, force=False):

    now = time.time()
    with _monitor_state['lock']:
        last = _monitor_state.get('last_dns_refresh') or 0.0
        if not force and (now - last) < DNS_RERESOLVE_MIN * 60:
            return 0
        _monitor_state['last_dns_refresh'] = now
    try:
        devices = [d for d in (store._cache['devices'] or [])
                   if not d.get('deleted') and d.get('ip') and d.get('mac')]
    except Exception:
        return 0
    if not devices:
        return 0
    from services.netscope_engine import _resolve_dns
    results = {}
    try:
        with ThreadPoolExecutor(max_workers=16) as pool:
            futs = {pool.submit(_resolve_dns, d['ip']): d for d in devices}
            for fut in as_completed(futs, timeout=180):
                d = futs[fut]
                try:
                    results[d['mac']] = fut.result(timeout=3) or ''
                except Exception:
                    pass
    except Exception:
        pass
    try:
        changed = store.apply_dns_refresh(results)
    except Exception:
        return 0
    if changed:
        try:
            app.logger.info(
                f'[NetScope] DNS refresh: {changed} nome(s) de host '
                f'atualizado(s) pela re-resolução periódica.')
        except Exception:
            pass
    return changed

def _monitor_pass(app, networks):

    if not _pass_lock.acquire(blocking=False):
        return
    try:
        _monitor_pass_body(app, networks)
    finally:
        _pass_lock.release()

def _monitor_pass_body(app, networks):

    new_count = 0
    seen = 0
    method = ''
    for net in networks:
        subnet = net['subnet']
        found, m = arp_discover_subnet(subnet, networks)
        if str(m).startswith('arp-'):
            method = m
        seen += len(found)
        for ip, mac in found.items():
            info = {'ip': ip, 'vendor': guess_vendor(mac), 'subnet': subnet,
                    'gateway': net.get('gateway', ''), 'discovery': 'arp',
                    'source': 'monitor'}
            known = store.find(mac, include_deleted=False)
            if not known:
                # Host novo: resolve DNS antes de cadastrar
                dns = _resolve_dns_safe(ip)
                if dns:
                    info['dns_name'] = dns
            # Conhecido ou novo: upsert atualiza ip/status/last_seen —
            # uma resposta ARP prova que o host está vivo (antes o monitor
            # ignorava hosts já cadastrados e eles ficavam offline/velhos
            # até o próximo ping sweep).
            if store.upsert_scan_result(mac, info, flush=False):
                new_count += 1
    if seen or new_count:
        try:
            with store._lock:
                store._flush()
        except Exception:
            pass
    with _monitor_state['lock']:
        _monitor_state.update({'last_run': datetime.now().isoformat(),
                               'last_new': new_count, 'last_total': seen,
                               'method': method, 'last_error': ''})
    if new_count:
        try:
            app.logger.info(
                f'[NetScope] Monitor ARP: {new_count} novo(s) host(s) '
                f'descoberto(s) via {method} (sem ping).')
        except Exception:
            pass
    try:
        _dns_refresh_known(app)
    except Exception:
        pass

def _monitor_loop(app):

    while not _monitor_stop.is_set():
        try:
            try:
                with app.app_context():
                    cfg = load_config()
            except Exception:
                if _monitor_wake.wait(30):
                    _monitor_wake.clear()
                continue
            mon = cfg.get('arp_monitor') if isinstance(cfg.get('arp_monitor'), dict) else {}
            networks = cfg.get('networks', []) or []
            if not mon.get('enabled') or not networks:
                if _monitor_wake.wait():
                    _monitor_wake.clear()
                continue
            try:
                interval = clamp_interval(mon.get('interval_minutes', ARP_INTERVAL_MIN)) * 60
            except (TypeError, ValueError):
                interval = 300
            if _monitor_wake.wait(interval):
                _monitor_wake.clear()
                continue
            if _monitor_stop.is_set():
                break
            _monitor_pass(app, networks)
        except Exception as e:
            with _monitor_state['lock']:
                _monitor_state['last_error'] = str(e)
            if _monitor_wake.wait(30):
                _monitor_wake.clear()

def start_arp_monitor(app):

    global _app_ref
    with _monitor_state['lock']:
        if _monitor_state['thread_alive']:
            return None
        _monitor_state['thread_alive'] = True
    _app_ref = app
    t = threading.Thread(target=_monitor_loop, args=(app,), daemon=True)
    t.start()
    return t

def monitor_status():

    with _monitor_state['lock']:
        st = {k: v for k, v in _monitor_state.items() if k != 'lock'}
    enabled = None
    interval = ARP_INTERVAL_MIN
    try:
        cfg = load_config()
        mon = cfg.get('arp_monitor') or {}
        enabled = bool(mon.get('enabled'))
        interval = clamp_interval(mon.get('interval_minutes', ARP_INTERVAL_MIN))
    except Exception:
        pass
    st['enabled'] = bool(enabled)
    st['interval_minutes'] = interval
    st['running'] = bool(st.get('thread_alive')) and bool(enabled)
    st.pop('thread_alive', None)
    return st

def set_monitor_enabled(enabled=None, interval_minutes=None):

    cfg = load_config()
    mon = cfg.get('arp_monitor') if isinstance(cfg.get('arp_monitor'), dict) else {}
    if enabled is not None:
        mon['enabled'] = bool(enabled)
    if interval_minutes is not None:
        mon['interval_minutes'] = clamp_interval(interval_minutes)
    if 'enabled' not in mon:
        mon['enabled'] = True
    if 'interval_minutes' not in mon:
        mon['interval_minutes'] = ARP_INTERVAL_MIN
    cfg['arp_monitor'] = mon
    try:
        save_config(cfg)
    except Exception:
        pass
    with _monitor_state['lock']:
        _monitor_state['enabled'] = bool(mon['enabled'])
    _monitor_wake.set()
    return monitor_status()

def run_manual_pass(app):

    try:
        cfg = load_config()
        networks = cfg.get('networks') or []
    except Exception:
        networks = []
    if not networks:
        return None
    _monitor_pass(app, networks)
    with _monitor_state['lock']:
        return {k: v for k, v in _monitor_state.items() if k != 'lock'}
