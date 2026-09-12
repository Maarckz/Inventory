
import re
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

from services.netscope_core import (store, guess_vendor, load_config,
                                    save_config, _plausible_hostname)
from services.netscope_discovery import arp_discover_subnet, read_arp_table, clamp_interval
from services.netscope_snapshots import get_instance

AUTO_SCAN_INTERVAL_MIN = 5
AUTO_SCAN_INTERVAL_MAX = 360

_scan_state = {'running': False, 'result': None, 'lock': threading.Lock()}
_auto_scan_event = threading.Event()
_auto_wake = threading.Event()
_app_ref = None

def wake_auto_scan():

    _auto_wake.set()

def _ping_host(ip, timeout):
    try:
        r = subprocess.run(
            ['ping', '-c', '1', '-W', str(timeout), ip],
            capture_output=True, text=True, timeout=timeout + 2
        )
        if r.returncode == 0:
            ttl_m = re.search(r'ttl=(\d+)', r.stdout, re.IGNORECASE)
            return True, int(ttl_m.group(1)) if ttl_m else None
        return False, None
    except (subprocess.TimeoutExpired, OSError):
        return False, None

def _resolve_dns(ip, timeout=2.5):
    try:
        result = socket.gethostbyaddr(ip)
        if result and result[0] and _plausible_hostname(result[0], ip):
            return result[0]
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        pass
    try:
        r = subprocess.run(['getent', 'hosts', ip], capture_output=True, text=True, timeout=timeout)
        if r.returncode == 0 and r.stdout.strip():
            parts = r.stdout.strip().split()
            if len(parts) >= 2 and _plausible_hostname(parts[1], ip):
                return parts[1]
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    try:
        hosts = Path('/etc/hosts')
        if hosts.exists():
            for line in hosts.read_text().splitlines():
                line = line.split('#')[0].strip()
                if not line:
                    continue
                parts = line.split()
                if (len(parts) >= 2 and parts[0] == ip
                        and _plausible_hostname(parts[1], ip)):
                    return parts[1]
    except (IOError, OSError):
        pass
    return ''

def scan_tcp_ports(dev_ip, port_map, port_timeout):
    open_ports = []
    for p_str in port_map:
        port = int(p_str)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(port_timeout)
            if sock.connect_ex((dev_ip, port)) == 0:
                open_ports.append(port)
            sock.close()
        except OSError:
            pass
    return open_ports

def run_scan(app, networks, scan_cfg, auto_snapshot=False):

    global _scan_state
    with app.app_context():
        _run_scan_inner(networks, scan_cfg, auto_snapshot)

def _auto_wazuh_sync():

    try:
        from flask import current_app
        app = current_app._get_current_object()
        from services.netscope_wazuh_bridge import sync_from_inventory
        stats = sync_from_inventory(app)
        app.logger.info(
            "[NetScope] Ponte Wazuh automática pós-scan: "
            "{hosts} hosts, {matched} casados, {created} criados, "
            "{merged} duplicatas mescladas.".format(**stats))
        return stats
    except Exception as e:
        try:
            from flask import current_app
            current_app.logger.error(
                f"[NetScope] Ponte Wazuh automática pós-scan falhou: {e}")
        except Exception:
            pass
        return None

def _run_scan_inner(networks, scan_cfg, auto_snapshot=False):
    global _scan_state
    timeout = scan_cfg.get('timeout', 1)
    workers = scan_cfg.get('workers', 64)
    all_found = {}
    ttl_map = {}
    errors = []

    for net in networks:
        subnet = net['subnet']
        gw = net.get('gateway', '')
        ips = [f'{subnet}.{i}' for i in range(1, 255)]
        reachable = set()
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(_ping_host, ip, timeout): ip for ip in ips}
            for fut in as_completed(futures, timeout=timeout * 255 + 15):
                ip = futures[fut]
                try:
                    ok, ttl = fut.result()
                    if ok:
                        reachable.add(ip)
                        if ttl:
                            ttl_map[ip] = ttl
                except Exception:
                    pass

        time.sleep(0.5)
        arp = read_arp_table()

        try:
            arp_extra, _arp_method = arp_discover_subnet(
                subnet, networks, exclude=reachable)
        except Exception:
            arp_extra, _arp_method = {}, 'erro'
        for ip, mac in arp.items():
            if ip.startswith(subnet + '.') and ip not in reachable:
                arp_extra.setdefault(ip, mac)

        for ip, mac in arp.items():
            if ip.startswith(subnet + '.') and ip in reachable:
                all_found[mac] = {
                    'ip': ip, 'vendor': guess_vendor(mac),
                    'subnet': subnet, 'gateway': gw,
                    'ttl': ttl_map.get(ip), 'discovery': 'ping',
                }
        for ip, mac in arp_extra.items():
            if not mac or ip in reachable or mac in all_found:
                continue
            all_found[mac] = {
                'ip': ip, 'vendor': guess_vendor(mac),
                'subnet': subnet, 'gateway': gw,
                'ttl': None, 'discovery': 'arp',
            }

    if all_found:
        dns_results = {}
        with ThreadPoolExecutor(max_workers=32) as pool:
            dns_futs = {pool.submit(_resolve_dns, info['ip']): mac for mac, info in all_found.items()}
            for fut in as_completed(dns_futs, timeout=90):
                mac = dns_futs[fut]
                try:
                    dns_results[mac] = fut.result(timeout=3)
                except Exception:
                    dns_results[mac] = ''

        new_count = 0
        found_macs = set()
        for mac, info in all_found.items():
            info['dns_name'] = dns_results.get(mac, '')
            if store.upsert_scan_result(mac, info, flush=False):
                new_count += 1
            found_macs.add(mac)

        store.mark_offline(found_macs)
    else:
        store.mark_offline(set())
        new_count = 0

    wazuh_stats = _auto_wazuh_sync()

    try:
        from flask import current_app as _ca
        from services.notifications import evaluate_all
        _r = evaluate_all(_ca._get_current_object())
        if _r.get('created'):
            try:
                _ca.logger.info(
                    f"[Notificações] pós-scan: {_r['created']} novo(s) "
                    f"alerta(s) — {_r['rules']}")
            except Exception:
                pass
    except Exception:
        pass

    if auto_snapshot and (all_found or new_count):
        try:
            get_instance().create_snapshot(
                f'Auto-scan {datetime.now().strftime("%d/%m/%Y %H:%M")}',
                'Snapshot automático pós-scan', auto=True
            )
        except Exception:
            pass

    with _scan_state['lock']:
        _scan_state['result'] = {
            'scanned': len(networks), 'new': new_count,
            'total': len(all_found), 'errors': errors,
            'arp_found': sum(1 for i in all_found.values()
                             if i.get('discovery') == 'arp'),
            'wazuh_synced': wazuh_stats is not None,
        }
        _scan_state['running'] = False

def scan_status():
    with _scan_state['lock']:
        if _scan_state['running']:
            return {'status': 'scanning'}
        elif _scan_state['result']:
            r = _scan_state['result'].copy()
            _scan_state['result'] = None
            return r
        return {'status': 'idle'}

def start_scan(auto_snapshot=False):

    from flask import current_app
    try:
        app = current_app._get_current_object()
    except RuntimeError:
        app = _app_ref
    with _scan_state['lock']:
        if _scan_state['running']:
            return False, {'error': 'Scan já em andamento',
                           'reason': 'already_running'}, 409
        cfg = load_config()
        networks = cfg.get('networks', [])
        if not networks:
            return False, {'error': 'Nenhuma rede configurada'}, 400
        _scan_state['running'] = True
        _scan_state['result'] = None
    scan_cfg = cfg.get('scan', {})
    t = threading.Thread(target=run_scan, args=(app, networks, scan_cfg),
                         kwargs={'auto_snapshot': auto_snapshot}, daemon=True)
    t.start()
    return True, {'status': 'scanning', 'subnets': len(networks)}, 200

def _auto_scan_loop(app):

    while not _auto_scan_event.is_set():
        try:
            try:
                with app.app_context():
                    cfg = load_config()
            except Exception:
                if _auto_wake.wait(30):
                    _auto_wake.clear()
                continue
            auto = cfg.get('auto_scan') if isinstance(cfg.get('auto_scan'), dict) else {}
            if not auto.get('enabled') or not (cfg.get('networks') or []):
                if _auto_wake.wait():
                    _auto_wake.clear()
                continue
            try:
                interval = clamp_interval(auto.get('interval_minutes',
                                                   AUTO_SCAN_INTERVAL_MIN)) * 60
            except (TypeError, ValueError):
                interval = 300
            if _auto_wake.wait(interval):
                _auto_wake.clear()
                continue
            if _auto_scan_event.is_set():
                break
            with _scan_state['lock']:
                if _scan_state['running']:
                    continue
                networks = cfg.get('networks', []) or []
                if not networks:
                    continue
                _scan_state['running'] = True
                _scan_state['result'] = None
            scan_cfg = cfg.get('scan', {})
            try:
                run_scan(app, networks, scan_cfg, auto_snapshot=True)
            except Exception:
                with _scan_state['lock']:
                    _scan_state['running'] = False
        except Exception as e:
            try:
                app.logger.error(f"[NetScope] Ping sweep automático: erro no ciclo: {e}")
            except Exception:
                pass
            if _auto_wake.wait(30):
                _auto_wake.clear()

def set_auto_scan(enabled=None, interval_minutes=None):

    cfg = load_config()
    auto = cfg.get('auto_scan') if isinstance(cfg.get('auto_scan'), dict) else {}
    if enabled is not None:
        auto['enabled'] = bool(enabled)
    if interval_minutes is not None:
        auto['interval_minutes'] = clamp_interval(interval_minutes)
    if 'enabled' not in auto:
        auto['enabled'] = False
    if 'interval_minutes' not in auto:
        auto['interval_minutes'] = AUTO_SCAN_INTERVAL_MIN
    cfg['auto_scan'] = auto
    try:
        save_config(cfg)
    except Exception:
        pass
    _auto_wake.set()
    return {'enabled': bool(auto['enabled']),
            'interval_minutes': auto['interval_minutes']}

def start_auto_scan_thread(app):
    global _app_ref
    _app_ref = app
    t = threading.Thread(target=_auto_scan_loop, args=(app,), daemon=True)
    t.start()
    return t
