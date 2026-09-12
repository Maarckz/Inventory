
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

from services.netscope_core import load_config, store

ALL_PORTS = range(1, 65536)

_FALLBACK_SERVICES = {
    21: ('ftp', 'tcp'), 22: ('ssh', 'tcp'), 23: ('telnet', 'tcp'),
    25: ('smtp', 'tcp'), 53: ('domain', 'both'), 67: ('bootps', 'udp'),
    68: ('bootpc', 'udp'), 69: ('tftp', 'udp'), 80: ('http', 'tcp'),
    88: ('kerberos', 'both'), 110: ('pop3', 'tcp'), 123: ('ntp', 'udp'),
    135: ('msrpc', 'tcp'), 137: ('netbios-ns', 'udp'),
    138: ('netbios-dgm', 'udp'), 139: ('netbios-ssn', 'tcp'),
    143: ('imap', 'tcp'), 161: ('snmp', 'udp'), 162: ('snmptrap', 'udp'),
    389: ('ldap', 'tcp'), 443: ('https', 'tcp'), 445: ('microsoft-ds', 'tcp'),
    465: ('smtps', 'tcp'), 500: ('isakmp', 'udp'), 514: ('syslog', 'udp'),
    515: ('printer', 'tcp'), 548: ('afp', 'tcp'), 554: ('rtsp', 'tcp'),
    587: ('submission', 'tcp'), 631: ('ipp', 'both'), 636: ('ldaps', 'tcp'),
    993: ('imaps', 'tcp'), 995: ('pop3s', 'tcp'), 1080: ('socks', 'tcp'),
    1194: ('openvpn', 'both'), 1433: ('ms-sql-s', 'tcp'),
    1434: ('ms-sql-m', 'udp'), 1521: ('oracle', 'tcp'), 1723: ('pptp', 'tcp'),
    1900: ('ssdp', 'udp'), 2049: ('nfs', 'both'), 3128: ('squid', 'tcp'),
    3306: ('mysql', 'tcp'), 3389: ('ms-wbt-server', 'tcp'),
    4444: ('krb524', 'tcp'), 5060: ('sip', 'both'), 5222: ('xmpp', 'tcp'),
    5353: ('mdns', 'udp'), 5432: ('postgresql', 'tcp'), 5555: ('adb', 'tcp'),
    5666: ('nrpe', 'tcp'), 5900: ('vnc', 'tcp'), 5984: ('couchdb', 'tcp'),
    6379: ('redis', 'tcp'), 6443: ('kubernetes', 'tcp'), 6667: ('irc', 'tcp'),
    8000: ('http-alt', 'tcp'), 8080: ('http-proxy', 'tcp'),
    8443: ('https-alt', 'tcp'), 8888: ('sun-answerbook', 'tcp'),
    9100: ('jetdirect', 'tcp'), 9200: ('elasticsearch', 'tcp'),
    11211: ('memcached', 'both'), 27017: ('mongodb', 'tcp'),
    32400: ('plex', 'tcp'), 49152: ('epmap', 'tcp'),
}

_TCP_NAMES = None
_UDP_NAMES = None

def _load_service_tables():

    tcp, udp = {}, {}
    try:
        for line in Path('/etc/services').read_text().splitlines():
            line = line.split('#')[0].strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            name = parts[0]
            pp = parts[1].split('/')
            if len(pp) != 2:
                continue
            try:
                port = int(pp[0])
            except ValueError:
                continue
            proto = pp[1].lower()
            if proto == 'tcp' and port not in tcp:
                tcp[port] = name
            elif proto == 'udp' and port not in udp:
                udp[port] = name
    except (IOError, OSError):
        pass
    for port, (name, proto) in _FALLBACK_SERVICES.items():
        if proto in ('tcp', 'both') and port not in tcp:
            tcp[port] = name
        if proto in ('udp', 'both') and port not in udp:
            udp[port] = name
    return tcp, udp

def service_name(port, proto='tcp'):
    global _TCP_NAMES, _UDP_NAMES
    if _TCP_NAMES is None:
        _TCP_NAMES, _UDP_NAMES = _load_service_tables()
    table = _TCP_NAMES if proto == 'tcp' else _UDP_NAMES
    return table.get(int(port), '')

def _fd_soft_limit():

    try:
        import resource
        soft, _hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        return int(soft) if soft and soft > 0 else 0
    except Exception:
        return 0

def _fd_worker_cap():

    soft = _fd_soft_limit()
    if not soft:
        return 2048
    usable = max(0, soft - 256)
    cap = usable // max(1, MAX_PARALLEL)
    return max(64, min(2048, cap))

def _tcp_probe(ip, port, timeout, banner=True):

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except OSError:
        return None
    s.settimeout(timeout)
    try:
        if s.connect_ex((ip, port)) != 0:
            return None
        entry = {'port': port, 'name': service_name(port, 'tcp'), 'banner': ''}
        if banner:
            entry['banner'] = _recv_banner(s)
        return entry
    except OSError:
        return None
    finally:
        try:
            s.close()
        except OSError:
            pass

def _recv_banner(sock, timeout=0.4, limit=120):

    try:
        sock.settimeout(timeout)
        data = sock.recv(limit)
        return data.decode('utf-8', 'replace').replace('\n', ' ')[:limit]
    except (socket.timeout, OSError):
        return ''

def scan_tcp(ip, ports=None, workers=512, timeout=0.3, banner=True,
             progress_cb=None):

    if ports is None:
        ports = ALL_PORTS
    ports = list(ports)
    workers = max(16, min(int(workers), _fd_worker_cap()))
    results = []
    done = {'n': 0}
    lock = threading.Lock()

    def _tick():
        with lock:
            done['n'] += 1
            if progress_cb and (done['n'] % 512 == 0 or done['n'] == len(ports)):
                progress_cb(done['n'], len(ports))

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_tcp_probe, ip, p, timeout, banner): p
                   for p in ports}
        for fut in as_completed(futures):
            try:
                entry = fut.result()
            except Exception:
                entry = None
            if entry is not None:
                results.append(entry)
            _tick()
    results.sort(key=lambda r: r['port'])
    return results

_UDP_PROBE = b'\x00'

def _udp_probe(ip, port, timeout, double_probe=False):

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except OSError:
        return 'open|filtered'
    s.settimeout(timeout)
    try:
        try:
            s.connect((ip, port))
            s.send(_UDP_PROBE)
        except OSError:
            return 'open|filtered'
        try:
            s.recvfrom(512)
            return 'open'
        except (ConnectionRefusedError, ConnectionResetError):
            return 'closed'
        except (socket.timeout, TimeoutError):
            if double_probe:
                try:
                    s.send(_UDP_PROBE)
                    s.recvfrom(512)
                    return 'open'
                except (ConnectionRefusedError, ConnectionResetError):
                    return 'closed'
                except (socket.timeout, TimeoutError, OSError):
                    return 'open|filtered'
            return 'open|filtered'
        except OSError:
            return 'open|filtered'
    finally:
        try:
            s.close()
        except OSError:
            pass

def scan_udp(ip, ports=None, workers=512, timeout=0.5, progress_cb=None,
             known_only=True):

    if ports is None:
        ports = ALL_PORTS
    ports = list(ports)
    workers = max(16, min(int(workers), _fd_worker_cap()))
    open_ports, of_ports = [], []
    closed = {'n': 0}
    lock = threading.Lock()
    total = len(ports)
    done = {'n': 0}

    def _tick():
        with lock:
            done['n'] += 1
            if progress_cb and (done['n'] % 1024 == 0 or done['n'] == total):
                progress_cb(done['n'], total)

    with ThreadPoolExecutor(max_workers=max(16, int(workers))) as pool:
        futures = {}
        for p in ports:
            futures[pool.submit(_udp_probe, ip, p, timeout, p <= 1024)] = p
        for fut in as_completed(futures):
            p = futures[fut]
            try:
                state = fut.result()
            except Exception:
                state = 'open|filtered'
            if state == 'open':
                open_ports.append({'port': p, 'name': service_name(p, 'udp'),
                                   'state': 'open'})
            elif state == 'open|filtered':
                if not known_only or service_name(p, 'udp'):
                    of_ports.append({'port': p, 'name': service_name(p, 'udp'),
                                     'state': 'open|filtered'})
            else:
                with lock:
                    closed['n'] += 1
            _tick()
    open_ports.sort(key=lambda r: r['port'])
    of_ports.sort(key=lambda r: r['port'])
    return open_ports, of_ports, closed['n']

MAX_PARALLEL = 3

_jobs = {}
_job_lock = threading.Lock()

def job_status():

    with _job_lock:
        jobs = sorted(_jobs.values(),
                      key=lambda j: j.get('started_at') or '', reverse=True)
        running = sum(1 for j in jobs if j.get('status') == 'running')
        return {'max_parallel': MAX_PARALLEL, 'running': running,
                'jobs': [dict(j) for j in jobs]}

def start_portscan(app, ident):

    dev = store.find(ident)
    if not dev:
        return False, {'error': 'Não encontrado'}, 404
    ip = dev.get('ip') or ''
    if not ip:
        return False, {'error': 'Dispositivo sem IP'}, 400
    uid = dev.get('uid') or ''
    hostname = dev.get('hostname') or ''
    with _job_lock:
        mine = _jobs.get(uid)
        if mine and mine.get('status') == 'running':
            return False, {'error': 'Varredura de portas já em andamento',
                           'same': True, 'mac': uid}, 409
        running = sum(1 for j in _jobs.values()
                      if j.get('status') == 'running')
        if running >= MAX_PARALLEL:
            return False, {
                'error': ('Limite de ' + str(MAX_PARALLEL) +
                          ' varreduras simultâneas — aguarde a conclusão'
                          ' de uma'),
                'reason': 'limit', 'max_parallel': MAX_PARALLEL}, 409
        _jobs[uid] = {
            'status': 'running', 'mac': uid, 'ip': ip,
            'name': dev.get('hostname') or dev.get('vendor') or ip,
            'progress': 0.0, 'phase': 'tcp', 'tcp_found': 0, 'udp_found': 0,
            'tcp': [], 'udp_open': [], 'udp_open_filtered': [],
            'udp_closed': 0, 'duration_s': 0, 'error': '',
            'started_at': datetime.now().isoformat(), 'finished_at': None,
        }
    t = threading.Thread(target=_run_job, args=(app, uid, ip, hostname),
                         daemon=True)
    t.start()
    return True, {'status': 'running', 'mac': uid, 'ip': ip,
                  'max_parallel': MAX_PARALLEL}, 202

def _record_history(app, uid, ip, hostname, started_at, finished_at,
                    duration_s, tcp, open_udp, of_udp, closed_n, error):

    db = None
    try:
        from models import db as _db, NetscopeScanHistory
        db = _db
        with app.app_context():
            db.session.add(NetscopeScanHistory(
                device_uid=uid or '', ip=ip or '',
                hostname=hostname or '',
                status='error' if error else 'done',
                started_at=started_at, finished_at=finished_at,
                duration_s=float(duration_s or 0),
                tcp_count=len(tcp or []),
                udp_count=len(open_udp or []) + len(of_udp or []),
                udp_closed=int(closed_n or 0),
                error=error or '',
                results={'tcp': tcp or [], 'udp_open': open_udp or [],
                         'udp_open_filtered': of_udp or []},
            ))
            db.session.commit()
    except Exception:
        try:
            if db is not None:
                db.session.rollback()
        except Exception:
            pass

def _run_job(app, uid, ip, hostname=''):
    started = time.time()
    started_iso = datetime.now().isoformat()
    try:
        with app.app_context():
            cfg = load_config()
        pscan = cfg.get('port_scan') if isinstance(cfg.get('port_scan'), dict) else {}
        try:
            workers = max(16, int(pscan.get('workers', 512) or 512))
        except (TypeError, ValueError):
            workers = 512
        try:
            tmo = max(0.05, float(pscan.get('tcp_timeout', 0.3) or 0.3))
        except (TypeError, ValueError):
            tmo = 0.3
        try:
            utmo = max(0.05, float(pscan.get('udp_timeout', 0.5) or 0.5))
        except (TypeError, ValueError):
            utmo = 0.5
        want_banner = pscan.get('banner', True) is not False

        def prog_tcp(n, total):
            pct = min(60.0, 60.0 * n / max(1, total))
            with _job_lock:
                if uid in _jobs:
                    _jobs[uid]['progress'] = round(pct, 1)

        def prog_udp(n, total):
            pct = 60.0 + min(40.0, 40.0 * n / max(1, total))
            with _job_lock:
                if uid in _jobs:
                    _jobs[uid]['progress'] = round(pct, 1)

        tcp = scan_tcp(ip, workers=workers, timeout=tmo,
                       banner=want_banner, progress_cb=prog_tcp)
        with _job_lock:
            if uid in _jobs:
                _jobs[uid]['phase'] = 'udp'
        open_udp, of_udp, closed_n = scan_udp(
            ip, workers=workers, timeout=utmo, progress_cb=prog_udp)
        duration = round(time.time() - started, 1)
        finished_iso = datetime.now().isoformat()

        try:
            with app.app_context():
                dev = store.find(uid)
                if dev:
                    dev['open_ports'] = [r['port'] for r in tcp]
                    dev['port_scan'] = {
                        'scanned_at': finished_iso,
                        'started_at': started_iso,
                        'duration_s': duration,
                        'tcp': tcp,
                        'udp_open': open_udp,
                        'udp_open_filtered': of_udp,
                        'udp_closed': closed_n,
                    }
                    with store._lock:
                        store._flush()
        except Exception:
            pass

        _record_history(app, uid=uid, ip=ip, hostname=hostname,
                        started_at=started_iso, finished_at=finished_iso,
                        duration_s=duration, tcp=tcp, open_udp=open_udp,
                        of_udp=of_udp, closed_n=closed_n, error='')

        with _job_lock:
            if uid in _jobs:
                _jobs[uid].update({
                    'status': 'done', 'progress': 100.0,
                    'tcp_found': len(tcp),
                    'udp_found': len(open_udp) + len(of_udp),
                    'tcp': tcp, 'udp_open': open_udp,
                    'udp_open_filtered': of_udp, 'udp_closed': closed_n,
                    'duration_s': duration,
                    'started_at': started_iso,
                    'scanned_at': finished_iso,
                    'finished_at': finished_iso,
                })
    except Exception as e:
        finished_iso = datetime.now().isoformat()
        _record_history(app, uid=uid, ip=ip, hostname=hostname,
                        started_at=started_iso, finished_at=finished_iso,
                        duration_s=round(time.time() - started, 1),
                        tcp=[], open_udp=[], of_udp=[], closed_n=0,
                        error=str(e))
        with _job_lock:
            if uid in _jobs:
                _jobs[uid].update({'status': 'error', 'error': str(e),
                                   'finished_at': finished_iso})
