
import json
import threading
import uuid
from datetime import datetime

from services.netscope_core import store

class SnapshotManager:

    def __init__(self):
        self._lock = threading.RLock()

    def _models(self):
        from models import db, NetscopeSnapshot
        return db, NetscopeSnapshot

    def list_snapshots(self):
        with self._lock:
            try:
                _, NS = self._models()
                rows = NS.query.order_by(NS.created_at.desc()).all()
            except Exception:
                return []
            snaps = []
            for r in rows:
                d = r.data if isinstance(r.data, dict) else {}
                devs = d.get('devices', [])
                snaps.append({
                    'id': r.snap_id,
                    'label': r.label or '',
                    'notes': r.notes or '',
                    'created_at': r.created_at or '',
                    'device_count': r.device_count if r.device_count is not None else len(devs),
                    'link_count': (r.link_count if r.link_count is not None
                                   else sum(1 for x in devs if isinstance(x, dict) and x.get('parent_id'))),
                    'auto': bool(r.auto),
                })
            return snaps

    def create_snapshot(self, label, notes='', auto=False):
        with self._lock:
            snap_id = datetime.now().strftime('%Y%m%d_%H%M%S') + '_' + uuid.uuid4().hex[:6]
            devices = json.loads(json.dumps(store.active(), default=str))
            snap = {
                'id': snap_id,
                'label': label or f'Snapshot {datetime.now().strftime("%d/%m/%Y %H:%M")}',
                'notes': notes,
                'created_at': datetime.now().isoformat(),
                'auto': auto,
                'devices': devices,
            }
            db, NS = self._models()
            db.session.add(NS(
                snap_id=snap_id,
                label=snap['label'],
                notes=notes or '',
                auto=auto,
                created_at=snap['created_at'],
                device_count=len(devices),
                link_count=sum(1 for d in devices if d.get('parent_id')),
                data=json.loads(json.dumps(snap, default=str)),
            ))
            db.session.commit()
            return snap

    def load_snapshot(self, snap_id):
        try:
            _, NS = self._models()
            r = NS.query.get(str(snap_id))
        except Exception:
            return None
        if not r:
            return None
        return r.data if isinstance(r.data, dict) else None

    def delete_snapshot(self, snap_id):
        with self._lock:
            try:
                db, NS = self._models()
                r = NS.query.get(str(snap_id))
                if not r:
                    return False
                db.session.delete(r)
                db.session.commit()
                return True
            except Exception:
                try:
                    db.session.rollback()
                except Exception:
                    pass
                return False

    def compare_snapshots(self, snap_id_a, snap_id_b):
        a = self.load_snapshot(snap_id_a)
        b = self.load_snapshot(snap_id_b)
        if not a or not b:
            return None
        def _key(d):
            return str(d.get('uid') or d.get('mac') or '').lower()
        a_devs = {_key(d): d for d in a.get('devices', [])}
        b_devs = {_key(d): d for d in b.get('devices', [])}
        added = []
        removed = []
        changed = []
        for k, d in b_devs.items():
            if k not in a_devs:
                added.append({'mac': k, 'ip': d.get('ip'), 'hostname': d.get('hostname', '')})
            else:
                old = a_devs[k]
                diffs = {}
                for f in ('ip', 'hostname', 'vendor', 'type', 'parent_id', 'user',
                          'department', 'location', 'switch_port', 'has_agent',
                          'agent_status', 'agent_id', 'mac'):
                    if old.get(f) != d.get(f):
                        diffs[f] = {'old': old.get(f), 'new': d.get(f)}
                if diffs:
                    changed.append({'mac': k, 'ip': d.get('ip'), 'hostname': d.get('hostname', ''), 'diffs': diffs})
        for k, d in a_devs.items():
            if k not in b_devs:
                removed.append({'mac': k, 'ip': d.get('ip'), 'hostname': d.get('hostname', '')})
        return {
            'a': {'id': snap_id_a, 'label': a.get('label', ''), 'created_at': a.get('created_at', '')},
            'b': {'id': snap_id_b, 'label': b.get('label', ''), 'created_at': b.get('created_at', '')},
            'added': added, 'removed': removed, 'changed': changed,
        }

_instance = None

def get_instance():
    global _instance
    if _instance is None:
        _instance = SnapshotManager()
    return _instance
