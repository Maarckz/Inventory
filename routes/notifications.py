
from flask import Blueprint, jsonify, request, session

notify_bp = Blueprint('notifications', __name__)

def _authed():
    if 'username' not in session:
        return jsonify({'error': 'Não autenticado',
                        'session_expired': True}), 401
    return None

def _admin_json():

    if 'username' not in session:
        return jsonify({'error': 'Não autenticado',
                        'session_expired': True}), 401
    if session.get('role') != 'admin':
        return jsonify({'error': 'Somente administrador',
                        'forbidden': True}), 403
    return None

def _unread_count():
    from models import Notification
    return Notification.query.filter_by(read=False).count()

@notify_bp.route('/notifications/api/list')
def api_list():
    guard = _authed()
    if guard:
        return guard
    try:
        from services.notifications import list_notifications
        unread_only = request.args.get('unread') == '1'
        items, unread = list_notifications(limit=60, unread_only=unread_only)
        return jsonify({'items': items, 'unread': unread})
    except Exception as e:
        return jsonify({'items': [], 'unread': 0, 'error': str(e)}), 500

@notify_bp.route('/notifications/api/unread')
def api_unread():
    guard = _authed()
    if guard:
        return guard
    try:
        from models import Notification
        return jsonify({'unread': Notification.query.filter_by(read=False).count()})
    except Exception:
        return jsonify({'unread': 0})

@notify_bp.route('/notifications/api/read', methods=['POST'])
def api_read():
    guard = _authed()
    if guard:
        return guard
    body = request.get_json(silent=True) or {}
    nid = body.get('id')
    if nid is None:
        return jsonify({'error': 'id obrigatório'}), 400
    try:
        from models import Notification, db
        row = Notification.query.get(int(nid))
        if not row:
            return jsonify({'error': 'Não encontrada'}), 404
        row.read = True
        db.session.commit()
        unread = Notification.query.filter_by(read=False).count()
        return jsonify({'ok': True, 'unread': unread})
    except (ValueError, TypeError):
        return jsonify({'error': 'id inválido'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@notify_bp.route('/notifications/api/read_all', methods=['POST'])
def api_read_all():
    guard = _authed()
    if guard:
        return guard
    try:
        from models import Notification, db
        Notification.query.filter_by(read=False).update({'read': True})
        db.session.commit()
        return jsonify({'ok': True, 'unread': 0})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@notify_bp.route('/notifications/api/check', methods=['POST'])
def api_check():
    guard = _authed()
    if guard:
        return guard
    try:
        from services.notifications import evaluate_all
        from flask import current_app
        result = evaluate_all(current_app._get_current_object(),
                              logger=current_app.logger)
        from models import Notification
        unread = Notification.query.filter_by(read=False).count()
        return jsonify({'ok': True, 'created': result['created'],
                        'rules': result['rules'], 'unread': unread})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@notify_bp.route('/notifications/api/delete', methods=['POST'])
def api_delete():
    guard = _admin_json()
    if guard:
        return guard
    body = request.get_json(silent=True) or {}
    nid = body.get('id')
    if nid is None:
        return jsonify({'error': 'id obrigatório'}), 400
    try:
        from models import Notification, db
        row = Notification.query.get(int(nid))
        if not row:
            return jsonify({'error': 'Não encontrada'}), 404
        db.session.delete(row)
        db.session.commit()
        return jsonify({'ok': True, 'unread': _unread_count()})
    except (ValueError, TypeError):
        return jsonify({'error': 'id inválido'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@notify_bp.route('/notifications/api/clear_read', methods=['POST'])
def api_clear_read():
    guard = _admin_json()
    if guard:
        return guard
    try:
        from models import Notification, db
        n = Notification.query.filter_by(read=True).delete()
        db.session.commit()
        return jsonify({'ok': True, 'deleted': int(n or 0),
                        'unread': _unread_count()})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@notify_bp.route('/notifications/api/clear_all', methods=['POST'])
def api_clear_all():
    guard = _admin_json()
    if guard:
        return guard
    try:
        from models import Notification, db
        n = Notification.query.delete()
        db.session.commit()
        return jsonify({'ok': True, 'deleted': int(n or 0), 'unread': 0})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@notify_bp.route('/notifications/api/rules')
def api_rules_list():
    guard = _authed()
    if guard:
        return guard
    try:
        from services.notifications import (get_rules, RULE_FIELDS, RULE_OPS,
                                            MAX_RULES)
        from core.i18n import translate
        return jsonify({'items': get_rules(),
                        'fields': {k: translate(v) for k, v in RULE_FIELDS.items()},
                        'ops': {k: translate(v) for k, v in RULE_OPS.items()},
                        'max': MAX_RULES})
    except Exception as e:
        return jsonify({'items': [], 'fields': {}, 'ops': {},
                        'error': str(e)}), 500

@notify_bp.route('/notifications/api/rules', methods=['POST'])
def api_rules_save():
    guard = _admin_json()
    if guard:
        return guard
    body = request.get_json(silent=True) or {}
    try:
        from services.notifications import upsert_rule
        rule, err = upsert_rule(body)
        if err:
            return jsonify({'error': err}), 400
        return jsonify({'ok': True, 'rule': rule})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@notify_bp.route('/notifications/api/rules_delete', methods=['POST'])
def api_rules_delete():
    guard = _admin_json()
    if guard:
        return guard
    body = request.get_json(silent=True) or {}
    rid = str(body.get('id') or '').strip()
    if not rid:
        return jsonify({'error': 'id obrigatório'}), 400
    try:
        from services.notifications import delete_rule
        ok, err = delete_rule(rid)
        if not ok:
            return jsonify({'error': err or 'not_found'}), 404
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
