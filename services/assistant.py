
from flask import Blueprint, jsonify, request, session

assistant_bp = Blueprint('assistant', __name__)

@assistant_bp.route('/assistant/api/status')
def api_status():
    if 'username' not in session:
        return jsonify({'error': 'Não autenticado',
                        'session_expired': True}), 401
    try:
        from services.assistant import get_settings
        cfg = get_settings()
        return jsonify({'configured': bool(cfg['api_key']),
                        'source': cfg.get('key_source', '')})
    except Exception:
        return jsonify({'configured': False, 'source': ''})

@assistant_bp.route('/assistant/api/chat', methods=['POST'])
def api_chat():
    if 'username' not in session:
        return jsonify({'error': 'Não autenticado',
                        'session_expired': True}), 401
    body = request.get_json(silent=True) or {}
    message = body.get('message') or ''
    history = body.get('history') if isinstance(body.get('history'), list) else []
    lang = session.get('language', 'pt')
    username = session.get('username') or ''

    try:
        from services.assistant import chat
        reply, err, detail = chat(message, history, lang, username=username)
    except Exception as e:
        return jsonify({'error': 'assistant_error', 'detail': str(e)}), 500

    if err:
        code = 400 if err == 'no_api_key' else 502
        payload = {'error': err}
        if detail:
            payload['detail'] = str(detail)[:300]
        return jsonify(payload), code
    return jsonify({'reply': reply})

@assistant_bp.route('/assistant/api/history')
def api_history():

    if 'username' not in session:
        return jsonify({'error': 'Não autenticado',
                        'session_expired': True}), 401
    try:
        from services.assistant import get_history
        items = get_history(session.get('username') or '')
        return jsonify({'items': items})
    except Exception as e:
        return jsonify({'items': [], 'error': str(e)}), 500

@assistant_bp.route('/assistant/api/history/clear', methods=['POST'])
def api_history_clear():

    if 'username' not in session:
        return jsonify({'error': 'Não autenticado',
                        'session_expired': True}), 401
    try:
        from services.assistant import clear_history
        n = clear_history(session.get('username') or '')
        return jsonify({'ok': True, 'deleted': n})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500
