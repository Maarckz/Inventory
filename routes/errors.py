
from __future__ import annotations

import logging

from flask import Blueprint, jsonify, render_template, request, session

bp = Blueprint("errors", __name__)


def _is_api(req):
    """True if this request should get a JSON error body, not HTML."""
    try:
        path = (req.path or '')
    except Exception:
        return False
    if any(path.startswith(p) for p in (
            '/netscope/api/', '/assistant/api/', '/notifications/api/',
            '/get_chart_data', '/gw/', '/api/')):
        return True
    accept = (req.headers.get('Accept') or '').lower()
    if 'application/json' in accept and 'text/html' not in accept:
        return True
    ctype = (req.headers.get('Content-Type') or '').lower()
    if 'application/json' in ctype:
        return True
    return False


def register_error_handlers(app) -> None:
    @app.errorhandler(400)
    @app.errorhandler(401)
    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(405)
    @app.errorhandler(408)
    @app.errorhandler(409)
    @app.errorhandler(413)
    @app.errorhandler(415)
    @app.errorhandler(422)
    @app.errorhandler(500)
    @app.errorhandler(501)
    @app.errorhandler(502)
    @app.errorhandler(503)
    @app.errorhandler(504)
    def handle_errors(error):
        code = error.code if hasattr(error, 'code') else 500
        client_ip = request.remote_addr
        username = session.get('username', 'Desconhecido')

        # For unhandled 500s, capture the actual exception so the log AND the
        # JSON response carry the real root cause (previously the user only
        # saw "JSON.parse: unexpected character" because the HTML 500 page
        # was returned to a fetch() that expected JSON).
        exc_detail = ''
        if code >= 500:
            try:
                import traceback
                exc_detail = traceback.format_exc()
            except Exception:
                exc_detail = ''
            app.logger.error(
                f"Erro {code} - IP: {client_ip}, Usuário: {username}, "
                f"Endpoint: {request.endpoint}, Path: {request.path}, "
                f"Method: {request.method}\n{exc_detail}")
        else:
            app.logger.error(
                f"Erro {code} - IP: {client_ip}, Usuário: {username}, "
                f"Endpoint: {request.endpoint}, Path: {request.path}, "
                f"Method: {request.method}")

        # API path → JSON. This is the critical fix: returning HTML for
        # /api/* requests broke every fetch().json() call in graph.js, and
        # the user only saw "JSON.parse: unexpected character at line 1
        # column 1" instead of the actual error message.
        if _is_api(request):
            messages = {
                400: 'Requisição inválida',
                401: 'Não autenticado',
                403: 'Acesso proibido',
                404: 'Não encontrado',
                405: 'Método não permitido',
                408: 'Tempo limite da requisição',
                409: 'Conflito',
                413: 'Payload muito grande',
                415: 'Tipo de mídia não suportado',
                422: 'Entidade não processável',
                500: 'Erro interno do servidor',
                501: 'Não implementado',
                502: 'Bad Gateway',
                503: 'Serviço indisponível',
                504: 'Gateway Timeout',
            }
            msg = messages.get(code, 'Erro desconhecido')
            payload = {
                'error': msg,
                'status': code,
                'endpoint': request.endpoint,
                'path': request.path,
            }
            if code == 401:
                payload['session_expired'] = True
            if code >= 500 and exc_detail:
                # Include the exception type+message (first/last line of
                # traceback) so the frontend can display a useful toast.
                # The full traceback stays in the server log.
                lines = [l for l in exc_detail.strip().splitlines() if l]
                if lines:
                    payload['detail'] = lines[-1][:300]
            return jsonify(payload), code

        # Non-API path → HTML error page (original behavior).
        messages = {
            403: "Acesso proibido",
            404: "Página não encontrada",
            500: "Erro interno do servidor",
            502: "Bad Gateway",
            503: "Serviço indisponível",
            504: "Gateway Timeout"
        }

        title = messages.get(code, "Erro desconhecido")
        message = f"Ocorreu um erro {code} ao processar sua requisição."

        return render_template('error.html',
                               error_code=code,
                               title=title,
                               message=message,
                               error_details=f"Erro {code} - IP: {client_ip}, Usuário: {username}, Endpoint: {request.endpoint}"), code

    @app.errorhandler(Exception)
    def handle_unexpected(exc):
        """Catch-all for unhandled exceptions (e.g. DB errors in soft_delete).

        Without this, Flask's default behavior is to log the exception and
        re-raise it as a 500, which then goes through ``handle_errors``
        above. But some exceptions (e.g. werkzeug's) have a code attribute
        that routes them to a specific handler. This catch-all ensures
        EVERY exception is funneled through the same API-aware path.
        """
        if hasattr(exc, 'code') and exc.code is not None:
            # HTTPException subclass — let handle_errors deal with it.
            return handle_errors(exc)
        # Non-HTTP exception — treat as 500.
        app.logger.error(f"Exceção não tratada: {exc!r}", exc_info=True)
        from werkzeug.exceptions import InternalServerError
        return handle_errors(InternalServerError())
