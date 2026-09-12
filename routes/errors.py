
from __future__ import annotations

from flask import Blueprint, render_template, request, session

bp = Blueprint("errors", __name__)

def register_error_handlers(app) -> None:
    @app.errorhandler(404)
    @app.errorhandler(403)
    @app.errorhandler(500)
    @app.errorhandler(502)
    @app.errorhandler(503)
    @app.errorhandler(504)
    def handle_errors(error):
        code = error.code if hasattr(error, 'code') else 500
        client_ip = request.remote_addr
        username = session.get('username', 'Desconhecido')

        error_message = f"Erro {code} - IP: {client_ip}, Usuário: {username}, Endpoint: {request.endpoint}"
        app.logger.error(error_message)

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
                               error_details=error_message), code
