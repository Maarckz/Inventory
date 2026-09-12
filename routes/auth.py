
from __future__ import annotations

import time

import bcrypt
import pyotp
from flask import (
    Blueprint, flash, redirect, render_template, request, session, url_for,
)

from models import User
from core.security import login_limiter

ROUTES = [
    ('/login', 'login', 'login', {'methods': ['GET', 'POST']}),
    ('/verify_mfa', 'verify_mfa', 'verify_mfa', {'methods': ['GET', 'POST']}),
    ('/logout', 'logout', 'logout', {}),
    ('/set_language/<language>', 'set_language', 'set_language', {}),
]

_RATE_LIMIT_MSG = "Muitas tentativas. Aguarde um minuto e tente novamente."

def login():
    if 'username' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        client_ip = request.remote_addr
        if not login_limiter.allow(f"login:{client_ip}"):
            import logging
            logging.getLogger('security').warning(
                f"LOGIN RATE LIMIT - IP: {client_ip}")
            flash(_RATE_LIMIT_MSG, 'error')
            return render_template('login.html'), 429

        username = request.form.get('username', '')[:50]
        password = request.form.get('password', '')[:100]

        if not username or not password:
            flash('Preencha todos os campos', 'error')
            return render_template('login.html')

        user = User.query.filter_by(username=username).first()

        if user and bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
            session.clear()

            if user.mfa_enabled:
                session['mfa_username'] = username
                session['mfa_expire'] = time.time() + 300
                return redirect(url_for('verify_mfa'))

            session['username'] = username
            session['role'] = user.role
            session['user_id'] = user.id
            session['user_ip'] = client_ip
            session['user_agent'] = request.headers.get('User-Agent', '')
            session['login_time'] = time.time()

            if getattr(user, 'must_change_password', False):
                session['must_change_password'] = True
                flash('Por segurança, defina uma nova senha antes de continuar.', 'warning')
                return redirect(url_for('settings'))

            import logging
            logging.getLogger('security').info(
                f"LOGIN BEM-SUCEDIDO - Usuário: {username}, IP: {client_ip}")
            return redirect(url_for('dashboard'))
        else:
            import logging
            logging.getLogger('security').warning(
                f"TENTATIVA DE LOGIN FALHA - Usuário: {username}, IP: {client_ip}")
            flash('Credenciais inválidas', 'error')

    return render_template('login.html')

def verify_mfa():
    if 'mfa_username' not in session or time.time() > session.get('mfa_expire', 0):
        flash('Sessão expirada. Faça login novamente', 'error')
        session.pop('mfa_username', None)
        return redirect(url_for('login'))

    username = session['mfa_username']

    if request.method == 'POST':
        client_ip = request.remote_addr
        if not login_limiter.allow(f"mfa:{client_ip}"):
            import logging
            logging.getLogger('security').warning(
                f"MFA RATE LIMIT - IP: {client_ip}")
            flash(_RATE_LIMIT_MSG, 'error')
            return render_template('verify_mfa.html'), 429

        code = request.form.get('code', '')
        user = User.query.filter_by(username=username).first()

        if user and user.mfa_enabled and user.mfa_secret:
            totp = pyotp.TOTP(user.mfa_secret)
            if totp.verify(code, valid_window=1):
                session.clear()

                session['username'] = username
                session['role'] = user.role
                session['user_id'] = user.id
                session['user_ip'] = request.remote_addr
                session['user_agent'] = request.headers.get('User-Agent', '')
                session['login_time'] = time.time()

                if getattr(user, 'must_change_password', False):
                    session['must_change_password'] = True
                    flash('Por segurança, defina uma nova senha antes de continuar.', 'warning')
                    return redirect(url_for('settings'))

                import logging
                logging.getLogger('security').info(
                    f"LOGIN MFA BEM-SUCEDIDO - Usuário: {username}, IP: {request.remote_addr}")
                return redirect(url_for('dashboard'))

        flash('Código MFA inválido', 'error')

    return render_template('verify_mfa.html')

def logout():
    username = session.get('username', 'Desconhecido')
    client_ip = request.remote_addr

    import logging
    logging.getLogger('security').info(f"LOGOUT - Usuário: {username}, IP: {client_ip}")

    session.clear()
    return redirect(url_for('login'))

def set_language(language):
    from utils.language import LANGUAGES
    if language in LANGUAGES:
        session['language'] = language
    return redirect(request.referrer or url_for('dashboard'))
