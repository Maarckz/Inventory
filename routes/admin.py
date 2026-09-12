
from __future__ import annotations

from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for

from models import User, HostInventory, db
from core.security import admin_required, hash_password

ROUTES = [
    ('/admin/users', 'manage_users', 'manage_users', {}),
    ('/admin/users/add', 'add_user', 'add_user', {'methods': ['POST']}),
    ('/admin/users/delete/<int:user_id>', 'delete_user', 'delete_user', {'methods': ['POST']}),
    ('/settings/legacy_machines', 'legacy_machines', 'legacy_machines', {}),
    ('/settings/delete_legacy_host/<int:id>', 'delete_legacy_host', 'delete_legacy_host', {'methods': ['POST']}),
]

@admin_required
def manage_users():
    users = User.query.all()
    return render_template('admin_users.html', users=users)

def _wants_json() -> bool:

    return request.headers.get('X-Requested-With') == 'XMLHttpRequest'

@admin_required
def add_user():
    username = (request.form.get('username') or '').strip()
    full_name = (request.form.get('full_name') or '').strip()
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')
    role = request.form.get('role', 'user')

    def _err(msg, code=400):
        if _wants_json():
            return jsonify({'success': False, 'error': msg}), code
        flash(msg, "danger")
        return redirect(url_for('settings'))

    if not username or not password:
        return _err("Usuário e senha são obrigatórios.")
    if len(full_name) > 120:
        return _err("O nome completo deve ter no máximo 120 caracteres.")
    if password != confirm_password:
        return _err("As senhas não coincidem.")
    if User.query.filter_by(username=username).first():
        return _err("Usuário já existe.", 409)

    novo_usuario = User(username=username, full_name=full_name or None,
                        password_hash=hash_password(password), role=role)
    db.session.add(novo_usuario)
    db.session.commit()

    if _wants_json():
        return jsonify({'success': True, 'reload': True,
                        'message': f"Usuário {username} criado com sucesso."})
    flash(f"Usuário {username} criado com sucesso.", "success")
    return redirect(url_for('settings'))

@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.username == 'admin':
        msg = "Não é possível remover o administrador principal."
        if _wants_json():
            return jsonify({'success': False, 'error': msg}), 400
        flash(msg, "danger")
        return redirect(url_for('settings'))
    db.session.delete(user)
    db.session.commit()
    msg = f"Usuário {user.username} removido com sucesso."
    if _wants_json():
        return jsonify({'success': True, 'reload': True, 'message': msg})
    flash(msg, "success")
    return redirect(url_for('settings'))

@admin_required
def legacy_machines():
    legacy_hosts = HostInventory.query.filter_by(is_legacy=True).order_by(HostInventory.hostname).all()
    return render_template('legacy_machines.html', hosts=legacy_hosts)

@admin_required
def delete_legacy_host(id):
    from flask import current_app
    from utils import cache as shared_cache

    app = current_app._get_current_object()
    host = HostInventory.query.get_or_404(id)
    if not host.is_legacy:
        return jsonify({'error': 'Apenas máquinas legadas podem ser excluídas por aqui.'}), 400

    try:
        db.session.delete(host)
        db.session.commit()
        if hasattr(app, 'MACHINES_CACHE'):
            app.MACHINES_CACHE['data'] = None
        shared_cache.invalidate('machines', 'stats')
        return jsonify({'success': True, 'message': f'Host {host.hostname} excluído com sucesso.'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
