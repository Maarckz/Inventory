import pyotp
import qrcode
from io import BytesIO
import base64
import time
from flask import session
import os

# Configurações do MFA
MFA_ISSUER = "Inventory System"
SESSION_SALT = os.getenv('SESSION_SALT', 'default_salt_value')  # Adicione ao .env

def generate_mfa_secret():
    """Gera um novo segredo MFA para o usuário"""
    return pyotp.random_base32()

def generate_mfa_qr_code(secret, username):
    """Gera um QR Code para configuração do MFA"""
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name=MFA_ISSUER
    )
    
    img = qrcode.make(totp_uri)
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    return f"data:image/png;base64,{img_str}"

def verify_mfa_code(secret, code):
    """Verifica se o código MFA é válido"""
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)

def get_secure_mfa_session():
    """Obtém dados MFA da sessão de forma segura"""
    return session.get('mfa_data')

def set_secure_mfa_session(username, secret):
    """Armazena temporariamente as credenciais MFA na sessão com salt"""
    session['mfa_data'] = {
        'username': username,
        'secret': secret,
        'expire': time.time() + 300  # Expira em 5 minutos
    }

def clear_mfa_session():
    """Limpa os dados MFA da sessão"""
    session.pop('mfa_data', None)