from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import JSONB
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    full_name = db.Column(db.String(120), nullable=True)
    password_hash = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')
    mfa_enabled = db.Column(db.Boolean, default=False)
    mfa_secret = db.Column(db.String(32), nullable=True)
    must_change_password = db.Column(db.Boolean, default=False)

class HostInventory(db.Model):
    __tablename__ = 'host_inventory'
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(255), unique=True, nullable=False)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    data = db.Column(JSONB, nullable=False)
    is_legacy = db.Column(db.Boolean, default=True)

class Group(db.Model):
    __tablename__ = 'groups'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    data = db.Column(JSONB, nullable=False)
    is_legacy = db.Column(db.Boolean, default=True)

class SystemSetting(db.Model):
    __tablename__ = 'system_settings'
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)
    value = db.Column(JSONB, nullable=False)

class Notification(db.Model):

    __tablename__ = 'notifications'
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(160), nullable=False, index=True)
    kind = db.Column(db.String(40), nullable=False)
    params = db.Column(JSONB, nullable=False, default=dict)
    category = db.Column(db.String(20), nullable=False, default='system')
    severity = db.Column(db.String(10), nullable=False, default='info')
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    read = db.Column(db.Boolean, default=False, index=True)

class ChatMessage(db.Model):

    __tablename__ = 'chat_messages'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False, index=True)
    role = db.Column(db.String(10), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

class NetscopeDevice(db.Model):

    __tablename__ = 'netscope_devices'
    id = db.Column(db.Integer, primary_key=True)
    mac = db.Column(db.String(20), unique=True, nullable=True, index=True)
    ip = db.Column(db.String(64), default='')
    hostname = db.Column(db.String(255), default='')
    deleted = db.Column(db.Boolean, default=False, index=True)
    last_seen = db.Column(db.DateTime, nullable=True)
    data = db.Column(JSONB, nullable=False)

class NetscopeSetting(db.Model):

    __tablename__ = 'netscope_settings'
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)
    value = db.Column(JSONB, nullable=False)

class NetscopeSnapshot(db.Model):

    __tablename__ = 'netscope_snapshots'
    snap_id = db.Column(db.String(64), primary_key=True)
    label = db.Column(db.String(255), default='')
    notes = db.Column(db.Text, default='')
    auto = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.String(40))
    device_count = db.Column(db.Integer, default=0)
    link_count = db.Column(db.Integer, default=0)
    data = db.Column(JSONB, nullable=False)

class NetscopeScanHistory(db.Model):

    __tablename__ = 'netscope_scan_history'
    id = db.Column(db.Integer, primary_key=True)
    device_uid = db.Column(db.String(40), nullable=False, index=True)
    hostname = db.Column(db.String(255), default='')
    ip = db.Column(db.String(64), default='')
    status = db.Column(db.String(10), default='done')
    started_at = db.Column(db.String(40))
    finished_at = db.Column(db.String(40))
    duration_s = db.Column(db.Float, default=0)
    tcp_count = db.Column(db.Integer, default=0)
    udp_count = db.Column(db.Integer, default=0)
    udp_closed = db.Column(db.Integer, default=0)
    error = db.Column(db.Text, default='')
    results = db.Column(JSONB, nullable=False)
