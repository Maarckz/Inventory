from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import JSONB
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')
    mfa_enabled = db.Column(db.Boolean, default=False)
    mfa_secret = db.Column(db.String(32), nullable=True)

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