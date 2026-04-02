from app import app, db
from models import User, HostInventory, Group
import bcrypt

with app.app_context():
    db.drop_all()
    db.create_all()
    
    hashed = bcrypt.hashpw('Meuadmin123'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    admin_user = User(username='admin', password_hash=hashed, role='admin')
    db.session.add(admin_user)
    db.session.commit()
