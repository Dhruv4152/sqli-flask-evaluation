from app import app, db, User
from werkzeug.security import generate_password_hash

with app.app_context():
    db.drop_all()
    db.create_all()

    # SECURE: Hashing the passwords before saving them
    admin_hash = generate_password_hash('supersecret')
    guest_hash = generate_password_hash('guest')

    admin = User(username='admin', password=admin_hash)
    guest = User(username='guest', password=guest_hash)

    db.session.add(admin)
    db.session.add(guest)
    db.session.commit()
    
    print("Database rebuilt with securely hashed passwords!")