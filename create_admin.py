import sys
import os

# Add backend directory to path
sys.path.append(os.path.join(os.getcwd(), 'backend'))

from app.database.session import SessionLocal
from app.models.user import User
from app.core.security import hash_password

def create_admin():
    db = SessionLocal()
    try:
        email = "nandpatel0912@gmail.com"
        password = "nandpatel"

        existing = db.query(User).filter(User.email == email).first()
        if existing:
            print("User already exists")
            return

        admin = User(
            name="Admin User",
            email=email,
            password_hash=hash_password(password),
            role="admin",
            is_active=True,
            is_verified=True
        )
        db.add(admin)
        db.commit()
        print("Admin user created successfully")
    except Exception as e:
        db.rollback()
        print(f"Error: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    create_admin()
