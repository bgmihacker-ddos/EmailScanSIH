import sys
import os

# Add backend directory to path
sys.path.append(os.path.join(os.getcwd(), 'backend'))

from app.database.session import SessionLocal
from app.models.user import User

def update_role_to_admin():
    db = SessionLocal()
    try:
        email = "nandpatel0912@gmail.com"
        user = db.query(User).filter(User.email == email).first()

        if not user:
            print("User not found")
            return

        print(f"Current role: {user.role}")

        if user.role != 'admin':
            user.role = 'admin'
            db.commit()
            print("Role updated to admin successfully")
        else:
            print("User is already an admin")

    except Exception as e:
        db.rollback()
        print(f"Error: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    update_role_to_admin()
