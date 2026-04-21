
import db as DB
import auth as AUTH
import secrets
from datetime import datetime

def seed_presentation_users():
    DB.init_db()
    AUTH.bootstrap_users()
    
    users_to_add = [
        {"username": "izumi.free", "password": "normal123", "role": "analyst", "tier": "free"},
        {"username": "izumi.premium", "password": "pro123", "role": "admin", "tier": "premium"}
    ]
    
    for u in users_to_add:
        existing = DB.get_user(u["username"])
        if not existing:
            print(f"Seeding user: {u['username']}")
            h = AUTH.hash_password(u["password"])
            uid = f"u_{secrets.token_hex(4)}"
            with DB.db() as conn:
                conn.execute(
                    "INSERT INTO users (id, username, password_hash, role, site_id, created_at) VALUES (?,?,?,?,?,datetime('now'))",
                    (uid, u["username"], h, u["role"], "site_demo")
                )
        else:
            print(f"User {u['username']} already exists.")

if __name__ == "__main__":
    seed_presentation_users()
    print("Seeding complete.")
