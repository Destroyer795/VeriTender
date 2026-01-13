from database import get_db_connection, init_db
from utils.auth import hash_password

def seed_data():
    init_db() # Ensure tables exist
    conn = get_db_connection()
    c = conn.cursor()

    # The 3 Roles required by the Rubric
    users = [
        ("contractor", "contractor@example.com", "pass123", "contractor"),
        ("official", "official@gov.in", "admin123", "official"),
        ("auditor", "auditor@agency.com", "audit123", "auditor")
    ]

    print("Seeding Users...")
    for username, email, pwd, role in users:
        # Check if user exists to avoid crash
        exists = c.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone()
        if not exists:
            hashed, salt = hash_password(pwd)
            c.execute(
                "INSERT INTO users (username, email, password_hash, salt, role) VALUES (?, ?, ?, ?, ?)",
                (username, email, hashed, salt, role)
            )
            print(f" -> Created User: {username} (Role: {role})")
        else:
            print(f" -> User {username} already exists.")

    conn.commit()
    conn.close()
    print("Database seeding complete.")

if __name__ == "__main__":
    seed_data()