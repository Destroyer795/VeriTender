import os
from seed import seed_data

DB_NAME = "veritender.db"

def reset_database():
    # Delete the existing database file
    if os.path.exists(DB_NAME):
        try:
            os.remove(DB_NAME)
            print(f"🗑️  Deleted old database: {DB_NAME}")
        except PermissionError:
            print("❌ Error: Close the database (or stop the server) before resetting!")
            return
    else:
        print("ℹ️  No existing database found.")

    # Run the seed function to create tables and default users
    print("🌱 Initializing fresh database...")
    seed_data()
    print("✅ RESET COMPLETE. You can now run 'python main.py'")

if __name__ == "__main__":
    reset_database()