from database import get_db_connection

def log_action(username: str, event: str):
    """
    Records an event in the immutable audit log.
    Usage: log_action("contractor_bob", "Submitted a bid")
    """
    try:
        conn = get_db_connection()
        conn.execute(
            "INSERT INTO audit_logs (username, event) VALUES (?, ?)",
            (username, event)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"FAILED TO LOG EVENT: {e}")