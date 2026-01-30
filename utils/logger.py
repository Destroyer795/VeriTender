from database import get_db_connection

# Immutable Audit Trail - append-only logging for compliance
# No UPDATE/DELETE operations exist for audit_logs table (permanent record)

def log_action(username: str, event: str):
    """
    Records security events in immutable audit log.
    Production enhancement: Log signing, separate DB, automated backups.
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