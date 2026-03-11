import sqlite3

DB_PATH = "security_engine.db"


def get_connection():
    return sqlite3.connect(DB_PATH)


def init_db():

    conn = get_connection()

    conn.execute("""
    CREATE TABLE IF NOT EXISTS security_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        device_id TEXT,
        login_hour INTEGER,
        payload TEXT,
        risk_score REAL,
        risk_level TEXT,
        timestamp TEXT
    )
    """)

    conn.commit()
    conn.close()


def insert_event(user_id, device_id, login_hour, payload, risk_score, risk_level, timestamp):

    conn = get_connection()

    conn.execute("""
    INSERT INTO security_events
    (user_id, device_id, login_hour, payload, risk_score, risk_level, timestamp)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (user_id, device_id, login_hour, payload, risk_score, risk_level, timestamp))

    conn.commit()
    conn.close()


def get_events():

    conn = get_connection()
    conn.row_factory = sqlite3.Row

    rows = conn.execute("SELECT * FROM security_events").fetchall()

    conn.close()

    return [dict(r) for r in rows]