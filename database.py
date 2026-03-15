import sqlite3

DB_PATH = "security_engine.db"


def get_connection():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


# -----------------------------
# INITIALIZE DATABASE
# -----------------------------
def init_db():

    conn = get_connection()
    cursor = conn.cursor()

    # -----------------------------
    # SECURITY EVENTS TABLE
    # -----------------------------
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS security_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        device_id TEXT,
        source_ip TEXT,
        destination_ip TEXT,
        login_hour INTEGER,
        payload TEXT,
        risk_score REAL,
        risk_level TEXT,
        timestamp TEXT
    )
    """)

    # -----------------------------
    # KNOWN DEVICES TABLE
    # -----------------------------
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS known_devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        device_id TEXT,
        UNIQUE(user_id, device_id)
    )
    """)

    # -----------------------------
    # MALICIOUS IP TABLE
    # -----------------------------
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS malicious_ips (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source_ip TEXT UNIQUE,
        detected_at TEXT
    )
    """)

    conn.commit()
    conn.close()


# -----------------------------
# INSERT SECURITY EVENT
# -----------------------------
def insert_event(user_id, device_id, source_ip, destination_ip,
                 login_hour, payload, risk_score, risk_level, timestamp):

    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
        INSERT INTO security_events
        (user_id, device_id, source_ip, destination_ip,
         login_hour, payload, risk_score, risk_level, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            user_id,
            device_id,
            source_ip,
            destination_ip,
            login_hour,
            payload,
            risk_score,
            risk_level,
            timestamp
        ))

        conn.commit()

    finally:
        conn.close()


# -----------------------------
# GET SECURITY EVENTS
# -----------------------------
def get_events():

    conn = get_connection()
    conn.row_factory = sqlite3.Row

    rows = conn.execute(
        "SELECT * FROM security_events ORDER BY timestamp DESC"
    ).fetchall()

    conn.close()

    return [dict(r) for r in rows]


# -----------------------------
# DEVICE MANAGEMENT
# -----------------------------
def device_exists(user_id, device_id):

    conn = get_connection()

    row = conn.execute(
        "SELECT 1 FROM known_devices WHERE user_id=? AND device_id=?",
        (user_id, device_id)
    ).fetchone()

    conn.close()

    return row is not None


def add_device(user_id, device_id):

    try:
        conn = get_connection()

        conn.execute(
            "INSERT OR IGNORE INTO known_devices (user_id, device_id) VALUES (?, ?)",
            (user_id, device_id)
        )

        conn.commit()

    finally:
        conn.close()


# -----------------------------
# FLAG MALICIOUS IP
# -----------------------------
def flag_malicious_ip(source_ip, timestamp):

    try:
        conn = get_connection()

        conn.execute("""
        INSERT OR IGNORE INTO malicious_ips (source_ip, detected_at)
        VALUES (?, ?)
        """, (source_ip, timestamp))

        conn.commit()

    finally:
        conn.close()