import sqlite3

def init_db():
    conn = sqlite3.connect("database/scans.db")
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT,
        vulnerability TEXT,
        endpoint TEXT,
        payload TEXT,
        severity TEXT
    )
    """)

    conn.commit()
    conn.close()