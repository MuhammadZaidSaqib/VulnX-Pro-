import sqlite3
import os

DB_PATH = "database/vulnx.db"

def init_db():
    os.makedirs("database", exist_ok=True)

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            type TEXT,
            endpoint TEXT,
            payload TEXT
        )
    """)

    conn.commit()
    conn.close()


def save_results(target, results):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    for r in results:
        cur.execute("""
            INSERT INTO vulnerabilities (target, type, endpoint, payload)
            VALUES (?, ?, ?, ?)
        """, (target, r[0], r[1], r[2]))

    conn.commit()
    conn.close()