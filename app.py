import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from flask import Flask, render_template, request
from core.scanner import run_scan
from database.db import init_db
import sqlite3


app = Flask(__name__)
init_db()

@app.route('/')
def home():
    return render_template("index.html")

@app.route('/scan', methods=["POST"])
def scan():
    target = request.form.get("target")
    results = run_scan(target)

    conn = sqlite3.connect("database/scans.db")
    cursor = conn.cursor()

    for r in results:
        cursor.execute(
            "INSERT INTO scans (target, vulnerability, endpoint, payload, severity) VALUES (?, ?, ?, ?, ?)",
            (target, r["type"], r["endpoint"], r["payload"], r["severity"])
        )

    conn.commit()
    conn.close()

    return render_template("dashboard.html", results=results)

if __name__ == "__main__":
    app.run(debug=True)