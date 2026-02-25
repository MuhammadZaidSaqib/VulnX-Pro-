import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from flask import Flask, render_template, request, jsonify
from core.scanner import run_scan
from database.db import init_db, save_results

app = Flask(__name__)
init_db()

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json()

    if not data or "target" not in data:
        return jsonify({"error": "No target provided"}), 400

    target = data["target"]

    try:
        results = run_scan(target)
        save_results(target, results)

        return jsonify({
            "count": len(results),
            "results": [
                {
                    "type": r[0],
                    "endpoint": r[1],
                    "payload": r[2]
                }
                for r in results
            ]
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# -------------------------
# DEMO VULNERABLE ROUTES
# -------------------------

@app.route("/demo")
def demo_home():
    return """
    <h2>Demo Vulnerable App</h2>
    <ul>
        <li><a href='/demo/sqli?id=1'>SQL Injection Test</a></li>
        <li><a href='/demo/xss?name=test'>XSS Test</a></li>
    </ul>
    """

@app.route("/demo/sqli")
def demo_sqli():
    user_input = request.args.get("id", "")

    # Simulated SQL error
    if "'" in user_input or "OR" in user_input.upper():
        return "You have an error in your SQL syntax near '...mysql_fetch_array()'"

    return f"User ID: {user_input}"

@app.route("/demo/xss")
def demo_xss():
    name = request.args.get("name", "")
    return f"<h3>Hello {name}</h3>"

if __name__ == "__main__":
    app.run(debug=True)