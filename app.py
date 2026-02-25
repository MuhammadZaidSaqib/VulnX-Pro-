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


if __name__ == "__main__":
    app.run(debug=True)