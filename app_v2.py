"""
Optimized Flask application with improved structure and error handling.
"""
import os
import sys
import logging

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, render_template, request, jsonify
from core.scanner_v2 import VulnerabilityScanner
from database.db import init_db, save_results
from utils.helpers_v2 import LoggerFactory, URLValidator

# Configure logging
logger = LoggerFactory.get_logger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False

# Initialize database
init_db()

# Initialize scanner
scanner = VulnerabilityScanner()


# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({"error": "Endpoint not found"}), 404


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    logger.error(f"Internal server error: {error}")
    return jsonify({"error": "Internal server error"}), 500


# ==================== MAIN ROUTES ====================

@app.route("/")
def home():
    """Serve main dashboard"""
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def scan():
    """
    Main scanning endpoint.
    Expects JSON body: {"target": "https://example.com"}
    """
    try:
        data = request.get_json()

        # Validation
        if not data:
            logger.warning("Scan request with no JSON data")
            return jsonify({"error": "No JSON data provided"}), 400

        target = data.get("target", "").strip()
        if not target:
            logger.warning("Scan request with no target")
            return jsonify({"error": "No target provided"}), 400

        # Validate URL
        if not URLValidator.is_valid(target):
            logger.warning(f"Invalid URL provided: {target}")
            return jsonify({"error": "Invalid URL format"}), 400

        # Normalize URL
        target = URLValidator.normalize(target)

        logger.info(f"Starting scan: {target}")

        # Execute scan
        results = scanner.scan(target)
        result_tuples = scanner.get_results_tuples()
        summary = scanner.get_summary()

        # Save to database
        if result_tuples:
            save_results(target, result_tuples)
            logger.info(f"Saved {len(result_tuples)} results to database")

        # Return response
        return jsonify({
            "success": True,
            "target": target,
            "count": len(results),
            "results": scanner.get_results(),
            "summary": summary
        }), 200

    except Exception as e:
        logger.error(f"Scan error: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route("/api/scan-fast", methods=["POST"])
def scan_fast():
    """
    Fast scan endpoint (no crawling, only target URL).
    Expects JSON body: {"target": "https://example.com"}
    """
    try:
        data = request.get_json()

        if not data or not data.get("target"):
            return jsonify({"error": "No target provided"}), 400

        target = URLValidator.normalize(data.get("target", ""))
        if not target:
            return jsonify({"error": "Invalid URL format"}), 400

        logger.info(f"Starting fast scan: {target}")

        # Execute fast scan
        results = scanner.scan_fast(target)
        result_tuples = scanner.get_results_tuples()
        summary = scanner.get_summary()

        # Save to database
        if result_tuples:
            save_results(target, result_tuples)

        return jsonify({
            "success": True,
            "target": target,
            "count": len(results),
            "results": scanner.get_results(),
            "summary": summary
        }), 200

    except Exception as e:
        logger.error(f"Fast scan error: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route("/api/status", methods=["GET"])
def status():
    """Health check endpoint"""
    return jsonify({
        "status": "online",
        "version": "2.0",
        "scanner": "VulnX_Pro"
    }), 200


# ==================== DEMO ROUTES ====================

@app.route("/demo")
def demo_home():
    """Demo home page with vulnerable endpoints"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>VulnX_Pro - Demo Vulnerable App</title>
        <style>
            body { font-family: Arial; margin: 20px; background: #1a1a1a; color: #fff; }
            h2 { color: #00ff00; }
            a { color: #00ccff; text-decoration: none; }
            a:hover { text-decoration: underline; }
            ul { list-style: none; padding: 0; }
            li { margin: 10px 0; padding: 10px; background: #222; border-radius: 5px; }
            code { background: #111; padding: 2px 5px; border-radius: 3px; }
        </style>
    </head>
    <body>
        <h2>🔍 VulnX_Pro Demo - Vulnerable Endpoints</h2>
        <p>These endpoints contain intentional vulnerabilities for testing and education.</p>
        <ul>
            <li><a href='/demo/sqli?id=1'>SQL Injection Test</a> - Try: <code>id=' OR '1'='1</code></li>
            <li><a href='/demo/xss?name=test'>XSS Test</a> - Try: <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code></li>
        </ul>
        <hr>
        <p><small>⚠️ These vulnerabilities are intentional for educational purposes only!</small></p>
    </body>
    </html>
    """


@app.route("/demo/sqli")
def demo_sqli():
    """Demo SQL injection vulnerable endpoint"""
    user_input = request.args.get("id", "")

    # Simulate SQL error on malicious input
    if "'" in user_input or "OR" in user_input.upper() or "--" in user_input:
        return (
            "<h3>Database Error</h3>"
            f"<p>You have an error in your SQL syntax near '{user_input}' on line 1</p>"
        ), 400

    return f"<h3>User ID: {user_input}</h3><p>Data retrieved successfully</p>"


@app.route("/demo/xss")
def demo_xss():
    """Demo XSS vulnerable endpoint"""
    name = request.args.get("name", "Guest")
    return f"""
    <!DOCTYPE html>
    <html>
    <head><title>XSS Demo</title></head>
    <body>
        <h3>Welcome {name}</h3>
        <p>Hello {name}, thank you for visiting!</p>
    </body>
    </html>
    """


# ==================== MAIN ====================

if __name__ == "__main__":
    logger.info("Starting VulnX_Pro v2.0")
    app.run(debug=True, host="127.0.0.1", port=5000)

