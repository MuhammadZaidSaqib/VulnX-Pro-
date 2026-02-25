# VulnX_Pro - Web Vulnerability Scanner

<div align="center">

![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-green.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)
![Status](https://img.shields.io/badge/status-production--ready-success.svg)

**A powerful, modular vulnerability scanner for identifying SQL injection and XSS vulnerabilities in web applications.**

[Features](#features) • [Installation](#installation) • [Usage](#usage) • [Documentation](#documentation) • [Demo](#demo)

</div>

---

## 🎯 Features

- ✅ **Automatic URL Discovery** - Intelligent web crawling to discover all endpoints
- ✅ **SQL Injection Detection** - Error-based and Boolean-based SQLi detection
- ✅ **XSS Detection** - Reflected XSS vulnerability identification
- ✅ **HTML Form Analysis** - Automatic form extraction and testing
- ✅ **Parallel Scanning** - Multi-threaded concurrent vulnerability testing
- ✅ **Web Dashboard** - Modern, user-friendly interface with real-time charts
- ✅ **RESTful API** - Programmatic access to scanning functionality
- ✅ **Results Persistence** - SQLite database storage for scan history
- ✅ **Rate Limiting** - Respectful scanning with configurable delays
- ✅ **Comprehensive Logging** - Detailed operation and error tracking

---

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- pip package manager
- Virtual environment (recommended)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/VulnX_Pro.git
   cd VulnX_Pro
   ```

2. **Create and activate virtual environment**
   ```bash
   # Windows
   python -m venv .venv
   .venv\Scripts\activate

   # Linux/Mac
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the application**
   ```bash
   python app_v2.py
   ```

5. **Access the dashboard**
   ```
   Open browser: http://localhost:5000
   ```

---

## 📖 Usage

### Web Interface

1. **Launch the application**
   ```bash
   python app_v2.py
   ```

2. **Open your browser**
   Navigate to `http://localhost:5000`

3. **Enter target URL**
   Input the target website URL (e.g., `https://example.com`)

4. **Start scan**
   Click "START SCAN" button

5. **View results**
   Monitor real-time scanning progress and view detected vulnerabilities

### API Usage

#### Full Scan (with crawling)
```bash
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com"}'
```

#### Fast Scan (single page)
```bash
curl -X POST http://localhost:5000/api/scan-fast \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com"}'
```

#### Health Check
```bash
curl http://localhost:5000/api/status
```

### Python Script

```python
import requests

# Start a scan
response = requests.post(
    "http://localhost:5000/api/scan",
    json={"target": "https://example.com"}
)

results = response.json()
print(f"Found {results['count']} vulnerabilities")

for vuln in results['results']:
    print(f"- {vuln['type']} at {vuln['endpoint']}")
```

---

## 🏗️ Architecture

VulnX_Pro uses a modular, layered architecture:

```
┌─────────────────────────────────┐
│   Web UI (Dashboard)            │
│   Templates + Static Assets     │
└────────────┬────────────────────┘
             │
┌────────────▼────────────────────┐
│   Flask Application (app_v2.py) │
│   REST API Endpoints             │
└────────────┬────────────────────┘
             │
┌────────────▼────────────────────┐
│   Core Scanning Engine           │
│   ├─ VulnerabilityScanner        │
│   ├─ WebCrawler (thread-safe)   │
│   ├─ FormExtractor               │
│   ├─ PayloadInjector             │
│   └─ Detectors                   │
│       ├─ SQLInjectionScanner     │
│       ├─ XSSScanner               │
│       └─ ParameterScanner        │
└────────────┬────────────────────┘
             │
┌────────────▼────────────────────┐
│   Support Layer                  │
│   ├─ Database (SQLite)           │
│   ├─ Configuration               │
│   ├─ Logging                     │
│   └─ Utilities                   │
└─────────────────────────────────┘
```

### Key Components

- **scanner_v2.py** - Main orchestrator coordinating the scanning process
- **crawler_v2.py** - Thread-safe URL discovery and crawling
- **extractor_v2.py** - HTML form extraction and analysis
- **injector_v2.py** - Payload injection with rate limiting
- **detectors_v2.py** - Vulnerability detection algorithms
- **app_v2.py** - Flask application with REST API
- **config_v2.py** - Configuration management

---

## 📁 Project Structure

```
VulnX_Pro/
├── app_v2.py                   # Enhanced Flask application
├── config_v2.py                # Configuration management
├── requirements.txt             # Project dependencies
│
├── core/                       # Core scanning engine
│   ├── scanner_v2.py           # Main orchestrator
│   ├── crawler_v2.py           # URL discovery
│   ├── extractor_v2.py         # Form extraction
│   ├── injector_v2.py          # Payload injection
│   ├── detectors_v2.py         # Vulnerability detection
│   └── constants.py            # Payloads & constants
│
├── database/                   # Data persistence
│   ├── db.py                   # Database operations
│   └── vulnx.db                # SQLite database
│
├── utils/                      # Utilities
│   ├── helpers_v2.py           # Helper functions
│   ├── logger.py               # Logging
│   └── validator.py            # URL validation
│
├── templates/                  # HTML templates
│   ├── index.html              # Main dashboard
│   ├── dashboard.html          # Results page
│   └── layout.html             # Base layout
│
└── static/                     # Frontend assets
    ├── css/style.css           # Stylesheets
    └── js/dashboard.js         # JavaScript
```

---

## 🔧 Configuration

Edit `config_v2.py` to customize scanner behavior:

```python
# Crawler settings
MAX_DEPTH = 2                # Maximum crawl depth
REQUEST_TIMEOUT = 5          # Request timeout (seconds)

# Threading
THREADS = 5                  # Concurrent worker threads

# Rate limiting
RATE_LIMIT_DELAY = 0.4       # Delay between requests (seconds)

# User agent
USER_AGENT = "VulnX_Pro-Scanner/2.0"
```

---

## 🎮 Demo Vulnerabilities

VulnX_Pro includes built-in vulnerable endpoints for testing:

### SQL Injection Demo
```
http://localhost:5000/demo/sqli?id=1
```
Try: `id=' OR '1'='1`

### XSS Demo
```
http://localhost:5000/demo/xss?name=test
```
Try: `name=<script>alert('XSS')</script>`

---

## 🔍 Vulnerability Detection

### SQL Injection
- **Error-based Detection** - Identifies SQL syntax errors in responses
- **Boolean-based Detection** - Analyzes TRUE/FALSE condition responses
- **Payloads**:
  - `' OR '1'='1`
  - `' OR 1=1--`
  - `" OR 1=1--`
  - `' UNION SELECT NULL--`

### Cross-Site Scripting (XSS)
- **Reflected XSS** - Detects unencoded payload reflection
- **Payloads**:
  - `<script>alert(1)</script>`
  - `'\"><script>alert(1)</script>`
  - `<img src=x onerror=alert(1)>`

---

## 📊 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/scan` | POST | Full scan with crawling |
| `/api/scan-fast` | POST | Fast scan (single URL) |
| `/api/status` | GET | Health check |

### Response Format

```json
{
  "success": true,
  "target": "https://example.com",
  "count": 3,
  "results": [
    {
      "type": "SQL Injection",
      "endpoint": "/login",
      "payload": "' OR '1'='1",
      "timestamp": "2026-02-26T10:30:45"
    }
  ],
  "summary": {
    "total_vulnerabilities": 3,
    "total_urls_discovered": 5,
    "vulnerabilities_by_type": {
      "SQL Injection": 1,
      "Reflected XSS": 2
    }
  }
}
```

---

## 🛡️ Security Considerations

### ⚠️ Legal Notice

**USE ONLY FOR AUTHORIZED TESTING**

This tool is designed for:
- ✅ Testing your own applications
- ✅ Authorized security assessments with written permission
- ✅ Educational purposes in controlled environments

**DO NOT USE FOR:**
- ❌ Unauthorized testing of systems you don't own
- ❌ Production systems without approval
- ❌ Malicious or illegal activities

**Disclaimer:** The authors assume no liability for misuse or damage caused by this tool. Always obtain proper authorization before conducting security assessments.

### Built-in Safety Features

- ✅ **Rate Limiting** - Prevents overwhelming target servers
- ✅ **Request Timeouts** - Avoids hanging on unresponsive servers
- ✅ **Depth Limiting** - Prevents infinite crawling loops
- ✅ **Domain Validation** - Stays within target domain only
- ✅ **Thread Control** - Limited concurrent connections

---

## 📚 Documentation

- **[Architecture Analysis](ARCHITECTURE_ANALYSIS.md)** - Detailed architecture documentation
- **[Folder Structure](Folder%20Structure)** - Project organization guide
- **API Documentation** - REST API reference (see API Endpoints section)

---

## 🧪 Testing

### Manual Testing

1. Start the demo vulnerable application:
   ```bash
   python app_v2.py
   ```

2. Access demo endpoints:
   - SQL Injection: `http://localhost:5000/demo/sqli`
   - XSS: `http://localhost:5000/demo/xss`

3. Run a scan against the demo:
   ```bash
   curl -X POST http://localhost:5000/api/scan \
     -H "Content-Type: application/json" \
     -d '{"target": "http://localhost:5000/demo"}'
   ```

---

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

```bash
# Install development dependencies
pip install -r requirements.txt

# Run with debug mode
python app_v2.py
```

---

## 🐛 Troubleshooting

### Common Issues

**Issue: Port 5000 already in use**
```bash
# Solution: Change port in app_v2.py
app.run(debug=True, host="127.0.0.1", port=5001)
```

**Issue: Module not found errors**
```bash
# Solution: Ensure virtual environment is activated
.venv\Scripts\activate  # Windows
source .venv/bin/activate  # Linux/Mac

# Reinstall dependencies
pip install -r requirements.txt
```

**Issue: Database errors**
```bash
# Solution: Delete and reinitialize database
rm database/vulnx.db
python -c "from database.db import init_db; init_db()"
```

---

## 📝 Changelog

### Version 2.0.0 (February 26, 2026)
- ✨ Complete codebase refactoring with modular architecture
- ✨ Thread-safe WebCrawler with proper state management
- ✨ Specialized scanners: SQLInjectionScanner, XSSScanner, ParameterScanner
- ✨ VulnerabilityScanner orchestrator with parallel processing
- ✨ Enhanced configuration with environment-based settings
- ✨ Improved error handling and comprehensive logging
- ✨ Type hints and docstrings throughout codebase
- ✨ Better code organization and maintainability

### Version 1.0.0 (Initial Release)
- 🎉 Initial release with basic scanning functionality
- 🎉 SQL injection and XSS detection
- 🎉 Web dashboard interface
- 🎉 REST API endpoints

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👥 Authors

- **Muhammad Zaid Saqib** - *Initial work* - [GitHub Profile](https://github.com/yourusername)

---

## 🙏 Acknowledgments

- **Flask** - Web framework
- **BeautifulSoup4** - HTML parsing
- **Requests** - HTTP library
- **Chart.js** - Dashboard visualizations
- Community contributors and testers

---

## 📞 Support

- 📧 **Email:** B24F1722CYS084@paf-iast.edu.pk
- 🐛 **Issues:** [GitHub Issues](https://github.com/yourusername/VulnX_Pro/issues)
- 💬 **Discussions:** [GitHub Discussions](https://github.com/yourusername/VulnX_Pro/discussions)

---

## 🌟 Star History

If you find this project useful, please consider giving it a ⭐ on GitHub!

---

<div align="center">

**Made with ❤️ by Muhammad Zaid Saqib**

*For educational and authorized testing purposes only*

[⬆ Back to Top](#vulnx_pro---web-vulnerability-scanner)

</div>

