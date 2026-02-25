# VulnX_Pro - Complete Project Architecture Analysis

## 🎯 PROJECT CORE PURPOSE

**VulnX_Pro** is a **Web Vulnerability Scanner** designed to automatically detect and identify security vulnerabilities in web applications. It specifically targets:
- **SQL Injection (SQLi)** - Error-based and Boolean-based detection
- **Cross-Site Scripting (XSS)** - Reflected XSS vulnerabilities
- **Parameter-based vulnerabilities** in URLs and forms

The tool provides a web-based interface for scanning target websites and includes built-in vulnerable demo routes for testing and educational purposes.

---

## 🏗️ ARCHITECTURE OVERVIEW

### Architecture Type: **Modular Layered Architecture**

```
┌─────────────────────────────────────────────┐
│         PRESENTATION LAYER (Web UI)         │
│  ├── index.html (Main Dashboard)            │
│  ├── dashboard.html (Results Display)       │
│  └── dashboard.js (Frontend Logic)          │
└──────────────────┬──────────────────────────┘
                   │ HTTP API
┌──────────────────▼──────────────────────────┐
│      APPLICATION LAYER (Flask App)          │
│  ├── app.py (Route Handlers)                │
│  ├── /api/scan (Main Scanning Endpoint)     │
│  └── /demo/* (Vulnerable Demo Routes)       │
└──────────────────┬──────────────────────────┘
                   │ Orchestration
┌──────────────────▼──────────────────────────┐
│      CORE SCANNING LOGIC LAYER              │
│  ├── scanner.py (Main Orchestrator)         │
│  ├── crawler.py (Web Crawling)              │
│  ├── extractor.py (Form Extraction)         │
│  ├── injector.py (Payload Injection)        │
│  ├── sqli.py (SQL Injection Scanner)        │
│  ├── xss.py (XSS Scanner)                   │
│  ├── analyzer.py (Response Analysis)        │
│  └── payloads.py (Vulnerability Payloads)   │
└──────────────────┬──────────────────────────┘
                   │ Support Services
┌──────────────────▼──────────────────────────┐
│     SUPPORT & UTILITY LAYERS                │
│  ├── rate_limiter.py (Request Throttling)   │
│  ├── db.py (SQLite Database)                │
│  ├── logger.py (Logging Utility)            │
│  ├── validator.py (URL Validation)          │
│  └── config.py (Configuration)              │
└─────────────────────────────────────────────┘
```

---

## 📦 MODULE BREAKDOWN

### **1. PRESENTATION LAYER**

#### `templates/index.html`
- **Purpose**: Main dashboard interface
- **Features**:
  - Target URL input field
  - Event stream log display
  - Critical alerts panel
  - Scan progress indicator (circular progress)
  - Three vulnerability data charts (Chart.js)
- **Key Elements**: Target System, Event Stream, Alerts, Charts

#### `templates/dashboard.html`
- **Purpose**: Results display template
- **Renders**: Scan results with vulnerability details (type, endpoint, payload, severity)

#### `static/js/dashboard.js`
- **Purpose**: Frontend logic for dashboard interactions
- **Handles**: API calls, UI updates, chart rendering

#### `static/css/style.css`
- **Purpose**: Styling and layout for the web interface

---

### **2. APPLICATION LAYER (Flask)**

#### `app.py`
- **Port**: Runs on Flask development server (debug mode)
- **Main Routes**:
  - `GET /` - Home page (index.html)
  - `POST /api/scan` - Main scanning endpoint
  - `GET /demo` - Demo home page with vulnerable endpoints
  - `GET /demo/sqli` - SQL Injection vulnerable demo
  - `GET /demo/xss` - XSS vulnerable demo

**Scan Flow**:
```
POST /api/scan (target URL)
    │
    └─> run_scan(target) 
        │
        └─> Results stored in database
            │
            └─> JSON response with results
```

---

### **3. CORE SCANNING LAYER**

#### `core/scanner.py` (Main Orchestrator)
**Responsibility**: Coordinates the entire scanning process

**Scanning Pipeline**:
```
run_scan(target)
    │
    ├─> crawl(target)
    │   └─> Discover all URLs within target domain
    │
    ├─> For each discovered URL (parallel processing with ThreadPoolExecutor):
    │   │
    │   ├─> extract_forms(url)
    │   │   └─> Find all HTML forms
    │   │
    │   ├─> For each form:
    │   │   ├─> scan_sqli(url, form)
    │   │   └─> scan_xss(url, form)
    │   │
    │   └─> test_url_parameters(url)
    │       └─> Inject payloads into URL parameters
    │
    └─> Return consolidated results list
```

**Concurrency**: Uses `ThreadPoolExecutor` with configurable worker threads (default: 5)

#### `core/crawler.py` (Web Crawler)
- **Responsibility**: Discover all accessible URLs within a target domain
- **Algorithm**: Depth-first recursive crawling with cycle detection
- **Limits**:
  - Maximum depth: 2 levels (configurable)
  - Tracks visited URLs to avoid duplication
- **Process**:
  1. Extracts links from HTML using BeautifulSoup
  2. Validates that links belong to the target domain
  3. Recursively crawls child links up to MAX_DEPTH
  4. Returns deduplicated URL list

#### `core/extractor.py` (Form Extractor)
- **Responsibility**: Extract HTML form metadata
- **Extracts from each form**:
  - Form action URL
  - HTTP method (GET/POST)
  - Input field names
- **Returns**: List of form data structures for vulnerability testing

#### `core/injector.py` (Payload Injection)
- **Responsibility**: Execute payload injections into forms/parameters
- **Process**:
  1. Takes target URL, form data, and payload
  2. Applies rate limiting before request
  3. Constructs request based on form method (GET/POST)
  4. Returns response text for analysis
- **Key Feature**: Rate limiting to avoid overwhelming target servers

#### `core/sqli.py` (SQL Injection Scanner)
- **Scanning Techniques**:
  1. **Error-based SQLi**: Injects payloads and detects SQL error messages
  2. **Boolean-based SQLi**: Injects True/False conditions and analyzes response differences
- **Detection Logic**:
  - Uses payload list from `payloads.py`
  - Compares response lengths to detect boolean-based SQLi
  - Marks results with different severity labels

#### `core/xss.py` (XSS Scanner)
- **Scanning Technique**: Reflected XSS detection
- **Process**:
  1. Injects XSS payloads into form inputs
  2. Checks if payload appears unencoded in response
  3. Indicates successful reflection vulnerability
- **Payload Types**: Script tags, event handlers, img tags

#### `core/analyzer.py` (Response Analyzer)
- **detect_sqli()**: Searches for SQL error keywords in responses
- **boolean_based_check()**: Compares response sizes to detect logic-based SQLi
- **SQL_ERRORS**: Predefined list of common SQL error patterns

#### `core/payloads.py` (Payload Library)
```python
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "'\"><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>"
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR 1=1--",
    "' UNION SELECT NULL--"
]

SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    ...
]
```

---

### **4. SUPPORT & UTILITY LAYER**

#### `core/rate_limiter.py`
- **Purpose**: Throttle requests to avoid overwhelming target servers
- **Implementation**: Simple time-based delay (default: 0.4 seconds)
- **Usage**: Called before each injection request

#### `database/db.py`
- **Database**: SQLite (`vulnx.db`)
- **Schema**: Single table `vulnerabilities`
  - `id`: Auto-increment primary key
  - `target`: Target URL
  - `type`: Vulnerability type (SQLi, XSS, etc.)
  - `endpoint`: Vulnerable endpoint
  - `payload`: Injected payload
- **Functions**:
  - `init_db()`: Create database and schema
  - `save_results()`: Insert scan results into database

#### `utils/logger.py`
- **Purpose**: Centralized logging utility
- **Format**: Prefixes messages with "[VulnX]"

#### `utils/validator.py`
- **Purpose**: URL validation
- **Function**: `is_valid_url()` - Validates URL format (scheme + netloc)

#### `config.py` (Global Configuration)
```python
MAX_DEPTH = 2                  # Crawler depth limit
REQUEST_TIMEOUT = 5            # HTTP request timeout (seconds)
THREADS = 5                    # Concurrent worker threads
RATE_LIMIT_DELAY = 0.4         # Delay between requests (seconds)
USER_AGENT = "VulnX_Pro-Scanner"
```

---

## 🔄 SCANNING WORKFLOW

### **Complete Request Flow**:

```
1. USER INPUT
   └─> Enters target URL in web interface
       └─> Clicks "START SCAN"

2. HTTP REQUEST
   └─> POST /api/scan
       └─> JSON body: {"target": "https://example.com"}

3. SCANNING ORCHESTRATION (scanner.py)
   └─> crawl(target)
       ├─> Discover URLs
       └─> Returns: [url1, url2, url3, ...]

4. PARALLEL PROCESSING (ThreadPoolExecutor)
   ├─> Thread 1: Process URL1
   │   ├─> extract_forms(url1)
   │   ├─> For each form:
   │   │   ├─> scan_sqli() → Inject payloads, analyze
   │   │   └─> scan_xss() → Inject payloads, analyze
   │   └─> test_url_parameters()
   │
   ├─> Thread 2: Process URL2 (same as above)
   └─> Thread N: Process URLn (same as above)

5. RESPONSE ANALYSIS
   ├─> detect_sqli(): Find SQL error messages
   ├─> boolean_based_check(): Compare response sizes
   └─> Detect reflected payloads for XSS

6. RESULTS AGGREGATION
   └─> Collect findings: [
           ("SQL Injection", "/admin/login", "' OR 1=1--"),
           ("Reflected XSS", "/search", "<script>alert(1)</script>"),
           ...
       ]

7. DATABASE STORAGE
   └─> save_results(target, results)
       └─> Insert into vulnerabilities table

8. API RESPONSE
   └─> Return JSON:
       {
           "count": 3,
           "results": [
               {"type": "SQLi", "endpoint": "...", "payload": "..."},
               ...
           ]
       }

9. FRONTEND UPDATE
   └─> dashboard.js renders results
       └─> Updates charts and alerts
```

---

## 🛡️ VULNERABILITY DETECTION TECHNIQUES

### **SQL Injection Detection**
1. **Error-based**: Looks for SQL syntax errors in responses
2. **Boolean-based**: Injects `TRUE` and `FALSE` conditions, compares response sizes
3. **Common Payloads**:
   - `' OR '1'='1`
   - `' OR 1=1--`
   - `" OR 1=1--`
   - `' UNION SELECT NULL--`

### **XSS Detection**
1. **Reflected XSS**: Checks if payload appears unencoded in response
2. **Common Payloads**:
   - `<script>alert(1)</script>`
   - `'\"><script>alert(1)</script>`
   - `<img src=x onerror=alert(1)>`

### **Parameter Testing**
- Extracts URL query parameters
- Injects XSS and SQLi payloads
- Checks for reflected content or SQL errors

---

## 🎓 BUILT-IN DEMO VULNERABLE ENDPOINTS

### Purpose: Testing and Educational Demonstration

#### `/demo/sqli?id=<value>`
- **Vulnerability**: SQL Injection (Intentional)
- **Behavior**:
  - Returns SQL error message if payload contains `'` or `OR`
  - Shows error: "You have an error in your SQL syntax near..."
  - Safe input returns: "User ID: {value}"

#### `/demo/xss?name=<value>`
- **Vulnerability**: Reflected XSS (Intentional)
- **Behavior**:
  - Reflects user input without encoding
  - Returns: `<h3>Hello {name}</h3>`
  - Any injected HTML/JavaScript executes

---

## 📊 DATA FLOW DIAGRAM

```
┌─────────────────┐
│  Web Browser    │
│  (index.html)   │
└────────┬────────┘
         │ (AJAX POST /api/scan)
         ▼
┌─────────────────────────────────┐
│    Flask Application            │
│    (app.py - Route Handler)     │
└────────┬────────────────────────┘
         │
         ▼
┌─────────────────────────────────┐
│  Scanner Orchestrator           │
│  (core/scanner.py - run_scan)   │
└────────┬────────────────────────┘
         │
         ├─────────────────────────────────┐
         │                                 │
         ▼                                 ▼
  ┌─────────────┐            ┌────────────────────┐
  │  Crawler    │            │ Extractor & Forms  │
  │ Discovers   │            │ Analysis           │
  │   URLs      │            └────────────────────┘
  └─────────────┘
         │
         └────────────────┬───────────────┘
                          ▼
            ┌──────────────────────────┐
            │  Parallel Processing     │
            │  (ThreadPoolExecutor)    │
            └────────────┬─────────────┘
                         │
         ┌───────────────┼───────────────┐
         │               │               │
         ▼               ▼               ▼
    ┌────────┐      ┌────────┐      ┌────────┐
    │ SQLi   │      │  XSS   │      │ Param  │
    │Scanner │      │Scanner │      │ Test   │
    └─────┬──┘      └───┬────┘      └───┬────┘
          │             │               │
          └─────────────┼───────────────┘
                        │
                        ▼
          ┌──────────────────────────┐
          │ Response Analyzer        │
          │ - detect_sqli()          │
          │ - Payload Detection      │
          └────────────┬─────────────┘
                       │
                       ▼
          ┌──────────────────────────┐
          │ Results Aggregation      │
          │ (List of vulnerabilities)│
          └────────────┬─────────────┘
                       │
         ┌─────────────┼─────────────┐
         │             │             │
         ▼             ▼             ▼
    ┌────────┐  ┌──────────┐  ┌──────────┐
    │Database│  │ API JSON │  │ Frontend │
    │ Store  │  │ Response │  │  Update  │
    └────────┘  └──────────┘  └──────────┘
```

---

## 🔐 SECURITY CONSIDERATIONS

### Built-in Safeguards:
1. **Rate Limiting**: 0.4-second delays between requests prevent DoS
2. **Timeout Protection**: 5-second HTTP timeout prevents hanging
3. **Depth Limiting**: Crawling limited to 2 levels prevents infinite recursion
4. **Thread Pooling**: Limited to 5 concurrent threads for resource control
5. **Domain Validation**: Crawler only follows links within target domain

### Intended Use Cases:
- ✅ Security testing of authorized web applications
- ✅ Vulnerability assessment during penetration testing
- ✅ Educational demonstrations of web vulnerabilities
- ✅ Learning security scanning techniques

---

## 📈 SCALABILITY & PERFORMANCE

### Concurrency Model:
- Uses `ThreadPoolExecutor` for parallel URL scanning
- Default: 5 concurrent threads (configurable)
- Each thread independently processes forms and payloads

### Performance Characteristics:
- **Crawling**: O(n) where n = number of discoverable URLs
- **Scanning**: O(n × f × p) where:
  - n = number of URLs
  - f = forms per URL
  - p = payloads per scanner type
- **Rate Limiting**: 0.4s × (total requests) seconds minimum

### Resource Usage:
- Memory: Minimal (BeautifulSoup parsing + threading overhead)
- Network: Controlled by rate limiting and timeouts
- CPU: Parallelized across thread pool

---

## 🎯 KEY COMPONENTS SUMMARY

| Component | Purpose | Language | Key Dependency |
|-----------|---------|----------|-----------------|
| app.py | Flask routing & API | Python | Flask |
| crawler.py | URL discovery | Python | BeautifulSoup4 |
| extractor.py | Form extraction | Python | BeautifulSoup4 |
| scanner.py | Orchestration | Python | concurrent.futures |
| sqli.py | SQLi detection | Python | requests |
| xss.py | XSS detection | Python | requests |
| injector.py | Payload injection | Python | requests |
| analyzer.py | Response analysis | Python | - |
| rate_limiter.py | Request throttling | Python | - |
| db.py | Data persistence | Python | sqlite3 |
| dashboard.js | Frontend logic | JavaScript | Chart.js |

---

## 🚀 TECHNOLOGY STACK

```
Backend:
├── Python 3.x
├── Flask (Web Framework)
├── BeautifulSoup4 (HTML Parsing)
├── requests (HTTP Library)
├── sqlite3 (Database)
├── concurrent.futures (Threading)
└── lxml (XML Parser)

Frontend:
├── HTML5
├── CSS3
├── JavaScript (Vanilla)
└── Chart.js (Data Visualization)

Configuration:
├── config.py (Global Settings)
├── requirements.txt (Dependencies)
└── .env (Environment Variables - if used)
```

---

## 💾 DATABASE SCHEMA

```sql
CREATE TABLE vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT,                -- Target URL
    type TEXT,                  -- Vulnerability type
    endpoint TEXT,              -- Vulnerable endpoint
    payload TEXT                -- Successful payload
);
```

---

## 📋 PROJECT STRENGTHS

1. ✅ **Modular Design**: Clear separation of concerns
2. ✅ **Parallel Processing**: Efficient concurrent scanning
3. ✅ **Multiple Detection Methods**: Error-based, Boolean-based, Reflected XSS
4. ✅ **Web UI**: User-friendly dashboard with real-time charts
5. ✅ **Rate Limiting**: Respectful scanning with throttling
6. ✅ **Demo Vulnerable App**: Built-in test targets
7. ✅ **Database Persistence**: Stores results for later review
8. ✅ **Configurable**: Easy parameter adjustment in config.py

---

## 🔧 AREAS FOR ENHANCEMENT

1. **Authentication**: Add user login/multi-tenant support
2. **Advanced Detection**: Add stored XSS, CSRF, authentication bypass detection
3. **Reporting**: Generate PDF/HTML reports with severity ratings
4. **API Documentation**: Add Swagger/OpenAPI specs
5. **Error Handling**: More granular exception handling
6. **Logging**: Structured logging with severity levels
7. **URL Validation**: Enhanced validator for edge cases
8. **Payload Customization**: User-defined custom payloads

---

## 📝 SUMMARY

**VulnX_Pro** is a **specialized web vulnerability scanner** that uses a **modular layered architecture** to:

1. **Discover** all accessible URLs via crawling
2. **Extract** HTML forms and URL parameters
3. **Inject** SQL and XSS payloads in parallel
4. **Analyze** server responses for vulnerability indicators
5. **Store** findings in SQLite database
6. **Display** results through a web-based dashboard

The tool demonstrates professional security scanning practices with rate limiting, concurrent processing, and multiple detection techniques. It's designed for educational purposes and authorized security testing of web applications.


