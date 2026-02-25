from core.payloads import SQLI_PAYLOADS
from core.injector import inject_payload
from core.analyzer import detect_sqli

def scan_sqli(url, forms):
    results = []

    for form in forms:
        for payload in SQLI_PAYLOADS:
            response = inject_payload(url, form, payload)

            if detect_sqli(response):
                results.append({
                    "type": "SQL Injection",
                    "endpoint": form["action"],
                    "payload": payload
                })

    return results