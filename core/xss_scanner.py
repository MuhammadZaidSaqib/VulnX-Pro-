from core.payloads import XSS_PAYLOADS
from core.injector import inject_payload
from core.analyzer import detect_xss

def scan_xss(url, forms):
    results = []

    for form in forms:
        for payload in XSS_PAYLOADS:
            response = inject_payload(url, form, payload)

            if detect_xss(response, payload):
                results.append({
                    "type": "Reflected XSS",
                    "endpoint": form["action"],
                    "payload": payload
                })

    return results