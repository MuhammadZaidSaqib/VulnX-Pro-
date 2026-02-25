from core.payloads import XSS_PAYLOADS
from core.injector import inject

def scan_xss(url, form):
    results = []

    for payload in XSS_PAYLOADS:
        resp = inject(url, form, payload)
        if payload in resp:
            results.append(("Reflected XSS", form["action"], payload))

    return results