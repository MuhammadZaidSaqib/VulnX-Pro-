import re
from core.payloads import SQL_ERRORS


def detect_xss(response, payload):
    if payload in response:
        return True

    script_pattern = re.compile(r"<script.*?>.*?</script>", re.IGNORECASE)
    return bool(script_pattern.search(response))


def detect_sqli(response):
    for error in SQL_ERRORS:
        if error.lower() in response.lower():
            return True
    return False


def boolean_based_check(resp_true, resp_false):
    return len(resp_true) != len(resp_false)