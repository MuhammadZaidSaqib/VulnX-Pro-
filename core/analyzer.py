from core.payloads import SQL_ERRORS

def detect_sqli(response):
    for error in SQL_ERRORS:
        if error.lower() in response.lower():
            return True
    return False

def boolean_based_check(resp_true, resp_false):
    return len(resp_true) != len(resp_false)