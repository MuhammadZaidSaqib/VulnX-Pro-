def assign_severity(vuln_type):
    if vuln_type == "SQL Injection":
        return "Critical"
    elif vuln_type == "Reflected XSS":
        return "High"
    return "Medium"