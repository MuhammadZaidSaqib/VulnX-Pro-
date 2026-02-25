from core.crawler import crawl
from core.extractor import extract_forms
from core.xss_scanner import scan_xss
from core.sqli_scanner import scan_sqli
from core.severity import assign_severity

def run_scan(target):
    results = []
    urls = crawl(target)

    for url in urls:
        forms = extract_forms(url)

        xss_results = scan_xss(url, forms)
        sqli_results = scan_sqli(url, forms)

        all_results = xss_results + sqli_results

        for vuln in all_results:
            vuln["severity"] = assign_severity(vuln["type"])
            results.append(vuln)

    return results