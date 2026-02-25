from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.crawler import crawl
from core.extractor import extract_forms
from core.sqli import scan_sqli
from core.xss import scan_xss
from config import THREADS

def test_url_parameters(url):
    results = []

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        return results

    for key in params:
        for payload in ["' OR 1=1--", "<script>alert(1)</script>"]:
            new_params = params.copy()
            new_params[key] = payload

            new_query = urlencode(new_params, doseq=True)
            new_url = urlunparse(parsed._replace(query=new_query))

            import requests
            r = requests.get(new_url)

            if payload in r.text:
                results.append(("Reflected XSS", url, payload))

            if "sql" in r.text.lower() or "mysql" in r.text.lower():
                results.append(("SQL Injection", url, payload))

    return results


def run_scan(target):
    results = []
    urls = crawl(target)

    def process(url):
        forms = extract_forms(url)

        # Form scanning
        for form in forms:
            results.extend(scan_sqli(url, form))
            results.extend(scan_xss(url, form))

        # URL parameter scanning
        results.extend(test_url_parameters(url))

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        executor.map(process, urls)

    return results