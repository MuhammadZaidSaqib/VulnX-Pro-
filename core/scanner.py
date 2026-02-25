from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import requests

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
            try:
                new_params = params.copy()
                new_params[key] = payload

                new_query = urlencode(new_params, doseq=True)
                new_url = urlunparse(parsed._replace(query=new_query))

                r = requests.get(new_url, timeout=5)

                if payload in r.text:
                    results.append(("Reflected XSS", url, payload))

                if "sql" in r.text.lower() or "mysql" in r.text.lower():
                    results.append(("SQL Injection", url, payload))

            except Exception:
                continue

    return results


def run_scan(target):
    results = []
    urls = crawl(target)

    def process(url):
        local_results = []

        forms = extract_forms(url)

        for form in forms:
            local_results.extend(scan_sqli(url, form))
            local_results.extend(scan_xss(url, form))

        local_results.extend(test_url_parameters(url))

        return local_results

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = executor.map(process, urls)

        for result in futures:
            results.extend(result)

    return results