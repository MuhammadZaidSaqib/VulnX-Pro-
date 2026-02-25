import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from config import REQUEST_TIMEOUT, USER_AGENT

visited = set()

def crawl(url, depth=0, max_depth=2):
    if depth > max_depth or url in visited:
        return []

    visited.add(url)
    urls = [url]

    try:
        headers = {"User-Agent": USER_AGENT}
        response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        soup = BeautifulSoup(response.text, "lxml")

        for link in soup.find_all("a", href=True):
            full_url = urljoin(url, link["href"])
            if full_url.startswith(url):
                urls.extend(crawl(full_url, depth + 1, max_depth))

    except Exception:
        pass

    return list(set(urls))