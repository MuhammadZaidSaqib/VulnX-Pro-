import requests
from urllib.parse import urljoin
from core.rate_limiter import apply_rate_limit

def inject(url, form, payload):
    apply_rate_limit()

    target = urljoin(url, form["action"])
    data = {name: payload for name in form["inputs"]}

    try:
        if form["method"] == "post":
            r = requests.post(target, data=data, timeout=5)
        else:
            r = requests.get(target, params=data, timeout=5)

        return r.text

    except Exception:
        return ""