import requests
from urllib.parse import urljoin

def inject_payload(url, form, payload):
    target = urljoin(url, form["action"])
    data = {input_name: payload for input_name in form["inputs"]}

    try:
        if form["method"] == "post":
            response = requests.post(target, data=data)
        else:
            response = requests.get(target, params=data)

        return response.text
    except:
        return ""