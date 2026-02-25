import requests
from bs4 import BeautifulSoup

def extract_forms(url):
    forms = []

    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, "lxml")

        for form in soup.find_all("form"):
            form_data = {
                "action": form.get("action"),
                "method": form.get("method", "get").lower(),
                "inputs": []
            }

            for input_tag in form.find_all("input"):
                name = input_tag.get("name")
                if name:
                    form_data["inputs"].append(name)

            forms.append(form_data)

    except Exception as e:
        print("Extractor error:", e)

    return forms