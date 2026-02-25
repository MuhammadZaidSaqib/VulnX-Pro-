"""
HTML form extraction and analysis module.
Extracts form metadata for vulnerability testing.
"""
import logging
from typing import Dict, List
import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


class FormExtractor:
    """Extracts HTML form metadata from web pages"""

    def __init__(self, timeout: int = 5):
        """
        Initialize form extractor.

        Args:
            timeout: HTTP request timeout in seconds
        """
        self.timeout = timeout

    def extract_forms(self, url: str) -> List[Dict[str, any]]:
        """
        Extract all forms from a URL.

        Args:
            url: URL to extract forms from

        Returns:
            List of form dictionaries with action, method, and inputs
        """
        forms = []

        try:
            response = requests.get(url, timeout=self.timeout)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, "lxml")

            for idx, form in enumerate(soup.find_all("form")):
                form_data = self._parse_form(form, url, idx)
                if form_data:
                    forms.append(form_data)

        except requests.exceptions.Timeout:
            logger.warning(f"Timeout extracting forms from {url}")
        except requests.exceptions.RequestException as e:
            logger.warning(f"Error extracting forms from {url}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error extracting forms: {e}")

        return forms

    @staticmethod
    def _parse_form(form, base_url: str, form_index: int) -> Dict[str, any]:
        """
        Parse a single form element.

        Args:
            form: BeautifulSoup form element
            base_url: Base URL for resolving relative actions
            form_index: Index of form on page

        Returns:
            Form data dictionary or None if invalid
        """
        try:
            form_data = {
                "id": f"form_{form_index}",
                "action": form.get("action") or "",
                "method": form.get("method", "get").lower(),
                "inputs": [],
                "textareas": [],
                "selects": []
            }

            # Extract input fields
            for input_tag in form.find_all("input"):
                name = input_tag.get("name")
                input_type = input_tag.get("type", "text")
                if name:
                    form_data["inputs"].append({
                        "name": name,
                        "type": input_type,
                        "value": input_tag.get("value", "")
                    })

            # Extract textarea fields
            for textarea in form.find_all("textarea"):
                name = textarea.get("name")
                if name:
                    form_data["textareas"].append({
                        "name": name,
                        "value": textarea.get_text("")
                    })

            # Extract select fields
            for select in form.find_all("select"):
                name = select.get("name")
                if name:
                    options = [opt.get("value", opt.get_text()) for opt in select.find_all("option")]
                    form_data["selects"].append({
                        "name": name,
                        "options": options
                    })

            return form_data

        except Exception as e:
            logger.error(f"Error parsing form: {e}")
            return None

    def get_all_field_names(self, form: Dict[str, any]) -> List[str]:
        """
        Get all input field names from a form.

        Args:
            form: Form dictionary

        Returns:
            List of all field names
        """
        names = []
        names.extend([inp["name"] for inp in form.get("inputs", [])])
        names.extend([ta["name"] for ta in form.get("textareas", [])])
        names.extend([sel["name"] for sel in form.get("selects", [])])
        return names

    def filter_by_type(self, forms: List[Dict], form_type: str = "all") -> List[Dict]:
        """
        Filter forms by method type.

        Args:
            forms: List of forms
            form_type: Filter type ('get', 'post', 'all')

        Returns:
            Filtered list of forms
        """
        if form_type.lower() == "all":
            return forms
        return [f for f in forms if f.get("method", "get").lower() == form_type.lower()]

    def has_vulnerable_inputs(self, form: Dict[str, any]) -> bool:
        """
        Check if form has potentially vulnerable input types.

        Args:
            form: Form dictionary

        Returns:
            True if form has user input fields
        """
        inputs = form.get("inputs", [])
        textareas = form.get("textareas", [])

        # Check for typical vulnerable input types
        for inp in inputs:
            input_type = inp.get("type", "text").lower()
            # Skip buttons, submits, and hidden fields
            if input_type not in ("submit", "button", "reset", "hidden"):
                return True

        return len(textareas) > 0

