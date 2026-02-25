"""
Enhanced payload injection and management module.
Handles intelligent payload injection with proper error handling and logging.
"""
import logging
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin
import requests

from config import RATE_LIMIT_DELAY
from core.constants import SQLI_PAYLOADS, XSS_PAYLOADS

logger = logging.getLogger(__name__)


class PayloadInjector:
    """Handles payload injection with rate limiting and error handling"""

    def __init__(self, rate_limit_delay: float = RATE_LIMIT_DELAY, timeout: int = 5):
        """
        Initialize the injector.

        Args:
            rate_limit_delay: Delay between requests in seconds
            timeout: HTTP request timeout in seconds
        """
        self.rate_limit_delay = rate_limit_delay
        self.timeout = timeout
        self.last_request_time = 0

    def apply_rate_limit(self) -> None:
        """Apply rate limiting to prevent overwhelming target server"""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.rate_limit_delay:
            time.sleep(self.rate_limit_delay - elapsed)
        self.last_request_time = time.time()

    def inject(
        self,
        url: str,
        form: Dict[str, any],
        payload: str,
        method: Optional[str] = None
    ) -> str:
        """
        Inject payload into form and return response.

        Args:
            url: Base URL for the form
            form: Form dictionary with 'action', 'method', 'inputs'
            payload: Payload to inject into all inputs
            method: Override form method (GET/POST)

        Returns:
            Response text or empty string on failure
        """
        try:
            # Apply rate limiting
            self.apply_rate_limit()

            # Construct target URL
            target = urljoin(url, form.get("action", ""))
            if not target:
                target = url

            # Prepare data
            data = {name: payload for name in form.get("inputs", [])}
            if not data:
                data = {"input": payload}

            # Determine method
            form_method = (method or form.get("method", "get")).lower()

            # Execute request
            if form_method == "post":
                response = requests.post(target, data=data, timeout=self.timeout)
            else:
                response = requests.get(target, params=data, timeout=self.timeout)

            logger.debug(f"Injection to {target} returned status {response.status_code}")
            return response.text

        except requests.exceptions.Timeout:
            logger.warning(f"Timeout during payload injection to {url}")
            return ""
        except requests.exceptions.ConnectionError:
            logger.warning(f"Connection error during payload injection to {url}")
            return ""
        except Exception as e:
            logger.error(f"Error during payload injection: {e}")
            return ""

    def test_single_form(
        self,
        url: str,
        form: Dict[str, any],
        scan_type: str = "all"
    ) -> List[Tuple[str, str, str]]:
        """
        Test a single form with appropriate payloads.

        Args:
            url: Base URL
            form: Form to test
            scan_type: Type of scan ('sqli', 'xss', 'all')

        Returns:
            List of (vulnerability_type, endpoint, payload) tuples
        """
        results = []
        payloads_to_test = []

        if scan_type in ("all", "sqli"):
            payloads_to_test.extend([(p, "SQL Injection") for p in SQLI_PAYLOADS])
        if scan_type in ("all", "xss"):
            payloads_to_test.extend([(p, "Reflected XSS") for p in XSS_PAYLOADS])

        for payload, vuln_type in payloads_to_test:
            response = self.inject(url, form, payload)
            if response and payload in response:
                endpoint = form.get("action", url)
                results.append((vuln_type, endpoint, payload))
                logger.info(f"Found {vuln_type} at {endpoint}")

        return results


class BulkPayloadInjector(PayloadInjector):
    """Extended injector for batch operations with statistics"""

    def __init__(self, *args, **kwargs):
        """Initialize bulk injector"""
        super().__init__(*args, **kwargs)
        self.injection_count = 0
        self.error_count = 0

    def inject(self, url: str, form: Dict, payload: str, method: Optional[str] = None) -> str:
        """Override to track statistics"""
        self.injection_count += 1
        try:
            return super().inject(url, form, payload, method)
        except Exception:
            self.error_count += 1
            raise

    def get_stats(self) -> Dict[str, int]:
        """Get injection statistics"""
        return {
            "total_injections": self.injection_count,
            "errors": self.error_count,
            "success_rate": (
                (self.injection_count - self.error_count) / self.injection_count * 100
                if self.injection_count > 0
                else 0
            )
        }

    def reset_stats(self) -> None:
        """Reset injection statistics"""
        self.injection_count = 0
        self.error_count = 0

