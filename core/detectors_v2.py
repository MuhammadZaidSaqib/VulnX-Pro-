"""
Vulnerability detection and analysis module.
Implements multiple detection techniques for SQL injection and XSS.
"""
import logging
from typing import Dict, List, Tuple
from core.constants import SQL_ERRORS, SQLI_PAYLOADS, XSS_PAYLOADS

logger = logging.getLogger(__name__)


class VulnerabilityAnalyzer:
    """Core vulnerability analysis and detection logic"""

    @staticmethod
    def detect_sqli_error(response: str) -> bool:
        """
        Detect SQL injection via error-based method.

        Args:
            response: HTTP response text

        Returns:
            True if SQL errors detected in response
        """
        response_lower = response.lower()
        return any(error.lower() in response_lower for error in SQL_ERRORS)

    @staticmethod
    def detect_sqli_boolean(resp_true: str, resp_false: str, threshold: float = 0.1) -> bool:
        """
        Detect SQL injection via boolean-based method.

        Args:
            resp_true: Response for TRUE condition
            resp_false: Response for FALSE condition
            threshold: Minimum response size difference ratio

        Returns:
            True if boolean-based SQLi detected
        """
        if not resp_true or not resp_false:
            return False

        true_len = len(resp_true)
        false_len = len(resp_false)

        if true_len == 0 or false_len == 0:
            return False

        # Calculate difference ratio
        diff_ratio = abs(true_len - false_len) / max(true_len, false_len)
        return diff_ratio > threshold

    @staticmethod
    def detect_xss_reflected(response: str, payload: str) -> bool:
        """
        Detect reflected XSS by checking if payload appears unencoded.

        Args:
            response: HTTP response text
            payload: Injected payload

        Returns:
            True if payload found unencoded in response
        """
        if not response or not payload:
            return False
        return payload in response

    @staticmethod
    def analyze_response(
        response: str,
        injected_payload: str,
        scan_type: str = "all"
    ) -> List[str]:
        """
        Analyze response for multiple vulnerability types.

        Args:
            response: HTTP response text
            injected_payload: The payload that was injected
            scan_type: Type of scan to perform ('sqli', 'xss', 'all')

        Returns:
            List of detected vulnerability types
        """
        detected = []

        if scan_type in ("all", "sqli"):
            if VulnerabilityAnalyzer.detect_sqli_error(response):
                detected.append("SQL Injection (Error-based)")

        if scan_type in ("all", "xss"):
            if VulnerabilityAnalyzer.detect_xss_reflected(response, injected_payload):
                detected.append("Reflected XSS")

        return detected


class SQLInjectionScanner:
    """Specialized scanner for SQL injection detection"""

    def __init__(self, analyzer: VulnerabilityAnalyzer = None):
        """
        Initialize SQL injection scanner.

        Args:
            analyzer: VulnerabilityAnalyzer instance
        """
        self.analyzer = analyzer or VulnerabilityAnalyzer()

    def scan_form(self, url: str, form: Dict, injector) -> List[Tuple[str, str, str]]:
        """
        Scan a form for SQL injection vulnerabilities.

        Args:
            url: Base URL
            form: Form dictionary
            injector: PayloadInjector instance

        Returns:
            List of (vulnerability_type, endpoint, payload) tuples
        """
        results = []
        endpoint = form.get("action", url)

        # Error-based SQLi
        for payload in SQLI_PAYLOADS:
            resp = injector.inject(url, form, payload)
            if self.analyzer.detect_sqli_error(resp):
                results.append(("SQL Injection", endpoint, payload))
                logger.info(f"SQL Injection (error-based) detected at {endpoint}")
                break  # Found vulnerability, no need to test more

        # Boolean-based SQLi
        resp_true = injector.inject(url, form, "' OR 1=1--")
        resp_false = injector.inject(url, form, "' OR 1=2--")

        if self.analyzer.detect_sqli_boolean(resp_true, resp_false):
            results.append(("Blind SQL Injection", endpoint, "Boolean Based"))
            logger.info(f"Blind SQL Injection (boolean-based) detected at {endpoint}")

        return results


class XSSScanner:
    """Specialized scanner for XSS detection"""

    def __init__(self, analyzer: VulnerabilityAnalyzer = None):
        """
        Initialize XSS scanner.

        Args:
            analyzer: VulnerabilityAnalyzer instance
        """
        self.analyzer = analyzer or VulnerabilityAnalyzer()

    def scan_form(self, url: str, form: Dict, injector) -> List[Tuple[str, str, str]]:
        """
        Scan a form for XSS vulnerabilities.

        Args:
            url: Base URL
            form: Form dictionary
            injector: PayloadInjector instance

        Returns:
            List of (vulnerability_type, endpoint, payload) tuples
        """
        results = []
        endpoint = form.get("action", url)

        for payload in XSS_PAYLOADS:
            resp = injector.inject(url, form, payload)
            if self.analyzer.detect_xss_reflected(resp, payload):
                results.append(("Reflected XSS", endpoint, payload))
                logger.info(f"Reflected XSS detected at {endpoint}")
                break  # Found vulnerability, no need to test more

        return results


class ParameterScanner:
    """Scanner for URL parameter vulnerabilities"""

    def __init__(self, analyzer: VulnerabilityAnalyzer = None):
        """
        Initialize parameter scanner.

        Args:
            analyzer: VulnerabilityAnalyzer instance
        """
        self.analyzer = analyzer or VulnerabilityAnalyzer()

    def scan_url_parameters(self, url: str, injector) -> List[Tuple[str, str, str]]:
        """
        Scan URL parameters for vulnerabilities.

        Args:
            url: URL with parameters
            injector: PayloadInjector instance

        Returns:
            List of (vulnerability_type, endpoint, payload) tuples
        """
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        results = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return results

        for key in params:
            for payload in ["' OR 1=1--", "<script>alert(1)</script>"]:
                try:
                    new_params = params.copy()
                    new_params[key] = [payload]  # parse_qs returns lists
                    new_query = urlencode(new_params, doseq=True)
                    new_url = urlunparse(parsed._replace(query=new_query))

                    import requests
                    response = requests.get(new_url, timeout=5)

                    if payload in response.text:
                        if "<script>" in payload:
                            results.append(("Reflected XSS", url, payload))
                        else:
                            results.append(("SQL Injection", url, payload))

                    if "sql" in response.text.lower() or "mysql" in response.text.lower():
                        results.append(("SQL Injection", url, payload))

                except Exception as e:
                    logger.debug(f"Error scanning parameter {key}: {e}")
                    continue

        return results

