"""
Enhanced utilities module with logging, validation, and helpers.
"""
import logging
import re
from typing import Optional
from urllib.parse import urlparse

# ==================== LOGGING SETUP ====================


class LoggerFactory:
    """Factory for creating properly configured loggers"""

    _configured = False

    @staticmethod
    def get_logger(name: str) -> logging.Logger:
        """
        Get or create a logger with standard configuration.

        Args:
            name: Logger name (usually __name__)

        Returns:
            Configured logger instance
        """
        logger = logging.getLogger(name)

        if not LoggerFactory._configured:
            # Set up root logger
            root_logger = logging.getLogger()
            root_logger.setLevel(logging.INFO)

            # Console handler
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.INFO)

            # Formatter
            formatter = logging.Formatter(
                '[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            console_handler.setFormatter(formatter)
            root_logger.addHandler(console_handler)

            LoggerFactory._configured = True

        return logger


# ==================== URL VALIDATION ====================


class URLValidator:
    """Validates and sanitizes URLs"""

    URL_PATTERN = re.compile(
        r'^https?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain
        r'localhost|'  # localhost
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # or IP
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)

    @staticmethod
    def is_valid(url: str) -> bool:
        """
        Validate URL format.

        Args:
            url: URL to validate

        Returns:
            True if URL is valid
        """
        if not url:
            return False

        try:
            result = urlparse(url)
            return all([
                result.scheme in ('http', 'https'),
                result.netloc,
                URLValidator.URL_PATTERN.match(url)
            ])
        except Exception:
            return False

    @staticmethod
    def normalize(url: str) -> Optional[str]:
        """
        Normalize URL to standard format.

        Args:
            url: URL to normalize

        Returns:
            Normalized URL or None if invalid
        """
        if not url:
            return None

        url = url.strip()

        # Add scheme if missing
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        if URLValidator.is_valid(url):
            return url

        return None

    @staticmethod
    def get_domain(url: str) -> Optional[str]:
        """
        Extract domain from URL.

        Args:
            url: Full URL

        Returns:
            Domain or None if invalid
        """
        try:
            parsed = urlparse(url)
            return parsed.netloc
        except Exception:
            return None

    @staticmethod
    def is_same_domain(url1: str, url2: str) -> bool:
        """
        Check if two URLs are from same domain.

        Args:
            url1: First URL
            url2: Second URL

        Returns:
            True if same domain
        """
        domain1 = URLValidator.get_domain(url1)
        domain2 = URLValidator.get_domain(url2)
        return domain1 and domain2 and domain1 == domain2


# ==================== PAYLOAD UTILITIES ====================


class PayloadSanitizer:
    """Sanitizes and validates payloads"""

    @staticmethod
    def is_safe_payload(payload: str) -> bool:
        """
        Check if payload appears to be a test payload (not malicious).

        Args:
            payload: Payload to check

        Returns:
            True if payload seems safe for testing
        """
        # Known test patterns
        safe_patterns = [
            "alert(",
            "OR 1=1",
            "' OR '",
            "UNION SELECT",
            "<script>",
            "onerror=",
            "onload="
        ]
        return any(pattern in payload for pattern in safe_patterns)

    @staticmethod
    def escape_html(text: str) -> str:
        """
        Escape HTML special characters.

        Args:
            text: Text to escape

        Returns:
            Escaped text
        """
        replacements = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#x27;'
        }
        for char, escape in replacements.items():
            text = text.replace(char, escape)
        return text


# ==================== RESULT FORMATTING ====================


class ResultFormatter:
    """Formats scan results for display"""

    @staticmethod
    def format_table(results: list, headers: list = None) -> str:
        """
        Format results as ASCII table.

        Args:
            results: List of result dictionaries
            headers: Column headers

        Returns:
            ASCII table string
        """
        if not results:
            return "No results"

        if headers is None:
            headers = list(results[0].keys()) if results else []

        # Calculate column widths
        widths = {header: len(header) for header in headers}
        for result in results:
            for header in headers:
                value = str(result.get(header, ""))
                widths[header] = max(widths[header], len(value))

        # Build table
        lines = []
        separator = "+".join("-" * (widths[h] + 2) for h in headers)
        lines.append("+" + separator + "+")

        # Headers
        header_line = "|".join(
            f" {header:<{widths[header]}} " for header in headers
        )
        lines.append("|" + header_line + "|")
        lines.append("+" + separator + "+")

        # Rows
        for result in results:
            row_line = "|".join(
                f" {str(result.get(h, '')):<{widths[h]}} " for h in headers
            )
            lines.append("|" + row_line + "|")

        lines.append("+" + separator + "+")
        return "\n".join(lines)

    @staticmethod
    def format_json(data: dict) -> str:
        """
        Format data as JSON.

        Args:
            data: Data to format

        Returns:
            JSON string
        """
        import json
        return json.dumps(data, indent=2)


# ==================== STATISTICS ====================


class ScanStatistics:
    """Tracks and reports scan statistics"""

    def __init__(self):
        """Initialize statistics"""
        self.total_urls = 0
        self.total_forms = 0
        self.total_payloads_tested = 0
        self.total_vulnerabilities = 0
        self.vulnerabilities_by_type = {}
        self.start_time = None
        self.end_time = None

    def record_url(self, url: str):
        """Record URL discovery"""
        self.total_urls += 1

    def record_form(self):
        """Record form extraction"""
        self.total_forms += 1

    def record_payload_test(self):
        """Record payload test"""
        self.total_payloads_tested += 1

    def record_vulnerability(self, vuln_type: str):
        """Record vulnerability discovery"""
        self.total_vulnerabilities += 1
        self.vulnerabilities_by_type[vuln_type] = (
            self.vulnerabilities_by_type.get(vuln_type, 0) + 1
        )

    def get_summary(self) -> dict:
        """Get statistics summary"""
        return {
            "total_urls": self.total_urls,
            "total_forms": self.total_forms,
            "total_payloads_tested": self.total_payloads_tested,
            "total_vulnerabilities": self.total_vulnerabilities,
            "vulnerabilities_by_type": self.vulnerabilities_by_type
        }

