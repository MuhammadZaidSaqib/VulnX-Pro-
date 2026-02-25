"""
Main vulnerability scanning orchestrator.
Coordinates all scanning components for comprehensive vulnerability assessment.
"""
import logging
from typing import List, Dict, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime

from core.crawler_v2 import WebCrawler
from core.extractor_v2 import FormExtractor
from core.injector_v2 import PayloadInjector
from core.detectors_v2 import SQLInjectionScanner, XSSScanner, ParameterScanner
from config import THREADS

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """Data class for scan results"""
    vulnerability_type: str
    endpoint: str
    payload: str
    timestamp: str = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()

    def to_tuple(self) -> Tuple[str, str, str]:
        """Convert to tuple format for database storage"""
        return (self.vulnerability_type, self.endpoint, self.payload)


class VulnerabilityScanner:
    """Main orchestrator for vulnerability scanning"""

    def __init__(
        self,
        max_threads: int = THREADS,
        max_crawl_depth: int = 2,
        request_timeout: int = 5,
        rate_limit: float = 0.4
    ):
        """
        Initialize the scanner with components.

        Args:
            max_threads: Maximum concurrent threads
            max_crawl_depth: Maximum crawling depth
            request_timeout: HTTP request timeout
            rate_limit: Rate limit delay in seconds
        """
        self.max_threads = max_threads
        self.crawler = WebCrawler(max_depth=max_crawl_depth, timeout=request_timeout)
        self.extractor = FormExtractor(timeout=request_timeout)
        self.injector = PayloadInjector(rate_limit_delay=rate_limit, timeout=request_timeout)
        self.sqli_scanner = SQLInjectionScanner()
        self.xss_scanner = XSSScanner()
        self.param_scanner = ParameterScanner()

        self.scan_results: List[ScanResult] = []
        self.discovered_urls: List[str] = []

    def _scan_single_url(self, url: str) -> List[ScanResult]:
        """
        Scan a single URL for vulnerabilities.

        Args:
            url: URL to scan

        Returns:
            List of detected vulnerabilities
        """
        results = []
        logger.debug(f"Scanning URL: {url}")

        try:
            # Extract forms
            forms = self.extractor.extract_forms(url)
            logger.debug(f"Found {len(forms)} forms on {url}")

            # Scan each form
            for form in forms:
                if not self.extractor.has_vulnerable_inputs(form):
                    continue

                try:
                    # SQL Injection scanning
                    sqli_results = self.sqli_scanner.scan_form(url, form, self.injector)
                    results.extend([ScanResult(*r) for r in sqli_results])

                    # XSS scanning
                    xss_results = self.xss_scanner.scan_form(url, form, self.injector)
                    results.extend([ScanResult(*r) for r in xss_results])

                except Exception as e:
                    logger.warning(f"Error scanning form on {url}: {e}")
                    continue

            # Test URL parameters
            try:
                param_results = self.param_scanner.scan_url_parameters(url, self.injector)
                results.extend([ScanResult(*r) for r in param_results])
            except Exception as e:
                logger.warning(f"Error scanning parameters on {url}: {e}")

        except Exception as e:
            logger.error(f"Error scanning {url}: {e}")

        return results

    def scan(self, target_url: str) -> List[ScanResult]:
        """
        Perform complete vulnerability scan on target.

        Args:
            target_url: Target URL to scan

        Returns:
            List of detected vulnerabilities
        """
        logger.info(f"Starting scan on {target_url}")
        self.scan_results.clear()

        try:
            # Step 1: Crawl
            logger.info("Step 1: Discovering URLs...")
            self.discovered_urls = self.crawler.crawl(target_url)
            logger.info(f"Discovered {len(self.discovered_urls)} URLs")

            # Step 2: Parallel scanning
            logger.info("Step 2: Scanning discovered URLs...")
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = {
                    executor.submit(self._scan_single_url, url): url
                    for url in self.discovered_urls
                }

                for future in as_completed(futures):
                    url = futures[future]
                    try:
                        results = future.result()
                        self.scan_results.extend(results)
                        if results:
                            logger.info(f"Found {len(results)} vulnerabilities on {url}")
                    except Exception as e:
                        logger.error(f"Error processing {url}: {e}")

        except Exception as e:
            logger.error(f"Scan failed: {e}")

        logger.info(f"Scan complete. Found {len(self.scan_results)} vulnerabilities")
        return self.scan_results

    def scan_fast(self, target_url: str) -> List[ScanResult]:
        """
        Fast scan without deep crawling (only target URL).

        Args:
            target_url: Target URL to scan

        Returns:
            List of detected vulnerabilities
        """
        logger.info(f"Starting fast scan on {target_url}")
        self.scan_results.clear()
        self.discovered_urls = [target_url]

        results = self._scan_single_url(target_url)
        self.scan_results.extend(results)

        logger.info(f"Fast scan complete. Found {len(results)} vulnerabilities")
        return results

    def get_results(self) -> List[Dict]:
        """
        Get scan results in dictionary format.

        Returns:
            List of vulnerability dictionaries
        """
        return [
            {
                "type": r.vulnerability_type,
                "endpoint": r.endpoint,
                "payload": r.payload,
                "timestamp": r.timestamp
            }
            for r in self.scan_results
        ]

    def get_results_tuples(self) -> List[Tuple[str, str, str]]:
        """
        Get scan results in tuple format (for database storage).

        Returns:
            List of (type, endpoint, payload) tuples
        """
        return [r.to_tuple() for r in self.scan_results]

    def get_summary(self) -> Dict:
        """
        Get scan summary statistics.

        Returns:
            Dictionary with scan statistics
        """
        results_by_type = {}
        for result in self.scan_results:
            vuln_type = result.vulnerability_type
            results_by_type[vuln_type] = results_by_type.get(vuln_type, 0) + 1

        return {
            "total_vulnerabilities": len(self.scan_results),
            "total_urls_discovered": len(self.discovered_urls),
            "vulnerabilities_by_type": results_by_type,
            "scan_timestamp": datetime.now().isoformat()
        }

