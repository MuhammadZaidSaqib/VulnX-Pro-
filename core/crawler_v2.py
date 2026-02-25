"""
Web crawler module for discovering URLs within target domains.
Implements thread-safe URL discovery with depth limiting.
"""
import logging
from typing import List, Set
from urllib.parse import urljoin, urlparse
import requests
from bs4 import BeautifulSoup
from config import REQUEST_TIMEOUT, USER_AGENT, MAX_DEPTH

logger = logging.getLogger(__name__)


class WebCrawler:
    """Thread-safe web crawler for discovering URLs"""

    def __init__(self, max_depth: int = MAX_DEPTH, timeout: int = REQUEST_TIMEOUT):
        """
        Initialize the crawler.

        Args:
            max_depth: Maximum recursion depth for crawling
            timeout: HTTP request timeout in seconds
        """
        self.max_depth = max_depth
        self.timeout = timeout
        self.visited: Set[str] = set()
        self.user_agent = USER_AGENT

    def _is_valid_url(self, url: str) -> bool:
        """Check if URL is valid."""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False

    def _is_same_domain(self, base_url: str, target_url: str) -> bool:
        """Check if target URL belongs to same domain as base URL."""
        try:
            base_domain = urlparse(base_url).netloc
            target_domain = urlparse(target_url).netloc
            return base_domain == target_domain
        except Exception:
            return False

    def _fetch_page(self, url: str) -> str:
        """
        Fetch page content with error handling.

        Args:
            url: URL to fetch

        Returns:
            Page content or empty string on failure
        """
        try:
            headers = {"User-Agent": self.user_agent}
            response = requests.get(url, headers=headers, timeout=self.timeout)
            response.raise_for_status()
            return response.text
        except requests.exceptions.Timeout:
            logger.warning(f"Timeout fetching {url}")
            return ""
        except requests.exceptions.ConnectionError:
            logger.warning(f"Connection error for {url}")
            return ""
        except requests.exceptions.RequestException as e:
            logger.warning(f"Error fetching {url}: {e}")
            return ""

    def _extract_links(self, url: str, html_content: str) -> List[str]:
        """
        Extract all links from HTML content.

        Args:
            url: Base URL for resolving relative links
            html_content: HTML content to parse

        Returns:
            List of absolute URLs found in content
        """
        links = []
        try:
            soup = BeautifulSoup(html_content, "lxml")
            for link in soup.find_all("a", href=True):
                href = link.get("href", "").strip()
                if not href:
                    continue

                # Handle relative URLs
                full_url = urljoin(url, href)

                # Validate and filter same-domain links
                if self._is_valid_url(full_url) and self._is_same_domain(url, full_url):
                    links.append(full_url)

        except Exception as e:
            logger.error(f"Error parsing HTML: {e}")

        return links

    def crawl(self, start_url: str) -> List[str]:
        """
        Crawl website starting from given URL.

        Args:
            start_url: Starting URL for crawl

        Returns:
            List of discovered URLs
        """
        # Reset state for new crawl
        self.visited.clear()
        discovered_urls = []

        return self._crawl_recursive(start_url, 0, discovered_urls)

    def _crawl_recursive(self, url: str, depth: int, discovered: List[str]) -> List[str]:
        """
        Recursively crawl URLs up to max depth.

        Args:
            url: Current URL to process
            depth: Current recursion depth
            discovered: Accumulator list of discovered URLs

        Returns:
            Updated list of discovered URLs
        """
        # Stop conditions
        if depth > self.max_depth or url in self.visited:
            return discovered

        # Mark as visited
        self.visited.add(url)
        discovered.append(url)

        logger.debug(f"Crawling {url} (depth: {depth})")

        # Fetch and parse page
        html_content = self._fetch_page(url)
        if not html_content:
            return discovered

        # Extract and process links
        links = self._extract_links(url, html_content)
        for link in links:
            if link not in self.visited:
                self._crawl_recursive(link, depth + 1, discovered)

        return discovered

    def crawl_fast(self, start_url: str) -> List[str]:
        """
        Fast crawl without recursion (shallow crawl).
        Returns only URLs from starting page.

        Args:
            start_url: Starting URL

        Returns:
            List of discovered URLs (only direct links)
        """
        urls = [start_url]
        html_content = self._fetch_page(start_url)

        if html_content:
            links = self._extract_links(start_url, html_content)
            urls.extend(links)

        return list(set(urls))  # Deduplicate

