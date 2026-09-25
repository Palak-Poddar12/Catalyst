from __future__ import annotations

import re
from html import unescape
from typing import Any
from urllib.parse import unquote, urlparse

import tldextract
from bs4 import BeautifulSoup


URL_PATTERN = re.compile(
    r"https?://[^\s<>'\"()]+",
    re.IGNORECASE,
)

SHORT_URL_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "cutt.ly",
    "rebrand.ly",
    "shorturl.at",
    "rb.gy",
}


def remove_trailing_url_punctuation(url: str) -> str:
    """Remove punctuation accidentally captured after a URL in body text."""
    return url.rstrip(".,;:!?)]}>\"'")


def normalize_url(raw_url: str) -> str:
    """
    Decode harmless URL encoding and clean surrounding whitespace.

    This function does not visit, request, or open the URL.
    """
    cleaned = unescape(raw_url or "").strip()
    cleaned = unquote(cleaned)
    cleaned = remove_trailing_url_punctuation(cleaned)

    return cleaned


def get_domain_from_url(url: str) -> str:
    """
    Return the hostname from an HTTP/HTTPS URL.

    Example:
    https://login.example.com/path -> login.example.com
    """
    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower().strip()
        return hostname
    except ValueError:
        return ""


def get_registered_domain(hostname: str) -> str:
    """
    Return registrable domain using Public Suffix List logic.

    Examples:
    login.example.co.in -> example.co.in
    login.microsoft.com -> microsoft.com
    """
    if not hostname:
        return ""

    extracted = tldextract.extract(hostname)

    if not extracted.domain or not extracted.suffix:
        return hostname.lower()

    return f"{extracted.domain}.{extracted.suffix}".lower()


def is_punycode_domain(hostname: str) -> bool:
    """
    Detect IDN/Punycode hostname labels such as xn--paypa1-abc.example.
    """
    hostname = hostname.lower().strip()

    return any(
        label.startswith("xn--")
        for label in hostname.split(".")
    )


def is_shortened_url(hostname: str) -> bool:
    """Detect commonly used URL-shortening domains."""
    registered_domain = get_registered_domain(hostname)

    return registered_domain in SHORT_URL_DOMAINS


def is_http_url(url: str) -> bool:
    """Accept only http and https URLs."""
    try:
        scheme = urlparse(url).scheme.lower()
        return scheme in {"http", "https"}
    except ValueError:
        return False


def extract_urls_from_plain_text(plain_text_body: str) -> list[dict[str, Any]]:
    """
    Extract visible http/https URLs from text email body.

    These are URLs that appear directly in text.
    """
    extracted_urls: list[dict[str, Any]] = []

    for raw_url in URL_PATTERN.findall(plain_text_body or ""):
        normalized_url = normalize_url(raw_url)

        if not is_http_url(normalized_url):
            continue

        hostname = get_domain_from_url(normalized_url)
        registered_domain = get_registered_domain(hostname)

        flags: list[str] = []

        if is_punycode_domain(hostname):
            flags.append("punycode_domain")

        if is_shortened_url(hostname):
            flags.append("shortened_url")

        extracted_urls.append({
            "url": normalized_url,
            "visible_text": normalized_url,
            "hostname": hostname,
            "registered_domain": registered_domain,
            "source": "plain_text",
            "risk_flags": flags,
        })

    return extracted_urls


def extract_urls_from_html(html_body: str) -> list[dict[str, Any]]:
    """
    Extract actual anchor href values and visible anchor text from HTML email.

    This does not fetch or visit any URL.
    """
    if not html_body:
        return []

    soup = BeautifulSoup(html_body, "html.parser")
    extracted_urls: list[dict[str, Any]] = []

    for anchor in soup.find_all("a", href=True):
        raw_href = anchor.get("href", "")
        normalized_url = normalize_url(raw_href)

        if not is_http_url(normalized_url):
            continue

        visible_text = anchor.get_text(" ", strip=True)
        hostname = get_domain_from_url(normalized_url)
        registered_domain = get_registered_domain(hostname)

        flags: list[str] = []

        if is_punycode_domain(hostname):
            flags.append("punycode_domain")

        if is_shortened_url(hostname):
            flags.append("shortened_url")

        # If anchor text itself is a URL, compare its displayed domain
        # with the actual href destination domain.
        visible_text_url = normalize_url(visible_text)

        if is_http_url(visible_text_url):
            visible_hostname = get_domain_from_url(visible_text_url)

            visible_registered_domain = get_registered_domain(
                visible_hostname
            )

            if (
                visible_registered_domain
                and registered_domain
                and visible_registered_domain != registered_domain
            ):
                flags.append("visible_link_destination_mismatch")

        extracted_urls.append({
            "url": normalized_url,
            "visible_text": visible_text,
            "hostname": hostname,
            "registered_domain": registered_domain,
            "source": "html_anchor",
            "risk_flags": flags,
        })

    return extracted_urls


def deduplicate_urls(url_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Deduplicate URLs while keeping combined flags and source information.
    """
    grouped: dict[str, dict[str, Any]] = {}

    for item in url_items:
        url = item["url"]

        if url not in grouped:
            grouped[url] = item.copy()
            continue

        existing = grouped[url]

        existing["risk_flags"] = sorted(
            set(existing["risk_flags"] + item["risk_flags"])
        )

        if not existing["visible_text"] and item["visible_text"]:
            existing["visible_text"] = item["visible_text"]

        if existing["source"] != item["source"]:
            existing["source"] = "plain_text_and_html"

    return list(grouped.values())


def extract_all_urls(
    plain_text_body: str,
    html_body: str,
) -> list[dict[str, Any]]:
    """
    Extract and normalize all URLs from text and HTML email bodies.
    """
    text_urls = extract_urls_from_plain_text(plain_text_body)
    html_urls = extract_urls_from_html(html_body)

    return deduplicate_urls(text_urls + html_urls)


def get_domains_from_urls(url_items: list[dict[str, Any]]) -> list[str]:
    """Return unique registered domains extracted from URLs."""
    domains = {
        item["registered_domain"]
        for item in url_items
        if item.get("registered_domain")
    }

    return sorted(domains)