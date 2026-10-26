"""Offline URL parsing and transparent structural feature extraction.

This module never makes a network request and never opens the submitted URL.
"""
from __future__ import annotations
import ipaddress
import re
from urllib.parse import parse_qsl, urlsplit, urlunsplit

MAX_URL_LENGTH = 4096
SHORTENER_DOMAINS = {
    "bit.ly", "t.co", "tinyurl.com", "is.gd", "ow.ly", "buff.ly", "cutt.ly", "rb.gy"
}
SUSPICIOUS_TLDS = {"zip", "mov", "top", "click", "country", "gq", "tk"}


class URLAnalysisError(ValueError):
    """Raised when the supplied input cannot be safely analyzed as a URL."""


def _to_ascii_hostname(hostname: str) -> str:
    try:
        return hostname.rstrip(".").encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError) as exc:
        raise URLAnalysisError("The hostname could not be parsed safely.") from exc


def analyze_url(raw_url: str) -> dict:
    if not isinstance(raw_url, str) or not raw_url.strip():
        raise URLAnalysisError("Please enter a URL.")
    raw = raw_url.strip()
    if len(raw) > MAX_URL_LENGTH:
        raise URLAnalysisError(f"URL is too long (maximum {MAX_URL_LENGTH} characters).")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in raw):
        raise URLAnalysisError("Control characters are not allowed in a URL.")
    candidate = raw if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", raw) else "https://" + raw
    try:
        parts = urlsplit(candidate)
        hostname_raw = parts.hostname
        # Accessing .port detects malformed/out-of-range ports.
        port = parts.port
    except ValueError as exc:
        raise URLAnalysisError("Malformed URL or invalid port.") from exc
    if parts.scheme.lower() not in {"http", "https"}:
        raise URLAnalysisError("Only HTTP and HTTPS URLs are supported.")
    if not hostname_raw:
        raise URLAnalysisError("A hostname is required (for example, example.com).")
    if parts.username is not None or parts.password is not None:
        has_credentials = True
    else:
        has_credentials = False
    hostname = _to_ascii_hostname(hostname_raw)
    if len(hostname) > 253:
        raise URLAnalysisError("Hostname is too long.")
    # Validate DNS-like host labels unless the host is a valid IP address.
    ip_host = False
    try:
        ipaddress.ip_address(hostname.strip("[]"))
        ip_host = True
    except ValueError:
        labels = hostname.split(".")
        if any(not label or len(label) > 63 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) for label in labels):
            raise URLAnalysisError("Hostname contains invalid characters or labels.")
        if len(labels) < 2 and hostname != "localhost":
            raise URLAnalysisError("Please provide a fully qualified hostname, such as example.com.")
    scheme = parts.scheme.lower()
    # Preserve the actual parsed hostname; omit credentials from normalized output.
    netloc = hostname
    if port is not None:
        default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
        if not default_port:
            netloc += f":{port}"
    path = parts.path or "/"
    normalized = urlunsplit((scheme, netloc, path, parts.query, ""))
    labels = hostname.split(".")
    query_pairs = parse_qsl(parts.query, keep_blank_values=True, max_num_fields=200)
    encoded_suspicious = bool(re.search(r"%(?:0[0-9a-f]|1[0-9a-f]|2f|5c|40|2e)", raw, re.I))
    shortener = hostname in SHORTENER_DOMAINS or any(hostname.endswith("." + domain) for domain in SHORTENER_DOMAINS)
    misleading_patterns = bool(re.search(r"(?:https?[-_.]?|login[-_.]?|verify[-_.]?|secure[-_.]?)", hostname))
    try:
        registrable_approx = ".".join(labels[-2:]) if len(labels) >= 2 else hostname
    except Exception:
        registrable_approx = hostname
    return {
        "raw_url": raw,
        "normalized_url": normalized,
        "scheme": scheme,
        "hostname": hostname,
        "hostname_unicode": hostname_raw,
        "path": path,
        "port": port,
        "url_length": len(raw),
        "hostname_length": len(hostname),
        "hostname_dot_count": hostname.count("."),
        "subdomain_count_approx": max(0, len(labels) - 2),
        "is_ip_address": ip_host,
        "uses_https": scheme == "https",
        "contains_at_symbol": "@" in raw,
        "has_url_credentials": has_credentials,
        "hostname_hyphen_count": hostname.count("-"),
        "hostname_digit_count": sum(ch.isdigit() for ch in hostname),
        "query_parameter_count": len(query_pairs),
        "has_suspicious_encoding": encoded_suspicious,
        "has_misleading_hostname_pattern": misleading_patterns,
        "is_known_shortener": shortener,
        "tld": labels[-1] if labels else "",
        "uses_uncommon_tld": bool(labels and labels[-1] in SUSPICIOUS_TLDS),
        "registrable_domain_approx": registrable_approx,
        "registrable_domain_note": "Approximation only; no Public Suffix List is bundled, so multi-part public suffixes may be misclassified.",
    }