"""
hostdiscovery.py — Reverse-IP, PTR lookup, and subdomain discovery for TriRecon.

Sources used:
  - socket.gethostbyaddr  → PTR (reverse DNS) record
  - HackerTarget API      → other domains hosted on the same IP
  - crt.sh JSON API       → Certificate Transparency subdomain enumeration

Only scan targets you own or have explicit authorization to test.
"""

import ipaddress
import socket
import time
from typing import Optional

import requests

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
HACKERTARGET_URL = "https://api.hackertarget.com/reverseiplookup/?q={ip}"
CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
REQUEST_TIMEOUT = 15  # seconds


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_ip(value: str) -> bool:
    """Return True if *value* is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _ptr_lookup(ip: str) -> Optional[str]:
    """
    Perform a reverse-DNS (PTR) lookup for *ip*.

    Returns the hostname string or None if lookup fails.
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname.rstrip(".")
    except (socket.herror, socket.gaierror, OSError):
        return None


def _hackertarget_reverse_ip(ip: str) -> list[str]:
    """
    Query HackerTarget's free reverse-IP API.

    Returns a (possibly empty) list of domain names sharing *ip*.
    Gracefully returns [] on any network or rate-limit error.
    """
    try:
        resp = requests.get(
            HACKERTARGET_URL.format(ip=ip),
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        text = resp.text.strip()

        # HackerTarget returns "No DNS A records found" or "error" on failure
        if not text or "error" in text.lower() or "no " in text.lower()[:20]:
            return []

        domains = [line.strip() for line in text.splitlines() if line.strip()]
        return domains

    except requests.RequestException:
        return []


def _crtsh_subdomains(domain: str) -> list[str]:
    """
    Query crt.sh Certificate Transparency logs for subdomains of *domain*.

    Returns a deduplicated, wildcard-stripped list of hostnames.
    """
    try:
        resp = requests.get(
            CRTSH_URL.format(domain=domain),
            timeout=REQUEST_TIMEOUT,
            headers={"Accept": "application/json"},
        )
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, ValueError):
        return []

    seen: set[str] = set()
    results: list[str] = []

    for entry in data:
        # name_value may contain newline-separated names
        raw_names = entry.get("name_value", "")
        for name in raw_names.splitlines():
            name = name.strip().lstrip("*").lstrip(".").lower()
            if name and name not in seen:
                seen.add(name)
                results.append(name)

    return sorted(results)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_host_discovery(target: str) -> dict:
    """
    Run all host-discovery sub-modules against *target*.

    Parameters
    ----------
    target:
        Either an IP address or a domain name.

    Returns
    -------
    dict with keys:
        ptr_hostname   : str | None   — PTR record hostname (if target is IP)
        reverse_ip     : list[str]    — domains sharing the IP (HackerTarget)
        subdomains     : list[str]    — crt.sh subdomain enumeration results
        domain_used    : str | None   — domain actually queried for crt.sh
    """
    result = {
        "ptr_hostname": None,
        "reverse_ip": [],
        "subdomains": [],
        "domain_used": None,
    }

    if _is_ip(target):
        # --- Input is an IP ---------------------------------------------------
        # 1. PTR / reverse-DNS lookup
        ptr = _ptr_lookup(target)
        result["ptr_hostname"] = ptr

        # 2. Reverse-IP via HackerTarget
        rev_ip_domains = _hackertarget_reverse_ip(target)
        result["reverse_ip"] = rev_ip_domains

        # 3. crt.sh: use PTR hostname as domain (strip leftmost label if needed)
        #    e.g. "mail.example.com" → query "example.com"
        domain_for_crtsh: Optional[str] = None
        if ptr:
            parts = ptr.split(".")
            # If hostname has >2 labels use the last two as the apex domain
            if len(parts) >= 2:
                domain_for_crtsh = ".".join(parts[-2:])

        if domain_for_crtsh:
            result["domain_used"] = domain_for_crtsh
            result["subdomains"] = _crtsh_subdomains(domain_for_crtsh)

    else:
        # --- Input is a domain ------------------------------------------------
        # 1. Resolve domain to IP for reverse-IP lookup
        try:
            resolved_ip = socket.gethostbyname(target)
        except socket.gaierror:
            resolved_ip = None

        # 2. Reverse-IP via HackerTarget (only if we could resolve)
        if resolved_ip:
            result["reverse_ip"] = _hackertarget_reverse_ip(resolved_ip)

        # 3. crt.sh subdomain enumeration against the provided domain
        # Use apex domain (strip any leading subdomain labels)
        parts = target.split(".")
        apex = ".".join(parts[-2:]) if len(parts) >= 2 else target
        result["domain_used"] = apex
        result["subdomains"] = _crtsh_subdomains(apex)

    return result
