"""
dirbrute.py — Threaded directory/path brute-forcer for TriRecon.

Probes HTTP and HTTPS endpoints on discovered hosts using a wordlist,
flagging interesting HTTP status codes (200, 301, 302, 403).

Only scan targets you own or have explicit authorization to test.
"""

import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable, Optional

import requests

# Suppress InsecureRequestWarning for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
INTERESTING_CODES = {200, 301, 302, 403, 401}
DEFAULT_TIMEOUT = 5        # seconds per request
DEFAULT_THREADS = 20
DEFAULT_WORDLIST = Path(__file__).parent.parent / "wordlists" / "common.txt"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _load_wordlist(wordlist_path: Path) -> list[str]:
    """
    Read *wordlist_path* and return non-empty, non-comment lines.

    Raises
    ------
    FileNotFoundError
        If the file doesn't exist.
    ValueError
        If the file is empty after filtering.
    """
    if not wordlist_path.exists():
        raise FileNotFoundError(f"Wordlist not found: {wordlist_path}")

    words = []
    with wordlist_path.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            word = line.strip()
            if word and not word.startswith("#"):
                words.append(word)

    if not words:
        raise ValueError(f"Wordlist file is empty: {wordlist_path}")

    return words


def _probe(
    url: str,
    timeout: int,
    session: requests.Session,
) -> Optional[dict]:
    """
    Send a GET request to *url* and return a result dict if the status
    code is interesting, otherwise None.

    Never raises — exceptions are silently swallowed (connection refused,
    timeout, DNS failure, etc.).
    """
    try:
        resp = session.get(
            url,
            timeout=timeout,
            allow_redirects=False,
            verify=False,
        )
        if resp.status_code in INTERESTING_CODES:
            return {
                "url": url,
                "status": resp.status_code,
                "size": len(resp.content),
            }
    except requests.RequestException:
        pass
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_dirbrute(
    hosts: list[str],
    wordlist_path: Optional[Path] = None,
    threads: int = DEFAULT_THREADS,
    timeout: int = DEFAULT_TIMEOUT,
    progress_callback: Optional[Callable[[str], None]] = None,
) -> list[dict]:
    """
    Brute-force directories/files on all *hosts* using *wordlist_path*.

    For every host the function probes both ``http://`` and ``https://``
    URLs unless the host already contains a scheme.

    Parameters
    ----------
    hosts:
        List of hostnames or IPs to probe.
    wordlist_path:
        Path to the wordlist file.  Defaults to ``wordlists/common.txt``.
    threads:
        Number of worker threads (default 20).
    timeout:
        Per-request timeout in seconds (default 5).
    progress_callback:
        Optional callable that receives a message string as URLs are probed.
        Useful for live Rich progress updates.

    Returns
    -------
    list[dict]
        Dicts with keys: url, status, size.
    """
    resolved_wordlist = wordlist_path or DEFAULT_WORDLIST
    words = _load_wordlist(resolved_wordlist)

    # Build the full URL list: http + https for each host × each word
    urls: list[str] = []
    for host in hosts:
        host = host.strip()
        if not host:
            continue
        # If the host already has a scheme, use as-is prefix
        if host.startswith("http://") or host.startswith("https://"):
            bases = [host.rstrip("/")]
        else:
            bases = [f"http://{host}", f"https://{host}"]

        for base in bases:
            for word in words:
                urls.append(f"{base}/{word}")

    if not urls:
        return []

    results: list[dict] = []

    # Reuse a single Session per thread via a per-thread Session approach
    with requests.Session() as session:
        session.headers["User-Agent"] = (
            "Mozilla/5.0 (compatible; TriRecon/1.0; +https://github.com/you/trirecon)"
        )

        with ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_url = {
                executor.submit(_probe, url, timeout, session): url
                for url in urls
            }

            for future in as_completed(future_to_url):
                url = future_to_url[future]
                if progress_callback:
                    progress_callback(url)
                try:
                    hit = future.result()
                    if hit:
                        results.append(hit)
                except Exception:
                    pass  # unexpected exception from thread — ignore

    # Sort by URL for deterministic output
    results.sort(key=lambda r: r["url"])
    return results
