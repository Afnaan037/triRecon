"""
portscan.py — Port scanning module for TriRecon.

Wraps nmap -sV -oX to produce structured port/service data.
Only scan targets you own or have explicit authorization to test.
"""

import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional


def _check_nmap() -> None:
    """Raise a clear RuntimeError if nmap is not on PATH."""
    if shutil.which("nmap") is None:
        raise RuntimeError(
            "nmap is not installed or not on PATH.\n"
            "Install it with:  sudo apt install nmap"
        )


def _parse_nmap_xml(xml_path: str) -> list[dict]:
    """
    Parse an nmap XML output file and return only open ports.

    Returns a list of dicts with keys:
        port, protocol, service, version, state
    """
    results: list[dict] = []

    try:
        tree = ET.parse(xml_path)
    except ET.ParseError as exc:
        raise RuntimeError(f"Failed to parse nmap XML output: {exc}") from exc

    root = tree.getroot()

    for host in root.findall("host"):
        ports_elem = host.find("ports")
        if ports_elem is None:
            continue

        for port_elem in ports_elem.findall("port"):
            state_elem = port_elem.find("state")
            if state_elem is None:
                continue
            state = state_elem.get("state", "")
            if state != "open":
                continue

            service_elem = port_elem.find("service")
            service_name = ""
            version_str = ""
            if service_elem is not None:
                service_name = service_elem.get("name", "")
                product = service_elem.get("product", "")
                version = service_elem.get("version", "")
                extra_info = service_elem.get("extrainfo", "")
                version_parts = [p for p in [product, version, extra_info] if p]
                version_str = " ".join(version_parts)

            results.append(
                {
                    "port": port_elem.get("portid", ""),
                    "protocol": port_elem.get("protocol", ""),
                    "service": service_name,
                    "version": version_str,
                    "state": state,
                }
            )

    return results


def run_portscan(target: str, extra_args: Optional[list[str]] = None) -> list[dict]:
    """
    Run nmap -sV against *target*, write XML to a temp file, parse and return results.

    Parameters
    ----------
    target:
        IP address or hostname to scan.
    extra_args:
        Additional nmap arguments (e.g. ['-p', '1-1000']).

    Returns
    -------
    list[dict]
        Each dict: { port, protocol, service, version, state }

    Raises
    ------
    RuntimeError
        If nmap is not installed, the target is unreachable, or nmap exits
        with a non-zero code.
    """
    _check_nmap()

    # Create a temporary file for nmap XML output; delete=False so nmap can write it
    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
        xml_path = tmp.name

    try:
        cmd = ["nmap", "-sV", "-oX", xml_path]
        if extra_args:
            cmd.extend(extra_args)
        cmd.append(target)

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,  # 5 minutes max
        )

        if result.returncode != 0:
            stderr = result.stderr.strip()
            raise RuntimeError(
                f"nmap exited with code {result.returncode}.\n"
                f"stderr: {stderr or '(no output)'}"
            )

        return _parse_nmap_xml(xml_path)

    except subprocess.TimeoutExpired:
        raise RuntimeError(
            "nmap timed out after 5 minutes. "
            "The target may be unreachable or a firewall is dropping packets."
        )
    except FileNotFoundError:
        raise RuntimeError(
            "nmap executable was not found. Install it with: sudo apt install nmap"
        )
    finally:
        # Clean up temp XML file
        Path(xml_path).unlink(missing_ok=True)
