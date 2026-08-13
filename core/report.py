"""
report.py — Rich terminal output and JSON export for TriRecon.

Builds a consolidated three-section report from all module results.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich import box
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()

# ---------------------------------------------------------------------------
# Status-code color map for directory brute-force results
# ---------------------------------------------------------------------------
STATUS_COLORS = {
    200: "bright_green",
    301: "cyan",
    302: "cyan",
    401: "yellow",
    403: "yellow",
}


def _status_color(code: int) -> str:
    return STATUS_COLORS.get(code, "white")


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------

def _build_ports_table(ports: list[dict]) -> Table:
    """Return a Rich Table for open port results."""
    table = Table(
        title="[bold magenta]Open Ports[/bold magenta]",
        box=box.ROUNDED,
        show_lines=True,
        header_style="bold cyan",
        border_style="bright_black",
    )
    table.add_column("Port", style="bold yellow", width=8)
    table.add_column("Proto", style="dim", width=6)
    table.add_column("Service", style="green", width=14)
    table.add_column("Version / Banner", style="white")

    if not ports:
        table.add_row("[dim]—[/dim]", "", "[dim]No open ports found[/dim]", "")
    else:
        for p in ports:
            table.add_row(
                str(p.get("port", "")),
                str(p.get("protocol", "")),
                str(p.get("service", "")),
                str(p.get("version", "")),
            )
    return table


def _build_hosts_table(discovery: dict) -> Table:
    """Return a Rich Table for host discovery results."""
    table = Table(
        title="[bold magenta]Discovered Hosts / Subdomains[/bold magenta]",
        box=box.ROUNDED,
        show_lines=True,
        header_style="bold cyan",
        border_style="bright_black",
    )
    table.add_column("Type", style="bold yellow", width=18)
    table.add_column("Value", style="white")

    ptr = discovery.get("ptr_hostname")
    if ptr:
        table.add_row("PTR (reverse DNS)", ptr)

    for domain in discovery.get("reverse_ip", []):
        table.add_row("Reverse-IP (HT)", domain)

    for sub in discovery.get("subdomains", []):
        table.add_row("Subdomain (crt.sh)", sub)

    if table.row_count == 0:
        table.add_row("[dim]—[/dim]", "[dim]No hosts/subdomains found[/dim]")

    return table


def _build_dirs_table(paths: list[dict]) -> Table:
    """Return a Rich Table for directory brute-force results."""
    table = Table(
        title="[bold magenta]Found Paths[/bold magenta]",
        box=box.ROUNDED,
        show_lines=True,
        header_style="bold cyan",
        border_style="bright_black",
    )
    table.add_column("Status", style="bold", width=8)
    table.add_column("Size (B)", style="dim", width=10)
    table.add_column("URL", style="white")

    if not paths:
        table.add_row("[dim]—[/dim]", "", "[dim]No interesting paths found[/dim]")
    else:
        for hit in paths:
            code = hit.get("status", 0)
            color = _status_color(code)
            table.add_row(
                f"[{color}]{code}[/{color}]",
                str(hit.get("size", "")),
                hit.get("url", ""),
            )
    return table


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def print_report(
    target: str,
    ports: list[dict],
    discovery: dict,
    paths: list[dict],
    elapsed: float,
) -> None:
    """
    Print the consolidated TriRecon report to the terminal using Rich.

    Parameters
    ----------
    target:    The original scan target.
    ports:     Output of portscan.run_portscan().
    discovery: Output of hostdiscovery.run_host_discovery().
    paths:     Output of dirbrute.run_dirbrute().
    elapsed:   Total wall-clock time in seconds.
    """
    console.print()
    console.rule("[bold bright_blue]  TriRecon — Consolidated Report  [/bold bright_blue]")
    console.print(
        f"  [dim]Target:[/dim] [bold]{target}[/bold]   "
        f"[dim]Scanned:[/dim] [bold]{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC[/bold]   "
        f"[dim]Elapsed:[/dim] [bold]{elapsed:.1f}s[/bold]"
    )
    console.print()

    # --- Ports ---------------------------------------------------------------
    console.print(_build_ports_table(ports))
    console.print()

    # --- Host discovery -------------------------------------------------------
    console.print(_build_hosts_table(discovery))
    console.print()

    # --- Dir brute-force -----------------------------------------------------
    console.print(_build_dirs_table(paths))
    console.print()

    # --- Summary line --------------------------------------------------------
    console.print(
        Panel(
            f"[green]✔  Ports:[/green] {len(ports)} open   "
            f"[cyan]✔  Hosts/Subs:[/cyan] "
            f"{len(discovery.get('reverse_ip', [])) + len(discovery.get('subdomains', []))} found   "
            f"[yellow]✔  Paths:[/yellow] {len(paths)} interesting",
            title="[bold]Summary[/bold]",
            border_style="bright_blue",
        )
    )
    console.print()


def export_json(
    target: str,
    ports: list[dict],
    discovery: dict,
    paths: list[dict],
    elapsed: float,
    output_path: str,
) -> None:
    """
    Export the full scan result as a JSON file.

    Parameters
    ----------
    output_path:
        Destination file path (e.g. "report.json").
    """
    payload = {
        "meta": {
            "tool": "TriRecon",
            "target": target,
            "scanned_at": datetime.utcnow().isoformat() + "Z",
            "elapsed_seconds": round(elapsed, 2),
        },
        "ports": ports,
        "host_discovery": discovery,
        "found_paths": paths,
    }

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)

    console.print(f"[dim]JSON report saved →[/dim] [bold]{out.resolve()}[/bold]")
