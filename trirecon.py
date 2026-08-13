#!/usr/bin/env python3
"""
trirecon.py — CLI entrypoint for TriRecon.

Usage:
    python trirecon.py scan --target scanme.nmap.org
    python trirecon.py scan --target 45.33.32.156 --ports --hosts
    python trirecon.py scan --target example.com --full --output report.json

Only scan targets you own or have explicit authorization to test.
"""

import ipaddress
import sys
import time
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

# ---------------------------------------------------------------------------
# Bootstrap: ensure our own package is importable when run directly
# ---------------------------------------------------------------------------
_HERE = Path(__file__).parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from core import (  # noqa: E402
    dirbrute,
    hostdiscovery,
    portscan,
    report,
    storage,
)

console = Console()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

BANNER = """[bold bright_cyan]
 ████████╗██████╗ ██╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
    ██╔══╝██╔══██╗██║██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
    ██║   ██████╔╝██║██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
    ██║   ██╔══██╗██║██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
    ██║   ██║  ██║██║██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
    ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝[/bold bright_cyan]
[dim]                    v1.0  |  Security Reconnaissance Toolkit[/dim]"""


def _print_banner() -> None:
    console.print(BANNER)
    console.print(
        Panel(
            "[bold yellow]⚠  Only scan targets you own or have explicit authorization to test.[/bold yellow]",
            border_style="yellow",
            expand=False,
        )
    )
    console.print()


def _is_ip(value: str) -> bool:
    """Return True if *value* is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _validate_target(target: str) -> str:
    """
    Validate that *target* is either a plausible domain or an IP address.
    Returns the stripped target or raises click.BadParameter.
    """
    target = target.strip()
    if not target:
        raise click.BadParameter("Target cannot be empty.")
    # Must contain at least one dot or be a valid IP
    if "." not in target and ":" not in target:
        raise click.BadParameter(
            f"'{target}' does not look like a valid IP or domain."
        )
    return target


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------

@click.group()
def cli() -> None:
    """TriRecon — A modular security reconnaissance toolkit."""
    pass


# ---------------------------------------------------------------------------
# scan command
# ---------------------------------------------------------------------------

@cli.command()
@click.option(
    "--target", "-t",
    required=True,
    help="IP address or domain to scan (e.g. scanme.nmap.org or 45.33.32.156).",
)
@click.option(
    "--ports", "run_ports",
    is_flag=True, default=False,
    help="Run port scanning module only.",
)
@click.option(
    "--hosts", "run_hosts",
    is_flag=True, default=False,
    help="Run host/subdomain discovery module only.",
)
@click.option(
    "--dirs", "run_dirs",
    is_flag=True, default=False,
    help="Run directory brute-force module only.",
)
@click.option(
    "--full", "run_full",
    is_flag=True, default=False,
    help="Run all three modules (default behaviour when no module flag is set).",
)
@click.option(
    "--wordlist", "-w",
    default=None,
    type=click.Path(exists=False),
    help="Path to the wordlist file for directory brute-forcing.",
)
@click.option(
    "--threads", "-T",
    default=dirbrute.DEFAULT_THREADS,
    show_default=True,
    help="Number of threads for directory brute-forcing.",
)
@click.option(
    "--output", "-o",
    default=None,
    help="Path to write a JSON report (e.g. report.json).",
)
@click.option(
    "--save-db",
    is_flag=True, default=False,
    help="Save scan results to the local SQLite history database.",
)
def scan(
    target: str,
    run_ports: bool,
    run_hosts: bool,
    run_dirs: bool,
    run_full: bool,
    wordlist: Optional[str],
    threads: int,
    output: Optional[str],
    save_db: bool,
) -> None:
    """
    Run reconnaissance modules against TARGET.

    \b
    Examples:
        trirecon scan --target scanme.nmap.org
        trirecon scan --target 45.33.32.156 --ports --hosts
        trirecon scan --target example.com --dirs --wordlist /path/to/list.txt
        trirecon scan --target scanme.nmap.org --full --output report.json

    \b
    Safe practice target recommended by the nmap project:
        scanme.nmap.org
    """
    _print_banner()

    # --- Validate target ---------------------------------------------------
    try:
        target = _validate_target(target)
    except click.BadParameter as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        sys.exit(1)

    # --- Determine which modules to run ------------------------------------
    # If no specific flag is set (or --full), run everything
    if run_full or not any([run_ports, run_hosts, run_dirs]):
        run_ports = run_hosts = run_dirs = True

    target_is_ip = _is_ip(target)

    # Resolved module outputs (populated progressively)
    port_results: list[dict] = []
    discovery_results: dict = {
        "ptr_hostname": None,
        "reverse_ip": [],
        "subdomains": [],
        "domain_used": None,
    }
    dir_results: list[dict] = []

    start_time = time.monotonic()

    # -----------------------------------------------------------------------
    # MODULE 1 — Port scanning
    # -----------------------------------------------------------------------
    if run_ports:
        console.rule("[bold blue]Module 1 — Port Scanning (nmap)[/bold blue]")
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task(
                f"Running nmap -sV against [bold]{target}[/bold] …", total=None
            )
            try:
                port_results = portscan.run_portscan(target)
                progress.update(task, description="[green]nmap complete[/green]")
            except RuntimeError as exc:
                progress.stop()
                console.print(f"[bold red]Port scan error:[/bold red] {exc}")

        console.print(
            f"[green]✔[/green] Found [bold]{len(port_results)}[/bold] open port(s)."
        )
        console.print()

    # -----------------------------------------------------------------------
    # MODULE 2 — Host / subdomain discovery
    # -----------------------------------------------------------------------
    if run_hosts:
        console.rule("[bold blue]Module 2 — Host & Subdomain Discovery[/bold blue]")
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task(
                f"Enumerating hosts / subdomains for [bold]{target}[/bold] …",
                total=None,
            )
            try:
                discovery_results = hostdiscovery.run_host_discovery(target)
                progress.update(task, description="[green]Discovery complete[/green]")
            except Exception as exc:
                progress.stop()
                console.print(f"[bold red]Host discovery error:[/bold red] {exc}")

        total_found = (
            len(discovery_results.get("reverse_ip", []))
            + len(discovery_results.get("subdomains", []))
            + (1 if discovery_results.get("ptr_hostname") else 0)
        )
        console.print(
            f"[green]✔[/green] Discovered [bold]{total_found}[/bold] host(s)/subdomain(s)."
        )
        console.print()

    # -----------------------------------------------------------------------
    # MODULE 3 — Directory brute-forcing
    # -----------------------------------------------------------------------
    if run_dirs:
        console.rule("[bold blue]Module 3 — Directory Brute-Force[/bold blue]")

        # Collect HTTP hosts to probe
        http_hosts: list[str] = []

        # Use open HTTP/HTTPS ports discovered by nmap as hints
        http_ports = {80, 443, 8080, 8443, 8000, 8888}
        for p in port_results:
            try:
                pnum = int(p.get("port", 0))
            except (ValueError, TypeError):
                pnum = 0
            if pnum in http_ports or "http" in str(p.get("service", "")).lower():
                http_hosts.append(target)
                break

        # Always add the primary target if no ports were scanned
        if not http_hosts:
            http_hosts = [target]

        wordlist_path = Path(wordlist) if wordlist else None

        try:
            resolved_wordlist = wordlist_path or dirbrute.DEFAULT_WORDLIST
            wl_size = len(dirbrute._load_wordlist(resolved_wordlist))
            url_count = wl_size * len(http_hosts) * 2  # http + https

            console.print(
                f"Probing [bold]{len(http_hosts)}[/bold] host(s) with "
                f"[bold]{wl_size}[/bold] words × 2 schemes "
                f"= [bold]{url_count}[/bold] requests "
                f"([bold]{threads}[/bold] threads) …"
            )

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                TimeElapsedColumn(),
                console=console,
                transient=True,
            ) as progress:
                task = progress.add_task("Brute-forcing …", total=None)

                dir_results = dirbrute.run_dirbrute(
                    hosts=http_hosts,
                    wordlist_path=wordlist_path,
                    threads=threads,
                )
                progress.update(task, description="[green]Brute-force complete[/green]")

        except (FileNotFoundError, ValueError) as exc:
            console.print(f"[bold red]Wordlist error:[/bold red] {exc}")

        console.print(
            f"[green]✔[/green] Found [bold]{len(dir_results)}[/bold] interesting path(s)."
        )
        console.print()

    # -----------------------------------------------------------------------
    # Consolidated report
    # -----------------------------------------------------------------------
    elapsed = time.monotonic() - start_time
    report.print_report(
        target=target,
        ports=port_results,
        discovery=discovery_results,
        paths=dir_results,
        elapsed=elapsed,
    )

    # -----------------------------------------------------------------------
    # Optional JSON export
    # -----------------------------------------------------------------------
    if output:
        report.export_json(
            target=target,
            ports=port_results,
            discovery=discovery_results,
            paths=dir_results,
            elapsed=elapsed,
            output_path=output,
        )

    # -----------------------------------------------------------------------
    # Optional SQLite storage
    # -----------------------------------------------------------------------
    if save_db:
        try:
            with storage.ScanStorage() as store:
                run_id = store.save(target, port_results, discovery_results, dir_results)
            console.print(
                f"[dim]Scan saved to history DB → run ID [bold]{run_id}[/bold][/dim]"
            )
        except Exception as exc:
            console.print(f"[yellow]Warning: could not save to DB:[/yellow] {exc}")


# ---------------------------------------------------------------------------
# history command — list previous scans from SQLite
# ---------------------------------------------------------------------------

@cli.command()
@click.option(
    "--limit", "-n",
    default=20,
    show_default=True,
    help="Maximum number of history entries to show.",
)
def history(limit: int) -> None:
    """List previous scan runs stored in the local database."""
    _print_banner()
    from rich.table import Table as RichTable, box as rich_box

    try:
        with storage.ScanStorage() as store:
            runs = store.list_runs(limit)
    except Exception as exc:
        console.print(f"[bold red]Error reading history:[/bold red] {exc}")
        sys.exit(1)

    if not runs:
        console.print("[dim]No scan history found. Run a scan with --save-db first.[/dim]")
        return

    tbl = RichTable(
        title="[bold magenta]Scan History[/bold magenta]",
        box=rich_box.ROUNDED,
        header_style="bold cyan",
    )
    tbl.add_column("ID", style="bold yellow", width=6)
    tbl.add_column("Target", style="green")
    tbl.add_column("Scanned At (UTC)", style="dim")

    for run in runs:
        tbl.add_row(str(run["id"]), run["target"], run["scanned_at"])

    console.print(tbl)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    cli()
