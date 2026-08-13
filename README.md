# TriRecon 🔍

> **TriRecon** is a modular, command-line security reconnaissance toolkit written in Python 3.
> It combines port scanning, reverse-IP / subdomain enumeration, and directory brute-forcing
> into a single workflow with a beautiful Rich terminal report.

```
 ████████╗██████╗ ██╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
    ██╔══╝██╔══██╗██║██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
    ██║   ██████╔╝██║██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
    ██║   ██╔══██╗██║██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
    ██║   ██║  ██║██║██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
    ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
                        v1.0  |  Security Reconnaissance Toolkit
```

---

## ⚠️ Legal & Ethical Use Disclaimer

> **This tool is for educational purposes and authorized security testing ONLY.**
>
> Unauthorized scanning of systems or networks you do not own, or do not have **explicit written
> permission** to test, is illegal in most jurisdictions (e.g., the Computer Fraud and Abuse Act
> in the United States, the Computer Misuse Act in the United Kingdom, and similar laws worldwide).
>
> The authors of TriRecon accept **no liability** for misuse or illegal activity conducted with
> this tool. By using TriRecon you agree that:
>
> 1. You are the owner of the target system, **OR**
> 2. You have received **explicit, documented authorization** from the system owner to perform
>    reconnaissance and security testing against it.
>
> **Safe practice target:** [scanme.nmap.org](http://scanme.nmap.org) — this host is provided
> by the nmap project specifically for public testing. It is the only external host you should
> target without prior authorization.

---

## ✨ Features

| Module | What it does |
|--------|-------------|
| **Port Scanner** | Runs `nmap -sV`, parses XML output, returns open ports with service/version info |
| **Host Discovery** | PTR (reverse-DNS), reverse-IP via HackerTarget API, subdomain enum via crt.sh CT logs |
| **Dir Brute-Forcer** | Threaded HTTP/HTTPS path discovery using a bundled or custom wordlist |
| **Rich Report** | Consolidated terminal tables + optional JSON export |
| **SQLite History** | Optional local scan-history persistence (`--save-db`) |

---

## 📂 Project Structure

```
triRecon/
├── trirecon.py              # CLI entrypoint  (click group: scan, history)
├── core/
│   ├── __init__.py
│   ├── portscan.py          # nmap -sV wrapper → list[{port, protocol, service, version}]
│   ├── hostdiscovery.py     # PTR + HackerTarget + crt.sh subdomain enumeration
│   ├── dirbrute.py          # ThreadPoolExecutor HTTP/HTTPS path brute-forcer
│   ├── report.py            # Rich terminal tables + JSON export
│   └── storage.py           # sqlite3 scan-history helper
├── wordlists/
│   └── common.txt           # ~150 bundled common paths
├── requirements.txt
├── README.md
├── LICENSE                  # MIT
└── .gitignore
```

---

## 🖥️ Requirements

- **OS:** Linux (Ubuntu 20.04+ / Debian 11+ recommended)
- **Python:** 3.9 or later
- **nmap:** must be installed separately

---

## 🚀 Installation

### 1 — Install system dependencies

```bash
sudo apt update
sudo apt install nmap python3 python3-pip python3-venv -y
```

### 2 — Clone the repository

```bash
git clone https://github.com/your-username/triRecon.git
cd triRecon
```

### 3 — Create a virtual environment and install Python packages

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 4 — (Optional) Make the CLI globally accessible

```bash
# From inside the repo directory:
chmod +x trirecon.py
sudo ln -s "$(pwd)/trirecon.py" /usr/local/bin/trirecon
```

---

## 🔧 Usage

```
Usage: trirecon.py scan [OPTIONS]

  Run reconnaissance modules against TARGET.

Options:
  -t, --target TEXT       IP address or domain to scan  [required]
  --ports                 Run port scanning module only
  --hosts                 Run host/subdomain discovery module only
  --dirs                  Run directory brute-force module only
  --full                  Run all three modules (default)
  -w, --wordlist PATH     Path to wordlist file
  -T, --threads INTEGER   Threads for dir brute-force  [default: 20]
  -o, --output PATH       Write JSON report to this path
  --save-db               Save results to local SQLite history DB
  --help                  Show this message and exit.
```

### Scan a domain (all modules — default)

```bash
python trirecon.py scan --target scanme.nmap.org
```

### Scan an IP address, ports and hosts only

```bash
python trirecon.py scan --target 45.33.32.156 --ports --hosts
```

### Directory brute-force with a custom wordlist, export JSON

```bash
python trirecon.py scan --target scanme.nmap.org --dirs \
    --wordlist /usr/share/wordlists/dirb/common.txt \
    --threads 40 \
    --output /tmp/scanme_report.json
```

### Full scan and save to history DB

```bash
python trirecon.py scan --target scanme.nmap.org --full --save-db
```

### View scan history

```bash
python trirecon.py history --limit 10
```

---

## 📋 Example Output

```
 ████████╗██████╗ ██╗██████╗ ...
 ┌──────────────────────────────────────────────────────────────┐
 │ ⚠  Only scan targets you own or have explicit authorization  │
 └──────────────────────────────────────────────────────────────┘

 ── Module 1 — Port Scanning (nmap) ────────────────────────────
 ✔ Found 4 open port(s).

 ── Module 2 — Host & Subdomain Discovery ──────────────────────
 ✔ Discovered 12 host(s)/subdomain(s).

 ── Module 3 — Directory Brute-Force ───────────────────────────
 Probing 1 host(s) with 148 words × 2 schemes = 296 requests (20 threads) …
 ✔ Found 3 interesting path(s).

 ── TriRecon — Consolidated Report ────────────────────────────
   Target: scanme.nmap.org   Scanned: 2024-09-15 12:34:00 UTC   Elapsed: 42.3s

 ╭──────────────────────────── Open Ports ─────────────────────────────╮
 │ Port  │ Proto │ Service       │ Version / Banner                     │
 ├───────┼───────┼───────────────┼──────────────────────────────────────┤
 │ 22    │ tcp   │ ssh           │ OpenSSH 6.6.1p1 Ubuntu               │
 │ 80    │ tcp   │ http          │ Apache httpd 2.4.7                   │
 │ 9929  │ tcp   │ nping-echo    │ Nping echo                           │
 │ 31337 │ tcp   │ Elite         │                                      │
 ╰───────┴───────┴───────────────┴──────────────────────────────────────╯

 ╭──────────────── Discovered Hosts / Subdomains ────────────────────────╮
 │ Type               │ Value                                            │
 ├────────────────────┼──────────────────────────────────────────────────┤
 │ PTR (reverse DNS)  │ scanme.nmap.org                                  │
 │ Reverse-IP (HT)    │ scanme.nmap.org                                  │
 │ Subdomain (crt.sh) │ scanme.nmap.org                                  │
 ╰────────────────────┴──────────────────────────────────────────────────╯

 ╭──────────────────────────── Found Paths ────────────────────────────╮
 │ Status │ Size (B) │ URL                                              │
 ├────────┼──────────┼──────────────────────────────────────────────────┤
 │ 200    │ 7563     │ http://scanme.nmap.org/                          │
 │ 403    │ 292      │ http://scanme.nmap.org/.htaccess                 │
 │ 301    │ 315      │ http://scanme.nmap.org/images                    │
 ╰────────┴──────────┴──────────────────────────────────────────────────╯

 ╭─────────────────────────── Summary ────────────────────────────────╮
 │ ✔ Ports: 4 open   ✔ Hosts/Subs: 2 found   ✔ Paths: 3 interesting  │
 ╰────────────────────────────────────────────────────────────────────╯
```

### Example JSON report (`report.json`)

```json
{
  "meta": {
    "tool": "TriRecon",
    "target": "scanme.nmap.org",
    "scanned_at": "2024-09-15T12:34:00Z",
    "elapsed_seconds": 42.3
  },
  "ports": [
    { "port": "22", "protocol": "tcp", "service": "ssh", "version": "OpenSSH 6.6.1p1 Ubuntu", "state": "open" },
    { "port": "80", "protocol": "tcp", "service": "http", "version": "Apache httpd 2.4.7", "state": "open" }
  ],
  "host_discovery": {
    "ptr_hostname": "scanme.nmap.org",
    "reverse_ip": ["scanme.nmap.org"],
    "subdomains": ["scanme.nmap.org"],
    "domain_used": "nmap.org"
  },
  "found_paths": [
    { "url": "http://scanme.nmap.org/", "status": 200, "size": 7563 },
    { "url": "http://scanme.nmap.org/.htaccess", "status": 403, "size": 292 }
  ]
}
```

---

## 🔌 Module Details

### `core/portscan.py`
- Runs: `nmap -sV -oX <tempfile> <target>`
- Parses the XML output with `xml.etree.ElementTree`
- Returns only **open** ports: `{port, protocol, service, version, state}`
- Temporary XML file is always cleaned up, even on error

### `core/hostdiscovery.py`
- **PTR lookup** via `socket.gethostbyaddr()` (reverse-DNS)
- **Reverse-IP** via [HackerTarget free API](https://hackertarget.com/reverse-ip-lookup/) — finds other domains hosted on the same IP
- **Subdomain enumeration** via [crt.sh](https://crt.sh) Certificate Transparency logs — deduped and wildcard-stripped

### `core/dirbrute.py`
- Loads a wordlist file, probes `http://host/<word>` and `https://host/<word>`
- Uses `concurrent.futures.ThreadPoolExecutor` (default 20 threads)
- 5-second per-request timeout; SSL verification disabled with `urllib3` warning suppressed
- Reports status codes: **200** (OK), **301/302** (redirect), **401** (auth required), **403** (forbidden)

### `core/report.py`
- Three `rich.table.Table` sections in the terminal
- Optional JSON export via `--output`

### `core/storage.py`
- SQLite3 database at `~/.trirecon/history.db`
- Saves full JSON payloads per scan run
- `history` command lists previous runs

---

## 🌐 Extending the Wordlist

The bundled `wordlists/common.txt` covers ~150 paths. For more thorough assessments consider:

```bash
# SecLists (requires git):
git clone https://github.com/danielmiessler/SecLists.git
python trirecon.py scan --target example.com \
    --dirs --wordlist SecLists/Discovery/Web-Content/common.txt

# dirb built-in wordlists (apt):
sudo apt install dirb
python trirecon.py scan --target example.com \
    --dirs --wordlist /usr/share/dirb/wordlists/common.txt
```

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-module`)
3. Commit your changes (`git commit -m 'feat: add my-module'`)
4. Push to the branch (`git push origin feature/my-module`)
5. Open a Pull Request

Please ensure any new module follows the same pattern: a single public `run_*()` function that returns a `list[dict]` or `dict`, with graceful error handling.

---

## 📜 License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE) for details.

---

*Built for learning, CTFs, and authorized penetration testing. Use responsibly.*
