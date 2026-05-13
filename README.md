# ⬡ NetRecon

> **Network Reconnaissance & Vulnerability Scanner**  
> A lightweight, fast Python tool for authorized network reconnaissance and passive vulnerability detection.

[![CI](https://github.com/Ernest-Kosmatko/NetRecon/actions/workflows/ci.yml/badge.svg)](https://github.com/Ernest-Kosmatko/NetRecon/actions)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

---

## 🔍 What is NetRecon?

NetRecon is a Python-based offensive security tool for **authorized** network reconnaissance. It combines:

- **Host Discovery** — TCP-based host discovery across CIDR ranges (no ICMP required)
- **Port Scanning** — Multi-threaded TCP connect scanner with configurable port ranges
- **Banner Grabbing** — Service fingerprinting via response banners
- **Vulnerability Detection** — Passive CVE matching against known signatures
- **Reporting** — Exports results as JSON, CSV, and styled HTML

Built with zero external runtime dependencies (Python stdlib only).

---

## 📸 Sample Output

```
 _   _      _   ____
| \ | | ___| |_|  _ \ ___  ___ ___  _ __
|  \| |/ _ \ __| |_) / _ \/ __/ _ \| '_ \
| |\  |  __/ |_|  _ <  __/ (_| (_) | | | |
|_| \_|\___|\__|_| \_\___|\___\___/|_| |_|

[*] Mode: Single host scan (192.168.1.10)
[*] Scanning host: 192.168.1.10
  [+] 192.168.1.10:22 OPEN (SSH)
  [+] 192.168.1.10:80 OPEN (HTTP)
  [+] 192.168.1.10:445 OPEN (SMB)

[*] Running vulnerability checks...
  [!] CRITICAL | SMB Port Exposed (EternalBlue risk)
  [!] MEDIUM   | OpenSSH 7.x User Enumeration (port 22)

───────────────────────────────────────────────────────
  SCAN SUMMARY
───────────────────────────────────────────────────────
  Hosts scanned   : 1
  Open ports      : 3
  Total findings  : 2
    CRITICAL      : 1
    MEDIUM        : 1
───────────────────────────────────────────────────────

[+] Reports saved:
    reports/scan_20240315_143022.json
    reports/scan_20240315_143022.csv
    reports/scan_20240315_143022.html
```

---

## 🚀 Quick Start

### Prerequisites

- Python 3.10+
- Target host(s) **you own or have explicit written permission to scan**

### Installation

```bash
# Clone the repository
git clone https://github.com/Ernest-Kosmatko/NetRecon.git
cd NetRecon

# Install (creates the `netrecon` CLI command)
pip install -e .
```

### Usage

```bash
# Scan a single host (top common ports)
netrecon --target 192.168.1.1

# Scan a network range
netrecon --target 192.168.1.0/24

# Custom port range
netrecon --target 10.0.0.5 --ports 22,80,443,8080-8090

# Full port scan with more threads
netrecon --target 10.0.0.1 --ports 1-65535 --threads 200 --timeout 0.5

# Skip banners for faster scan
netrecon --target 10.0.0.1 --no-banners

# Save to custom directory, JSON only
netrecon --target 10.0.0.1 --output-dir ./results --format json
```

### All Options

| Flag | Default | Description |
|------|---------|-------------|
| `--target` | — | IP, hostname, or CIDR (required) |
| `--ports` | top 17 | Port spec: `22,80` or `1-1024` |
| `--threads` | `100` | Max concurrent threads |
| `--timeout` | `1.0` | TCP timeout (seconds) |
| `--no-banners` | off | Skip banner grabbing |
| `--no-vulns` | off | Skip vulnerability checks |
| `--output-dir` | `reports/` | Report output directory |
| `--format` | `all` | `json` / `csv` / `html` / `all` |

---

## 🧠 Use as a Library

```python
from netrecon import NetRecon, VulnerabilityChecker
from netrecon.reporter import save_html

scanner = NetRecon(timeout=1.0, max_threads=100, grab_banners=True)
checker = VulnerabilityChecker()

# Scan a single host
host = scanner.scan_host("192.168.1.10")

# Check vulnerabilities
vulns = checker.check_host(host)
vulns_map = {host.ip: vulns}

# Save HTML report
report_path = save_html([host], vulns_map, output_dir="./reports")
print(f"Report: {report_path}")

# Access results programmatically
for port in host.open_ports:
    print(f"{port.port}/{port.service} — {port.banner}")

for vuln in vulns:
    print(f"[{vuln.severity}] {vuln.cve_id}: {vuln.title}")
```

---

## 🏗️ Project Structure

```
NetRecon/
├── netrecon/
│   ├── __init__.py       # Public API
│   ├── scanner.py        # Host discovery + port scanning engine
│   ├── vuln_checks.py    # CVE signature matching
│   ├── reporter.py       # JSON / CSV / HTML report generation
│   ├── cli.py            # CLI entry point
│   └── utils.py          # Logger, port range parser
├── tests/
│   └── test_netrecon.py  # Unit tests (pytest)
├── .github/
│   └── workflows/
│       └── ci.yml        # GitHub Actions CI (Python 3.10–3.12)
├── reports/              # Generated reports (gitignored)
├── pyproject.toml
├── requirements.txt
├── requirements-dev.txt
└── README.md
```

---

## 🧪 Running Tests

```bash
pip install -r requirements-dev.txt
pytest tests/ -v --cov=netrecon
```

---

## 🔍 Vulnerability Signatures

NetRecon includes passive detection for:

| CVE / ID | Severity | Description |
|----------|----------|-------------|
| CVE-2017-0144 | 🔴 CRITICAL | EternalBlue — SMB port 445 exposure |
| CVE-2019-0708 | 🔴 CRITICAL | BlueKeep — RDP port 3389 exposure |
| CVE-2011-2523 | 🔴 CRITICAL | vsFTPd 2.3.4 backdoor |
| CVE-2001-0361 | 🔴 CRITICAL | SSHv1 protocol enabled |
| CVE-2018-15473 | 🟠 HIGH | OpenSSH 7.x user enumeration |
| CVE-2017-7679 | 🟠 HIGH | Apache 2.2.x end-of-life |
| CVE-2017-7269 | 🔴 CRITICAL | IIS 6.0 WebDAV buffer overflow |
| N/A | 🟠 HIGH | Anonymous FTP login |
| N/A | 🟠 HIGH | Telnet service running |
| N/A | 🟠 HIGH | Redis / MongoDB exposed without auth |

> Adding new signatures is easy — extend the `BANNER_SIGNATURES` or `INSECURE_PORT_RULES` lists in `netrecon/vuln_checks.py`.

---

## ⚠️ Legal Disclaimer

**This tool is for authorized security testing only.**  
Scanning networks or systems without explicit written permission from the owner is illegal under the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, and equivalent laws worldwide.  

The author assumes no liability for misuse of this software.  
**Always get written authorization before scanning any target.**

---

## 📄 License

[MIT](LICENSE) © Ernest Kosmatko

---

## 👤 Author

**Ernest Kosmatko**  
GitHub: [@Ernest-Kosmatko](https://github.com/Ernest-Kosmatko)
