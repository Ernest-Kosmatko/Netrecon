# NetRecon

![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)
![CI](https://github.com/Ernest-Kosmatko/NetRecon/actions/workflows/ci.yml/badge.svg)
![Dependencies](https://img.shields.io/badge/dependencies-none-lightgrey)

A network reconnaissance and passive vulnerability scanner. It finds live hosts, scans ports, grabs banners, matches them against known vulnerability signatures and writes JSON, CSV and HTML reports. Standard library only.

> Use only on networks and systems you own or have written permission to test.

## Features

- TCP-based host discovery across CIDR ranges, no ICMP required
- Multithreaded TCP connect port scanner with configurable port ranges
- Banner grabbing for service fingerprinting
- Passive CVE matching against a list of signatures
- JSON, CSV and styled HTML reports

## Install

```bash
git clone https://github.com/Ernest-Kosmatko/NetRecon.git
cd NetRecon
pip install -e .
```

## Usage

```bash
# single host, common ports
netrecon --target 192.168.1.1

# network range
netrecon --target 192.168.1.0/24

# custom ports
netrecon --target 10.0.0.5 --ports 22,80,443,8080-8090

# all ports, more threads, shorter timeout
netrecon --target 10.0.0.1 --ports 1-65535 --threads 200 --timeout 0.5

# skip banners, JSON report in a custom folder
netrecon --target 10.0.0.1 --no-banners --output-dir ./results --format json
```

Also runnable without installing: `python -m netrecon.cli --target 192.168.1.1`

Example output:

```
[*] Scanning host: 192.168.1.10
  [+] 192.168.1.10:22 OPEN (SSH)
  [+] 192.168.1.10:80 OPEN (HTTP)
  [+] 192.168.1.10:445 OPEN (SMB)

[*] Running vulnerability checks...
  [!] CRITICAL | SMB Port Exposed (EternalBlue risk)
  [!] MEDIUM   | OpenSSH 7.x User Enumeration (port 22)

  Hosts scanned   : 1
  Open ports      : 3
  Total findings  : 2

[+] Reports saved:
    reports/scan_20240315_143022.json
    reports/scan_20240315_143022.csv
    reports/scan_20240315_143022.html
```

## Options

| Flag | Default | Description |
|---|---|---|
| `--target` | none | IP, hostname or CIDR (required) |
| `--ports` | top 17 | `22,80` or `1-1024` |
| `--threads` | `100` | Maximum concurrent threads |
| `--timeout` | `1.0` | TCP timeout in seconds |
| `--no-banners` | off | Skip banner grabbing |
| `--no-vulns` | off | Skip vulnerability checks |
| `--output-dir` | `reports/` | Where reports are written |
| `--format` | `all` | `json`, `csv`, `html` or `all` |

## Use as a library

```python
from netrecon import NetRecon, VulnerabilityChecker
from netrecon.reporter import save_html

scanner = NetRecon(timeout=1.0, max_threads=100, grab_banners=True)
checker = VulnerabilityChecker()

host = scanner.scan_host("192.168.1.10")
vulns = checker.check_host(host)

save_html([host], {host.ip: vulns}, output_dir="./reports")

for port in host.open_ports:
    print(f"{port.port}/{port.service} {port.banner}")
```

## Vulnerability signatures

| ID | Severity | Description |
|---|---|---|
| CVE-2017-0144 | Critical | EternalBlue, SMB port 445 exposed |
| CVE-2019-0708 | Critical | BlueKeep, RDP port 3389 exposed |
| CVE-2011-2523 | Critical | vsFTPd 2.3.4 backdoor |
| CVE-2001-0361 | Critical | SSHv1 protocol enabled |
| CVE-2017-7269 | Critical | IIS 6.0 WebDAV buffer overflow |
| CVE-2018-15473 | High | OpenSSH 7.x user enumeration |
| CVE-2017-7679 | High | Apache 2.2.x end of life |
| N/A | High | Anonymous FTP login |
| N/A | High | Telnet service running |
| N/A | High | Redis or MongoDB exposed without authentication |

New signatures go into `BANNER_SIGNATURES` or `INSECURE_PORT_RULES` in `netrecon/vuln_checks.py`.

## Project structure

```
NetRecon/
├── netrecon/
│   ├── scanner.py       host discovery and port scanning
│   ├── vuln_checks.py   signature matching
│   ├── reporter.py      JSON, CSV and HTML reports
│   ├── cli.py           command line entry point
│   └── utils.py         logger, port range parser
├── tests/
├── .github/workflows/ci.yml
├── pyproject.toml
└── README.md
```

## Tests

```bash
pip install -r requirements-dev.txt
pytest tests/ -v --cov=netrecon
```

## Limitations

- Detection is passive and based on open ports and banners, so results are indicators, not confirmed vulnerabilities, and false positives are possible
- Connect scanning is noisy and appears in target logs

## License

MIT
