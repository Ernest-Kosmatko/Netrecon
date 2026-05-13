#!/usr/bin/env python3
"""
NetRecon — CLI Entry Point
Usage: python -m netrecon.cli --help
       netrecon --help (after pip install -e .)

@author  Ernest Kosmatko <https://github.com/Ernest-Kosmatko>
@license MIT
"""

import argparse
import sys
from netrecon.scanner import NetRecon
from netrecon.vuln_checks import VulnerabilityChecker
from netrecon import reporter
from netrecon.utils import logger, parse_port_range

BANNER = r"""
 _   _      _   ____
| \ | | ___| |_|  _ \ ___  ___ ___  _ __
|  \| |/ _ \ __| |_) / _ \/ __/ _ \| '_ \
| |\  |  __/ |_|  _ <  __/ (_| (_) | | | |
|_| \_|\___|\__|_| \_\___|\___\___/|_| |_|

  Network Reconnaissance & Vulnerability Scanner
  Author: Ernest Kosmatko · github.com/Ernest-Kosmatko/NetRecon
  Version: 1.0.0 · For authorized testing only.
"""

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def print_summary(hosts, vulns_map):
    total = sum(len(v) for v in vulns_map.values())
    by_sev = {}
    for vlist in vulns_map.values():
        for v in vlist:
            by_sev[v.severity] = by_sev.get(v.severity, 0) + 1

    logger.info("\n" + "─" * 55)
    logger.info("  SCAN SUMMARY")
    logger.info("─" * 55)
    logger.info(f"  Hosts scanned   : {len(hosts)}")
    logger.info(f"  Open ports      : {sum(len(h.open_ports) for h in hosts)}")
    logger.info(f"  Total findings  : {total}")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        count = by_sev.get(sev, 0)
        if count:
            logger.info(f"    {sev:8s}      : {count}")
    logger.info("─" * 55)


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        prog="netrecon",
        description="Network Reconnaissance & Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  netrecon --target 192.168.1.1
  netrecon --target 192.168.1.0/24
  netrecon --target 10.0.0.5 --ports 22,80,443,8080-8090
  netrecon --target 192.168.1.1 --ports 1-65535 --threads 200
  netrecon --target 10.0.0.1 --no-banners --output-dir ./results

⚠  Only scan hosts you own or have explicit written permission to test.
        """,
    )
    parser.add_argument("--target", required=True,
                        help="Single IP, hostname, or CIDR range (e.g. 192.168.1.0/24)")
    parser.add_argument("--ports",  default=None,
                        help="Ports to scan (default: top 17 common ports). Examples: '22,80,443' or '1-1024'")
    parser.add_argument("--threads", type=int, default=100,
                        help="Max concurrent threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="TCP connect timeout in seconds (default: 1.0)")
    parser.add_argument("--no-banners", action="store_true",
                        help="Skip banner grabbing (faster)")
    parser.add_argument("--no-vulns", action="store_true",
                        help="Skip vulnerability checks")
    parser.add_argument("--output-dir", default="reports",
                        help="Directory to save reports (default: ./reports)")
    parser.add_argument("--format", choices=["all", "json", "csv", "html"], default="all",
                        help="Report format (default: all)")
    args = parser.parse_args()

    port_range = parse_port_range(args.ports) if args.ports else None

    scanner = NetRecon(
        timeout=args.timeout,
        max_threads=args.threads,
        grab_banners=not args.no_banners,
        port_range=port_range,
    )

    # Detect if target is a CIDR range
    is_cidr = "/" in args.target
    if is_cidr:
        logger.info(f"[*] Mode: Network scan ({args.target})")
        hosts = scanner.scan_network(args.target)
    else:
        logger.info(f"[*] Mode: Single host scan ({args.target})")
        hosts = [scanner.scan_host(args.target)]

    if not hosts:
        logger.info("[!] No hosts discovered. Exiting.")
        sys.exit(0)

    # Vulnerability analysis
    vulns_map: dict = {}
    if not args.no_vulns:
        logger.info("\n[*] Running vulnerability checks...")
        checker = VulnerabilityChecker()
        for host in hosts:
            vulns = checker.check_host(host)
            if vulns:
                vulns_map[host.ip] = vulns

    print_summary(hosts, vulns_map)

    # Reports
    saved = []
    fmt = args.format
    if fmt in ("all", "json"):
        p = reporter.save_json(hosts, vulns_map, args.output_dir)
        saved.append(p)
    if fmt in ("all", "csv"):
        p = reporter.save_csv(hosts, vulns_map, args.output_dir)
        saved.append(p)
    if fmt in ("all", "html"):
        p = reporter.save_html(hosts, vulns_map, args.output_dir)
        saved.append(p)

    logger.info("\n[+] Reports saved:")
    for p in saved:
        logger.info(f"    {p}")
    logger.info("")


if __name__ == "__main__":
    main()
