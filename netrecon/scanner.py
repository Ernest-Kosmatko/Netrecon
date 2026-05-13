"""
NetRecon - Network Reconnaissance & Vulnerability Scanner
Core scanning engine

@author  Ernest Kosmatko <https://github.com/Ernest-Kosmatko>
@license MIT
"""

import socket
import ipaddress
import concurrent.futures
import time
from dataclasses import dataclass, field
from typing import Optional
from .utils import logger


@dataclass
class PortResult:
    port: int
    state: str  # open / closed / filtered
    service: str = "unknown"
    banner: str = ""
    response_time_ms: float = 0.0


@dataclass
class HostResult:
    ip: str
    hostname: str = ""
    is_up: bool = False
    open_ports: list[PortResult] = field(default_factory=list)
    os_hint: str = ""
    scan_duration_s: float = 0.0


COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}


class PortScanner:
    """TCP connect scanner with optional banner grabbing."""

    def __init__(self, timeout: float = 1.0, max_threads: int = 100, grab_banners: bool = True):
        self.timeout = timeout
        self.max_threads = max_threads
        self.grab_banners = grab_banners

    def _probe_port(self, ip: str, port: int) -> PortResult:
        start = time.perf_counter()
        try:
            with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                elapsed = (time.perf_counter() - start) * 1000
                banner = ""
                if self.grab_banners:
                    try:
                        sock.settimeout(0.5)
                        raw = sock.recv(1024)
                        banner = raw.decode("utf-8", errors="replace").strip()[:200]
                    except Exception:
                        pass
                service = COMMON_PORTS.get(port, "unknown")
                return PortResult(port=port, state="open", service=service,
                                  banner=banner, response_time_ms=round(elapsed, 2))
        except (ConnectionRefusedError, socket.timeout, OSError):
            elapsed = (time.perf_counter() - start) * 1000
            return PortResult(port=port, state="closed",
                              service=COMMON_PORTS.get(port, "unknown"),
                              response_time_ms=round(elapsed, 2))

    def scan_ports(self, ip: str, ports: list[int]) -> list[PortResult]:
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as ex:
            futures = {ex.submit(self._probe_port, ip, p): p for p in ports}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result.state == "open":
                    results.append(result)
                    logger.info(f"  [+] {ip}:{result.port} OPEN ({result.service})")
        return sorted(results, key=lambda r: r.port)


class HostDiscovery:
    """ICMP-free host discovery using TCP probes."""

    DISCOVERY_PORTS = [22, 80, 443, 445, 3389]

    def __init__(self, timeout: float = 1.0):
        self.timeout = timeout

    def is_host_up(self, ip: str) -> bool:
        for port in self.DISCOVERY_PORTS:
            try:
                with socket.create_connection((ip, port), timeout=self.timeout):
                    return True
            except (ConnectionRefusedError,):
                # Refused = host is up but port closed
                return True
            except Exception:
                continue
        # Fallback: try DNS resolution
        try:
            socket.gethostbyaddr(ip)
            return True
        except Exception:
            return False

    def resolve_hostname(self, ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return ""

    def scan_network(self, cidr: str, max_threads: int = 50) -> list[str]:
        """Return list of responsive IPs in a CIDR range."""
        network = ipaddress.ip_network(cidr, strict=False)
        hosts = [str(h) for h in network.hosts()]
        logger.info(f"[*] Discovering hosts in {cidr} ({len(hosts)} addresses)")
        live = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as ex:
            futures = {ex.submit(self.is_host_up, ip): ip for ip in hosts}
            for future in concurrent.futures.as_completed(futures):
                ip = futures[future]
                if future.result():
                    live.append(ip)
                    logger.info(f"  [+] Host up: {ip}")
        return sorted(live)


class NetRecon:
    """Main orchestrator — ties host discovery + port scanning together."""

    def __init__(
        self,
        timeout: float = 1.0,
        max_threads: int = 100,
        grab_banners: bool = True,
        port_range: Optional[list[int]] = None,
    ):
        self.port_scanner = PortScanner(timeout=timeout, max_threads=max_threads,
                                        grab_banners=grab_banners)
        self.host_discovery = HostDiscovery(timeout=timeout)
        self.port_range = port_range or list(COMMON_PORTS.keys())

    def scan_host(self, ip: str) -> HostResult:
        logger.info(f"[*] Scanning host: {ip}")
        t0 = time.perf_counter()
        hostname = self.host_discovery.resolve_hostname(ip)
        open_ports = self.port_scanner.scan_ports(ip, self.port_range)
        duration = round(time.perf_counter() - t0, 2)
        return HostResult(
            ip=ip, hostname=hostname, is_up=True,
            open_ports=open_ports, scan_duration_s=duration,
        )

    def scan_network(self, cidr: str) -> list[HostResult]:
        live_hosts = self.host_discovery.scan_network(cidr)
        results = []
        for ip in live_hosts:
            result = self.scan_host(ip)
            results.append(result)
        return results
