"""
NetRecon — Unit Tests
Run: pytest tests/ -v

@author  Ernest Kosmatko <https://github.com/Ernest-Kosmatko>
"""

import pytest
from unittest.mock import patch, MagicMock
import socket

from netrecon.scanner import PortScanner, HostDiscovery, COMMON_PORTS, PortResult, HostResult
from netrecon.vuln_checks import VulnerabilityChecker, Vulnerability
from netrecon.utils import parse_port_range


# ── parse_port_range ────────────────────────────────────────────────────────

class TestParsePortRange:
    def test_single_port(self):
        assert parse_port_range("80") == [80]

    def test_comma_separated(self):
        assert parse_port_range("22,80,443") == [22, 80, 443]

    def test_range(self):
        result = parse_port_range("8080-8083")
        assert result == [8080, 8081, 8082, 8083]

    def test_mixed(self):
        result = parse_port_range("22,80,8080-8082")
        assert result == [22, 80, 8080, 8081, 8082]

    def test_dedup(self):
        result = parse_port_range("80,80,443")
        assert result.count(80) == 1


# ── PortScanner ──────────────────────────────────────────────────────────────

class TestPortScanner:
    def _scanner(self, timeout=0.5, grab=False):
        return PortScanner(timeout=timeout, max_threads=10, grab_banners=grab)

    @patch("socket.create_connection")
    def test_open_port(self, mock_conn):
        mock_sock = MagicMock()
        mock_sock.__enter__ = lambda s: s
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_8.9"
        mock_conn.return_value = mock_sock

        scanner = PortScanner(timeout=0.5, max_threads=5, grab_banners=True)
        result = scanner._probe_port("127.0.0.1", 22)
        assert result.state == "open"
        assert result.port == 22
        assert result.service == "SSH"

    @patch("socket.create_connection", side_effect=ConnectionRefusedError)
    def test_closed_port(self, _):
        scanner = self._scanner()
        result = scanner._probe_port("127.0.0.1", 9999)
        assert result.state == "closed"

    @patch("socket.create_connection", side_effect=socket.timeout)
    def test_timeout_port(self, _):
        scanner = self._scanner()
        result = scanner._probe_port("127.0.0.1", 9998)
        assert result.state == "closed"

    def test_scan_returns_only_open(self):
        scanner = self._scanner()
        open_result = PortResult(port=80, state="open", service="HTTP")
        closed_result = PortResult(port=9999, state="closed", service="unknown")

        with patch.object(scanner, "_probe_port", side_effect=[open_result, closed_result]):
            results = scanner.scan_ports("127.0.0.1", [80, 9999])
        assert all(r.state == "open" for r in results)
        assert len(results) == 1

    def test_results_sorted_by_port(self):
        scanner = self._scanner()
        results_map = {
            443: PortResult(port=443, state="open"),
            22:  PortResult(port=22,  state="open"),
            80:  PortResult(port=80,  state="open"),
        }
        with patch.object(scanner, "_probe_port", side_effect=lambda ip, p: results_map[p]):
            results = scanner.scan_ports("127.0.0.1", [443, 22, 80])
        assert [r.port for r in results] == [22, 80, 443]


# ── HostDiscovery ────────────────────────────────────────────────────────────

class TestHostDiscovery:
    @patch("socket.create_connection", side_effect=ConnectionRefusedError)
    def test_host_up_via_refused(self, _):
        hd = HostDiscovery(timeout=0.2)
        # ConnectionRefused means host is alive but port is closed
        assert hd.is_host_up("127.0.0.1") is True

    @patch("socket.create_connection")
    def test_host_up_via_connect(self, mock_conn):
        mock_conn.return_value.__enter__ = lambda s: s
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)
        hd = HostDiscovery(timeout=0.2)
        assert hd.is_host_up("127.0.0.1") is True

    @patch("socket.create_connection", side_effect=OSError)
    @patch("socket.gethostbyaddr", side_effect=socket.herror)
    def test_host_down(self, _, __):
        hd = HostDiscovery(timeout=0.1)
        assert hd.is_host_up("192.0.2.1") is False

    @patch("socket.gethostbyaddr", return_value=("myhost.local", [], ["192.168.1.1"]))
    def test_resolve_hostname(self, _):
        hd = HostDiscovery()
        assert hd.resolve_hostname("192.168.1.1") == "myhost.local"

    @patch("socket.gethostbyaddr", side_effect=socket.herror)
    def test_resolve_hostname_failure(self, _):
        hd = HostDiscovery()
        assert hd.resolve_hostname("10.0.0.1") == ""


# ── VulnerabilityChecker ─────────────────────────────────────────────────────

class TestVulnerabilityChecker:
    def _make_host(self, ip="10.0.0.1", ports=None):
        open_ports = [
            PortResult(port=p["port"], state="open",
                       service=p.get("service", "unknown"),
                       banner=p.get("banner", ""))
            for p in (ports or [])
        ]
        return HostResult(ip=ip, is_up=True, open_ports=open_ports)

    def test_smb_critical(self):
        host = self._make_host(ports=[{"port": 445, "service": "SMB"}])
        checker = VulnerabilityChecker()
        vulns = checker.check_host(host)
        sev = [v.severity for v in vulns]
        assert "CRITICAL" in sev

    def test_rdp_critical(self):
        host = self._make_host(ports=[{"port": 3389, "service": "RDP"}])
        checker = VulnerabilityChecker()
        vulns = checker.check_host(host)
        cves = [v.cve_id for v in vulns]
        assert "CVE-2019-0708" in cves

    def test_vsftpd_backdoor(self):
        host = self._make_host(ports=[{
            "port": 21, "service": "FTP",
            "banner": "220 (vsFTPd 2.3.4)"
        }])
        checker = VulnerabilityChecker()
        vulns = checker.check_host(host)
        cves = [v.cve_id for v in vulns]
        assert "CVE-2011-2523" in cves

    def test_ssh_user_enum(self):
        host = self._make_host(ports=[{
            "port": 22, "service": "SSH",
            "banner": "SSH-2.0-OpenSSH_7.4"
        }])
        checker = VulnerabilityChecker()
        vulns = checker.check_host(host)
        cves = [v.cve_id for v in vulns]
        assert "CVE-2018-15473" in cves

    def test_clean_host_no_vulns(self):
        host = self._make_host(ports=[{"port": 80, "service": "HTTP", "banner": "nginx/1.24"}])
        checker = VulnerabilityChecker()
        vulns = checker.check_host(host)
        assert len(vulns) == 0

    def test_telnet_open(self):
        host = self._make_host(ports=[{"port": 23, "service": "Telnet"}])
        checker = VulnerabilityChecker()
        vulns = checker.check_host(host)
        titles = [v.title for v in vulns]
        assert any("Telnet" in t for t in titles)

    def test_redis_exposed(self):
        host = self._make_host(ports=[{"port": 6379, "service": "Redis"}])
        checker = VulnerabilityChecker()
        vulns = checker.check_host(host)
        assert any("Redis" in v.title for v in vulns)
