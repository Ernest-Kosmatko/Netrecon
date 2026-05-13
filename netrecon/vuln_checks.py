"""
NetRecon - Vulnerability Checks
Passive banner-based vulnerability detection engine.

@author  Ernest Kosmatko <https://github.com/Ernest-Kosmatko>
@license MIT
"""

from dataclasses import dataclass, field
from .scanner import HostResult, PortResult
from .utils import logger


@dataclass
class Vulnerability:
    cve_id: str
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW / INFO
    title: str
    description: str
    affected_port: int
    affected_service: str
    recommendation: str
    references: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Signature database (extend freely!)
# ---------------------------------------------------------------------------

BANNER_SIGNATURES: list[dict] = [
    # SSH
    {
        "service": "SSH",
        "match": "SSH-2.0-OpenSSH_7",
        "cve": "CVE-2018-15473",
        "severity": "MEDIUM",
        "title": "OpenSSH 7.x User Enumeration",
        "description": (
            "OpenSSH versions before 7.8 are vulnerable to user enumeration "
            "via the auth2-gss.c, auth2-hostbased.c, and auth2-pubkey.c components."
        ),
        "recommendation": "Upgrade OpenSSH to version 7.8 or later.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2018-15473"],
    },
    {
        "service": "SSH",
        "match": "SSH-1.",
        "cve": "CVE-2001-0361",
        "severity": "CRITICAL",
        "title": "SSH Protocol Version 1 Enabled",
        "description": (
            "SSH protocol version 1 has fundamental design flaws including "
            "session hijacking and man-in-the-middle vulnerabilities."
        ),
        "recommendation": "Disable SSHv1 and enforce SSHv2 only.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2001-0361"],
    },
    # FTP
    {
        "service": "FTP",
        "match": "220 (vsFTPd 2.3.4)",
        "cve": "CVE-2011-2523",
        "severity": "CRITICAL",
        "title": "vsFTPd 2.3.4 Backdoor",
        "description": (
            "vsFTPd version 2.3.4 contains a backdoor that allows remote "
            "attackers to execute arbitrary code via a crafted username."
        ),
        "recommendation": "Immediately upgrade vsFTPd. This version should never be used.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2011-2523"],
    },
    {
        "service": "FTP",
        "match": "Anonymous",
        "cve": "N/A",
        "severity": "HIGH",
        "title": "Anonymous FTP Login Enabled",
        "description": "The FTP server allows anonymous authentication, potentially exposing sensitive files.",
        "recommendation": "Disable anonymous FTP access unless explicitly required.",
        "references": [],
    },
    # HTTP
    {
        "service": "HTTP",
        "match": "Apache/2.2",
        "cve": "CVE-2017-7679",
        "severity": "HIGH",
        "title": "Apache 2.2.x mod_mime Buffer Overread",
        "description": "Apache HTTP Server 2.2.x is end-of-life and has multiple known vulnerabilities.",
        "recommendation": "Upgrade to Apache 2.4.x or later immediately.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2017-7679"],
    },
    {
        "service": "HTTP",
        "match": "IIS/6.0",
        "cve": "CVE-2017-7269",
        "severity": "CRITICAL",
        "title": "IIS 6.0 WebDAV Buffer Overflow (EternalBlue adjacent)",
        "description": (
            "Microsoft IIS 6.0 WebDAV is vulnerable to a buffer overflow "
            "allowing remote code execution. This version is end-of-life."
        ),
        "recommendation": "Upgrade to a supported version of IIS immediately.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2017-7269"],
    },
    # Telnet
    {
        "service": "Telnet",
        "match": "",   # Any banner — telnet itself is the issue
        "cve": "N/A",
        "severity": "HIGH",
        "title": "Telnet Service Running",
        "description": (
            "Telnet transmits all data in cleartext, including credentials. "
            "It should be replaced with SSH."
        ),
        "recommendation": "Disable Telnet and use SSH for remote administration.",
        "references": [],
    },
]

# Ports that indicate insecure services regardless of banner
INSECURE_PORT_RULES: list[dict] = [
    {
        "port": 23,
        "cve": "N/A",
        "severity": "HIGH",
        "title": "Telnet Port Open",
        "description": "Port 23 (Telnet) is open. Telnet is an unencrypted protocol.",
        "recommendation": "Replace Telnet with SSH (port 22).",
        "references": [],
    },
    {
        "port": 445,
        "cve": "CVE-2017-0144",
        "severity": "CRITICAL",
        "title": "SMB Port Exposed (EternalBlue risk)",
        "description": (
            "Port 445 (SMB) is accessible. If unpatched, this service may be "
            "vulnerable to EternalBlue (MS17-010) allowing remote code execution."
        ),
        "recommendation": "Apply MS17-010 patch, disable SMBv1, and block port 445 at perimeter.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2017-0144"],
    },
    {
        "port": 3389,
        "cve": "CVE-2019-0708",
        "severity": "CRITICAL",
        "title": "RDP Exposed (BlueKeep risk)",
        "description": (
            "Port 3389 (RDP) is accessible from the network. If unpatched, "
            "it may be vulnerable to BlueKeep (CVE-2019-0708)."
        ),
        "recommendation": "Patch CVE-2019-0708, use NLA, restrict RDP behind VPN.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-0708"],
    },
    {
        "port": 6379,
        "cve": "N/A",
        "severity": "HIGH",
        "title": "Redis Exposed Without Authentication",
        "description": (
            "Redis (port 6379) is accessible. Redis defaults to no authentication "
            "and can be abused for data exfiltration or RCE via SLAVEOF."
        ),
        "recommendation": "Bind Redis to localhost, enable requirepass, use stunnel/TLS.",
        "references": [],
    },
    {
        "port": 27017,
        "cve": "N/A",
        "severity": "HIGH",
        "title": "MongoDB Exposed Without Authentication",
        "description": (
            "MongoDB (port 27017) is accessible. By default MongoDB has no "
            "authentication enabled."
        ),
        "recommendation": "Enable MongoDB authentication, bind to localhost, use TLS.",
        "references": [],
    },
]


class VulnerabilityChecker:
    """Match open ports and banners against known vulnerability signatures."""

    def check_host(self, host: HostResult) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        open_port_numbers = {p.port for p in host.open_ports}

        for rule in INSECURE_PORT_RULES:
            if rule["port"] in open_port_numbers:
                vulns.append(Vulnerability(
                    cve_id=rule["cve"],
                    severity=rule["severity"],
                    title=rule["title"],
                    description=rule["description"],
                    affected_port=rule["port"],
                    affected_service=str(rule["port"]),
                    recommendation=rule["recommendation"],
                    references=rule["references"],
                ))
                logger.warning(f"  [!] {rule['severity']:8s} | {rule['title']}")

        for port_result in host.open_ports:
            for sig in BANNER_SIGNATURES:
                if sig["match"] and sig["match"].lower() in port_result.banner.lower():
                    vulns.append(Vulnerability(
                        cve_id=sig["cve"],
                        severity=sig["severity"],
                        title=sig["title"],
                        description=sig["description"],
                        affected_port=port_result.port,
                        affected_service=port_result.service,
                        recommendation=sig["recommendation"],
                        references=sig["references"],
                    ))
                    logger.warning(f"  [!] {sig['severity']:8s} | {sig['title']} (port {port_result.port})")

        return vulns
