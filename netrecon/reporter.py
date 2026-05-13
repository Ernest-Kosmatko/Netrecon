"""
NetRecon - Report Generator
Outputs scan results as JSON, CSV, and styled HTML.

@author  Ernest Kosmatko <https://github.com/Ernest-Kosmatko>
@license MIT
"""

import json
import csv
import os
from datetime import datetime
from dataclasses import asdict
from .scanner import HostResult
from .vuln_checks import Vulnerability

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLOR = {
    "CRITICAL": "#ff2d55",
    "HIGH":     "#ff9500",
    "MEDIUM":   "#ffcc00",
    "LOW":      "#34c759",
    "INFO":     "#636366",
}


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _now_file() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def save_json(hosts: list[HostResult], vulns_map: dict[str, list[Vulnerability]],
              output_dir: str = "reports") -> str:
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, f"scan_{_now_file()}.json")
    payload = {
        "meta": {"tool": "NetRecon", "generated": _now(), "host_count": len(hosts)},
        "hosts": [],
    }
    for host in hosts:
        h = asdict(host)
        h["vulnerabilities"] = [asdict(v) for v in vulns_map.get(host.ip, [])]
        payload["hosts"].append(h)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    return path


def save_csv(hosts: list[HostResult], vulns_map: dict[str, list[Vulnerability]],
             output_dir: str = "reports") -> str:
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, f"scan_{_now_file()}.csv")
    rows = []
    for host in hosts:
        for port in host.open_ports:
            host_vulns = [v for v in vulns_map.get(host.ip, []) if v.affected_port == port.port]
            vuln_titles = "; ".join(v.title for v in host_vulns) or "None"
            rows.append({
                "IP": host.ip,
                "Hostname": host.hostname,
                "Port": port.port,
                "Service": port.service,
                "Banner": port.banner[:80],
                "Response_ms": port.response_time_ms,
                "Vulnerabilities": vuln_titles,
            })
    if not rows:
        rows.append({"IP": "No hosts found", "Hostname": "", "Port": "",
                     "Service": "", "Banner": "", "Response_ms": "", "Vulnerabilities": ""})
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    return path


def save_html(hosts: list[HostResult], vulns_map: dict[str, list[Vulnerability]],
              output_dir: str = "reports") -> str:
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, f"scan_{_now_file()}.html")

    total_vulns = sum(len(v) for v in vulns_map.values())
    critical = sum(1 for vl in vulns_map.values() for v in vl if v.severity == "CRITICAL")
    high = sum(1 for vl in vulns_map.values() for v in vl if v.severity == "HIGH")

    host_rows = ""
    for host in hosts:
        vulns = sorted(vulns_map.get(host.ip, []), key=lambda v: SEVERITY_ORDER.get(v.severity, 9))
        ports_html = "".join(
            f'<span class="badge">{p.port}/{p.service}</span>' for p in host.open_ports
        )
        vuln_html = ""
        for v in vulns:
            color = SEVERITY_COLOR.get(v.severity, "#999")
            refs = " ".join(
                f'<a href="{r}" target="_blank" rel="noopener">[ref]</a>' for r in v.references
            )
            vuln_html += f"""
            <div class="vuln-card" style="border-left:3px solid {color}">
              <div class="vuln-header">
                <span class="sev-badge" style="background:{color}">{v.severity}</span>
                <strong>{v.cve_id}</strong> — {v.title}
              </div>
              <p>{v.description}</p>
              <p><strong>Fix:</strong> {v.recommendation}</p>
              {f'<p class="refs">{refs}</p>' if refs else ''}
            </div>"""

        host_rows += f"""
        <div class="host-card">
          <div class="host-header">
            <span class="host-ip">{host.ip}</span>
            {f'<span class="hostname">({host.hostname})</span>' if host.hostname else ''}
            <span class="scan-time">scanned in {host.scan_duration_s}s</span>
          </div>
          <div class="ports">{ports_html or '<em>No open ports found</em>'}</div>
          {vuln_html}
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NetRecon Report — {_now()}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Syne:wght@400;700;800&display=swap');
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  :root {{
    --bg: #0a0a0f; --surface: #111118; --border: #1e1e2e;
    --text: #e8e8f0; --muted: #6b6b80; --accent: #00d4ff;
    --critical: #ff2d55; --high: #ff9500; --medium: #ffcc00;
  }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Syne', sans-serif;
         min-height: 100vh; }}
  header {{ padding: 2rem 2.5rem; border-bottom: 1px solid var(--border);
            background: linear-gradient(135deg, #0a0a0f 60%, #0d0d1a); }}
  header h1 {{ font-size: 2.2rem; font-weight: 800; letter-spacing: -1px;
               background: linear-gradient(90deg, var(--accent), #a78bfa);
               -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
  header p {{ color: var(--muted); font-size: 0.85rem; margin-top: 0.3rem; font-family: 'JetBrains Mono', monospace; }}
  .summary {{ display: flex; gap: 1rem; padding: 1.5rem 2.5rem; flex-wrap: wrap; }}
  .stat {{ background: var(--surface); border: 1px solid var(--border);
           border-radius: 12px; padding: 1rem 1.5rem; min-width: 140px; }}
  .stat .num {{ font-size: 2rem; font-weight: 800; }}
  .stat .label {{ font-size: 0.75rem; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; }}
  .stat.crit .num {{ color: var(--critical); }}
  .stat.high .num {{ color: var(--high); }}
  .stat.accent .num {{ color: var(--accent); }}
  .hosts {{ padding: 1rem 2.5rem 3rem; display: flex; flex-direction: column; gap: 1.5rem; }}
  .host-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 14px; padding: 1.5rem; }}
  .host-header {{ display: flex; align-items: baseline; gap: 0.75rem; margin-bottom: 0.75rem; flex-wrap: wrap; }}
  .host-ip {{ font-family: 'JetBrains Mono', monospace; font-size: 1.1rem; font-weight: 700; color: var(--accent); }}
  .hostname {{ color: var(--muted); font-size: 0.85rem; }}
  .scan-time {{ margin-left: auto; font-size: 0.75rem; color: var(--muted); font-family: 'JetBrains Mono', monospace; }}
  .ports {{ display: flex; flex-wrap: wrap; gap: 0.4rem; margin-bottom: 1rem; }}
  .badge {{ background: #1a1a2e; border: 1px solid #2a2a40; border-radius: 6px;
            padding: 0.25rem 0.6rem; font-family: 'JetBrains Mono', monospace;
            font-size: 0.78rem; color: #a0a0c0; }}
  .vuln-card {{ background: #0d0d15; border-left: 3px solid #333; border-radius: 0 8px 8px 0;
               padding: 1rem; margin-top: 0.75rem; }}
  .vuln-header {{ display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.5rem; flex-wrap: wrap; }}
  .sev-badge {{ padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.7rem;
               font-weight: 700; color: #000; letter-spacing: 0.5px; }}
  .vuln-card p {{ font-size: 0.85rem; color: #b0b0c8; line-height: 1.5; margin-top: 0.4rem; }}
  .refs a {{ color: var(--accent); font-size: 0.8rem; }}
  footer {{ text-align: center; padding: 2rem; color: var(--muted); font-size: 0.8rem;
            font-family: 'JetBrains Mono', monospace; border-top: 1px solid var(--border); }}
</style>
</head>
<body>
<header>
  <h1>⬡ NetRecon</h1>
  <p>Network Reconnaissance & Vulnerability Report — {_now()}</p>
</header>
<div class="summary">
  <div class="stat accent"><div class="num">{len(hosts)}</div><div class="label">Hosts Scanned</div></div>
  <div class="stat accent"><div class="num">{sum(len(h.open_ports) for h in hosts)}</div><div class="label">Open Ports</div></div>
  <div class="stat"><div class="num">{total_vulns}</div><div class="label">Findings</div></div>
  <div class="stat crit"><div class="num">{critical}</div><div class="label">Critical</div></div>
  <div class="stat high"><div class="num">{high}</div><div class="label">High</div></div>
</div>
<div class="hosts">
{host_rows or '<p style="color:var(--muted);padding:1rem">No hosts discovered.</p>'}
</div>
<footer>Generated by NetRecon v1.0.0 · github.com/Ernest-Kosmatko/NetRecon</footer>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    return path
