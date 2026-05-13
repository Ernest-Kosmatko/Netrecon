"""
NetRecon - Utilities
Shared logger and helper functions.

@author  Ernest Kosmatko <https://github.com/Ernest-Kosmatko>
@license MIT
"""

import logging
import sys


def _build_logger() -> logging.Logger:
    log = logging.getLogger("netrecon")
    log.setLevel(logging.DEBUG)
    if not log.handlers:
        handler = logging.StreamHandler(sys.stdout)
        fmt = logging.Formatter("%(message)s")
        handler.setFormatter(fmt)
        log.addHandler(handler)
    return log


logger = _build_logger()


def parse_port_range(spec: str) -> list[int]:
    """
    Parse port specification string into a list of ints.
    Supported formats:
      - "80"           → [80]
      - "80,443,8080"  → [80, 443, 8080]
      - "1-1024"       → [1, 2, ..., 1024]
      - "22,80,8000-8080"
    """
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)
