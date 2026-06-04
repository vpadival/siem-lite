#!/usr/bin/env python3
"""
Shared utilities for SIEM-Lite scorers.

Centralises helpers used by both alert_scorer.py and ml_scorer.py
so logic is never duplicated across the two entry points.
"""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger("siem-lite")

# Standard log file candidates, tried in order.
_LOG_CANDIDATES = [
    "/var/log/auth.log",    # Debian / Ubuntu
    "/var/log/secure",      # RHEL / CentOS / Fedora
    "/var/log/syslog",      # Debian / Ubuntu (general)
    "/var/log/messages",    # RHEL / CentOS / Fedora (general)
]


def discover_log_paths() -> list[str]:
    """Return existing log paths for the current distro.

    Checks the standard locations for Debian/Ubuntu and RHEL/Fedora.
    Emits a warning with actionable advice when nothing is found
    (e.g. systemd-journal-only systems).
    """
    found = [p for p in _LOG_CANDIDATES if Path(p).exists()]
    if not found:
        logger.warning(
            "No standard log files found. Your distro may use systemd-journal only.\n"
            "  Debian/Ubuntu/Parrot: sudo apt install rsyslog && sudo systemctl enable --now rsyslog\n"
            "  RHEL/Fedora:          sudo dnf install rsyslog && sudo systemctl enable --now rsyslog\n"
            "  Alternatively pipe journalctl: journalctl -f | python3 alert_scorer.py  (stdin not yet implemented)"
        )
    return found
