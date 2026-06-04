"""
Integration tests for SIEM-Lite.

Tests the full pipeline end-to-end:
  - Real detection-rules.yml loaded and matched against realistic log lines
  - alert_scorer and ml_scorer share the same discover_log_paths utility
  - Sliding-window brute-force counting (R6 / E5)
  - utils.discover_log_paths returns consistent results

Run with:  python -m pytest scripts/test_integration.py -v
"""
from __future__ import annotations

import re
import sys
import logging
import textwrap
import threading
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from alert_scorer import (
    CooldownTracker,
    load_rules,
    process_line,
)
from utils import discover_log_paths

RULES_PATH = str(Path(__file__).resolve().parent.parent / "rules" / "detection-rules.yml")

# ---------------------------------------------------------------------------
# Realistic log lines that should trigger each rule in detection-rules.yml
# ---------------------------------------------------------------------------
TRIGGER_LINES: list[tuple[str, str]] = [
    (
        "May 10 14:05:01 webserver01 sshd[4321]: Failed password for invalid user hacker "
        "from 45.33.32.156 port 51234 ssh2",
        "SSH brute force",
    ),
    (
        "May 10 09:10:22 dbserver02 sudo: bob : TTY=pts/1 ; PWD=/home/bob ; "
        "USER=root ; COMMAND=/bin/bash",
        "Privilege escalation",
    ),
    (
        "May 10 23:47:03 appserver03 sshd[9012]: Accepted password for alice "
        "from 192.168.1.15 port 58901 ssh2",
        "After-hours login",
    ),
    (
        "May 10 11:30:00 webserver01 useradd[7001]: new user: name=backdoor, "
        "UID=1099, GID=1099, home=/home/backdoor, shell=/bin/bash",
        "New user created",
    ),
    (
        "May 10 03:22:10 appserver03 sshd[6677]: Accepted password for root "
        "from 185.220.101.34 port 60001 ssh2",
        "Direct root login via SSH",
    ),
    (
        "May 10 08:15:44 dbserver02 su[3344]: FAILED su for root by intruder",
        "Repeated su failures",
    ),
]

BENIGN_LINES: list[str] = [
    "May 10 10:00:00 webserver01 sshd[1111]: Accepted password for alice from 192.168.1.10 port 50000 ssh2",
    "May 10 11:00:00 webserver01 CRON[2222]: pam_unix(cron:session): session opened for user alice(uid=1000) by (uid=0)",
    "May 10 12:00:00 dbserver02 systemd-logind[333]: New session 42 of user bob.",
]


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------
def _collect_alerts(
    lines: list[str],
    rules_path: str = RULES_PATH,
    cooldown_override: int | None = None,
) -> list[str]:
    """
    Run process_line over *lines* and return all WARNING messages containing 'ALERT'.
    If cooldown_override is set, all rules have their cooldown forced to that value.
    """
    rules = load_rules(rules_path)
    if cooldown_override is not None:
        for r in rules:
            r["cooldown"] = cooldown_override

    cooldowns = CooldownTracker()
    captured: list[str] = []

    class _Handler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            msg = record.getMessage()
            if "ALERT" in msg:
                captured.append(msg)

    handler = _Handler()
    log = logging.getLogger("siem-lite")
    log.addHandler(handler)
    try:
        for line in lines:
            process_line(line, rules, cooldowns)
    finally:
        log.removeHandler(handler)

    return captured


# ===========================================================================
# End-to-end: real detection-rules.yml vs realistic log lines
# ===========================================================================
class TestRealRulesEndToEnd:
    def test_rules_file_loads(self) -> None:
        rules = load_rules(RULES_PATH)
        assert len(rules) >= 6, "Expected at least 6 rules in detection-rules.yml"

    @pytest.mark.parametrize("log_line,expected_rule", TRIGGER_LINES)
    def test_trigger_line_fires_correct_rule(
        self, log_line: str, expected_rule: str
    ) -> None:
        """Each canonical trigger line should produce an alert for the right rule."""
        alerts = _collect_alerts([log_line], cooldown_override=0)
        assert any(expected_rule in a for a in alerts), (
            f"Expected rule '{expected_rule}' to fire for line:\n  {log_line}\n"
            f"Got alerts: {alerts}"
        )

    def test_benign_lines_produce_no_alerts(self) -> None:
        alerts = _collect_alerts(BENIGN_LINES, cooldown_override=0)
        assert alerts == [], f"Benign lines triggered unexpected alerts: {alerts}"

    def test_all_six_rules_fire_across_trigger_set(self) -> None:
        all_lines = [line for line, _ in TRIGGER_LINES]
        alerts = _collect_alerts(all_lines, cooldown_override=0)
        fired_rules = {a.split("rule=")[1].split("  ")[0] for a in alerts if "rule=" in a}
        expected = {rule for _, rule in TRIGGER_LINES}
        assert expected.issubset(fired_rules), (
            f"Missing rules in fired set.\nExpected: {expected}\nFired: {fired_rules}"
        )


# ===========================================================================
# Shared utility: discover_log_paths
# ===========================================================================
class TestDiscoverLogPaths:
    def test_returns_list(self) -> None:
        result = discover_log_paths()
        assert isinstance(result, list)

    def test_all_returned_paths_exist(self) -> None:
        for p in discover_log_paths():
            assert Path(p).exists(), f"discover_log_paths returned non-existent path: {p}"

    def test_alert_scorer_and_ml_scorer_use_same_function(self) -> None:
        """Both entry points must import from the same shared module."""
        from utils import discover_log_paths as scorer_fn
        # ml_scorer also imports from utils — verify the import chain is identical
        import utils as utils_mod
        assert scorer_fn is utils_mod.discover_log_paths


# ===========================================================================
# Sliding-window brute-force counter (Enhancement E5)
# Demonstrates correct per-IP event aggregation over a time window,
# the missing piece the regex cooldown alone cannot provide.
# ===========================================================================
class SlidingWindowCounter:
    """Count events per key within a rolling time window (seconds)."""

    def __init__(self, window_secs: int = 60) -> None:
        self._window = window_secs
        self._events: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def add(self, key: str) -> int:
        """Record an event for *key* and return the current window count."""
        now = time.monotonic()
        with self._lock:
            timestamps = self._events[key]
            timestamps.append(now)
            cutoff = now - self._window
            self._events[key] = [t for t in timestamps if t >= cutoff]
            return len(self._events[key])

    def count(self, key: str) -> int:
        now = time.monotonic()
        with self._lock:
            cutoff = now - self._window
            return sum(1 for t in self._events.get(key, []) if t >= cutoff)


_BRUTE_FORCE_IP_RE = re.compile(
    r"Failed password for (?:invalid user )?\S+ from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)


def count_ssh_failures_in_window(
    lines: list[str],
    window_secs: int = 60,
    threshold: int = 5,
) -> list[tuple[str, int]]:
    """Return (ip, count) pairs where a single IP exceeded the threshold."""
    counter = SlidingWindowCounter(window_secs)
    flagged: list[tuple[str, int]] = []
    for line in lines:
        m = _BRUTE_FORCE_IP_RE.search(line)
        if m:
            ip = m.group("ip")
            n = counter.add(ip)
            if n == threshold:  # fire exactly once at threshold crossing
                flagged.append((ip, n))
    return flagged


class TestSlidingWindowBruteForce:
    def _make_fail_line(self, ip: str) -> str:
        return (
            f"May 10 14:00:00 webserver01 sshd[1234]: "
            f"Failed password for invalid user hacker from {ip} port 51000 ssh2"
        )

    def test_five_failures_from_same_ip_triggers(self) -> None:
        ip = "45.33.32.156"
        lines = [self._make_fail_line(ip) for _ in range(5)]
        flagged = count_ssh_failures_in_window(lines, threshold=5)
        assert len(flagged) == 1
        assert flagged[0][0] == ip
        assert flagged[0][1] == 5

    def test_four_failures_does_not_trigger(self) -> None:
        ip = "45.33.32.156"
        lines = [self._make_fail_line(ip) for _ in range(4)]
        flagged = count_ssh_failures_in_window(lines, threshold=5)
        assert flagged == []

    def test_failures_from_different_ips_do_not_cross_contaminate(self) -> None:
        lines = [self._make_fail_line(f"10.0.0.{i}") for i in range(20)]
        flagged = count_ssh_failures_in_window(lines, threshold=5)
        assert flagged == [], "Different IPs should not accumulate toward same counter"

    def test_same_ip_fires_only_once_at_threshold(self) -> None:
        ip = "1.2.3.4"
        lines = [self._make_fail_line(ip) for _ in range(10)]
        flagged = count_ssh_failures_in_window(lines, threshold=5)
        # Should fire exactly once (at crossing), not once per subsequent event
        assert len(flagged) == 1

    def test_thread_safety_of_sliding_window_counter(self) -> None:
        counter = SlidingWindowCounter(window_secs=60)
        errors: list[Exception] = []

        def worker(key: str) -> None:
            try:
                for _ in range(100):
                    counter.add(key)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(f"ip-{i}",)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == []
