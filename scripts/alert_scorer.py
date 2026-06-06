#!/usr/bin/env python3
"""
SIEM-Lite Alert Scorer
Monitors auth.log / syslog (and RHEL equivalents), applies detection rules,
and emits scored alerts.

Now includes BruteForceDetector: a sliding-window per-IP SSH failure counter
that fires a single consolidated alert when a threshold is crossed, replacing
the old per-line cooldown approach for brute-force detection.
"""

from __future__ import annotations

import argparse
import logging
import re
import threading
import time
from collections import defaultdict
from io import TextIOWrapper
from pathlib import Path
from string import Template
from typing import Any, cast

import yaml

from utils import discover_log_paths


# ---------------------------------------------------------------------------
# inotify shim
# ---------------------------------------------------------------------------
class InotifyWatcher:
    """Thin typed wrapper around inotify.adapters.Inotify."""

    def __init__(self, watch_dir: str) -> None:
        self._instance: Any = None
        self._watch_dir = watch_dir

    def start(self) -> bool:
        try:
            import inotify.adapters as _ia  # type: ignore[import-untyped]
            self._instance = _ia.Inotify()
            self._instance.add_watch(self._watch_dir)
            return True
        except ImportError:
            return False

    def iter_events(self) -> Any:
        if self._instance is None:
            return iter([])
        return self._instance.event_gen(yield_nones=False)


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("siem-lite")

Rule = dict[str, Any]

# ---------------------------------------------------------------------------
# YAML validation schema (cerberus — optional)
# ---------------------------------------------------------------------------
RULE_SCHEMA: dict[str, Any] = {
    "rules": {
        "type": "list",
        "required": True,
        "schema": {
            "type": "dict",
            "allow_unknown": True,
            "schema": {
                "name":     {"type": "string",  "required": True},
                "pattern":  {"type": "string",  "required": True},
                "severity": {
                    "type": "string",
                    "required": True,
                    "allowed": ["low", "medium", "high", "critical"],
                },
                "score":    {"type": "integer", "required": True, "min": 0, "max": 100},
                "template": {"type": "string",  "required": False},
                "cooldown": {"type": "integer", "required": False, "min": 0},
            },
        },
    }
}


def _validate_with_cerberus(data: dict[str, Any]) -> None:
    try:
        from cerberus import Validator  # type: ignore[import-untyped]
    except ImportError:
        logger.warning("cerberus not installed; skipping schema validation")
        if "rules" not in data:
            raise ValueError("Rules file must contain a top-level 'rules' key")
        return

    ValidatorCls: Any = Validator
    v: Any = ValidatorCls(RULE_SCHEMA, require_all=False)
    if not bool(v.validate(data)):
        raise ValueError(f"Rule validation errors: {v.errors}")


def normalise_rule(rule: dict[str, Any]) -> dict[str, Any]:
    if "cooldown_seconds" in rule and "cooldown" not in rule:
        rule["cooldown"] = rule.pop("cooldown_seconds")
    if "alert_message_template" in rule and "template" not in rule:
        rule["template"] = rule.pop("alert_message_template")
        rule["template"] = re.sub(r"\{\{\s*(\w+)\s*\}\}", r"${\1}", rule["template"])
    return rule


def load_rules(path: str) -> list[Rule]:
    raw = Path(path).read_text(encoding="utf-8")
    data: Any = yaml.safe_load(raw)

    if isinstance(data, list):
        wrapped: dict[str, Any] = {"rules": cast(list[Any], data)}
    else:
        wrapped = cast(dict[str, Any], data)

    _validate_with_cerberus(wrapped)
    rules: list[Rule] = [normalise_rule(r) for r in wrapped["rules"]]

    for rule in rules:
        rule["_regex"] = re.compile(str(rule["pattern"]))
        rule.setdefault("cooldown", 60)
        rule.setdefault("template", "[ALERT] Rule '$rule' matched.")

    logger.info("Loaded %d detection rule(s) from %s", len(rules), path)
    return rules


# ---------------------------------------------------------------------------
# Template rendering
# ---------------------------------------------------------------------------
def render_alert(template_str: str, context: dict[str, str]) -> str:
    return Template(template_str).safe_substitute(context)


# ---------------------------------------------------------------------------
# CooldownTracker — thread-safe per-rule suppression
# ---------------------------------------------------------------------------
class CooldownTracker:
    """Tracks per-rule cooldowns and prunes stale entries automatically."""

    def __init__(self, max_age: int = 3600) -> None:
        self._last_fired: dict[str, float] = {}
        self._max_age = max_age
        self._lock = threading.Lock()

    def _prune(self) -> None:
        now = time.monotonic()
        expired = [k for k, t in self._last_fired.items() if now - t > self._max_age]
        for k in expired:
            del self._last_fired[k]
        if expired:
            logger.debug("Pruned %d expired cooldown entries", len(expired))

    def is_cooled_down(self, key: str, cooldown_secs: int) -> bool:
        with self._lock:
            self._prune()
            last = self._last_fired.get(key)
            return last is None or (time.monotonic() - last) >= cooldown_secs

    def mark_fired(self, key: str) -> None:
        with self._lock:
            self._last_fired[key] = time.monotonic()

    def set_fired_at(self, key: str, monotonic_time: float) -> None:
        """Test helper: backdates a fired timestamp."""
        with self._lock:
            self._last_fired[key] = monotonic_time

    def fired_keys(self) -> frozenset[str]:
        """Test helper."""
        with self._lock:
            return frozenset(self._last_fired)


# ---------------------------------------------------------------------------
# BruteForceDetector — sliding-window per-IP SSH failure counter
#
# Tracks failed SSH login attempts per source IP within a rolling time window.
# Fires a single consolidated HIGH alert when an IP crosses the threshold —
# far more accurate than the per-line cooldown for real SSH attack scenarios
# (e.g. Kali → Parrot OS SSH brute-force demonstrations).
# ---------------------------------------------------------------------------
_SSH_FAIL_RE = re.compile(
    r"Failed password for (?:invalid user )?\S+ from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)


class BruteForceDetector:
    """Per-IP sliding-window SSH failure counter.

    Thread-safe: shared across all watcher threads.

    Parameters
    ----------
    threshold   : number of failures within the window that triggers an alert
    window_secs : rolling window size in seconds
    """

    def __init__(self, threshold: int = 5, window_secs: int = 60) -> None:
        self.threshold = threshold
        self.window_secs = window_secs
        self._events: dict[str, list[float]] = defaultdict(list)
        self._alerted: set[str] = set()   # IPs already alerted in this window
        self._lock = threading.Lock()

    def _prune_ip(self, ip: str, now: float) -> None:
        """Remove timestamps outside the window. Caller must hold self._lock."""
        cutoff = now - self.window_secs
        self._events[ip] = [t for t in self._events[ip] if t >= cutoff]
        # Reset alert flag once the window clears
        if ip in self._alerted and not self._events[ip]:
            self._alerted.discard(ip)

    def process(self, line: str) -> tuple[str, int] | None:
        """
        Check one log line for a failed SSH login.

        Returns (ip, count) the moment an IP crosses the threshold for the
        first time in the current window, otherwise returns None.
        """
        m = _SSH_FAIL_RE.search(line)
        if not m:
            return None

        ip = m.group("ip")
        now = time.monotonic()

        with self._lock:
            self._prune_ip(ip, now)
            self._events[ip].append(now)
            count = len(self._events[ip])

            if count >= self.threshold and ip not in self._alerted:
                self._alerted.add(ip)
                return ip, count

        return None

    # -- Test helpers --------------------------------------------------------
    def inject_events(self, ip: str, timestamps: list[float]) -> None:
        """Test helper: directly set timestamps for an IP."""
        with self._lock:
            self._events[ip] = list(timestamps)

    def event_count(self, ip: str) -> int:
        """Test helper: current in-window count for an IP."""
        now = time.monotonic()
        with self._lock:
            self._prune_ip(ip, now)
            return len(self._events[ip])


# ---------------------------------------------------------------------------
# Core: match a log line against all rules + brute-force detector
# ---------------------------------------------------------------------------
def process_line(
    line: str,
    rules: list[Rule],
    cooldowns: CooldownTracker,
    brute: BruteForceDetector | None = None,
) -> None:
    # -- Sliding-window brute-force check (runs before per-rule matching) --
    if brute is not None:
        result = brute.process(line)
        if result is not None:
            ip, count = result
            logger.warning(
                "BRUTE-FORCE  score=%-3d  severity=HIGH      rule=SSH brute force  "
                "msg=[ALERT] %d failed SSH logins from %s within %ds window.",
                10, count, ip, brute.window_secs,
            )

    # -- Per-rule regex matching --
    for rule in rules:
        regex: re.Pattern[str] = rule["_regex"]
        m = regex.search(line)
        if not m:
            continue

        key: str = str(rule["name"])
        cooldown_secs: int = int(rule["cooldown"])

        if not cooldowns.is_cooled_down(key, cooldown_secs):
            logger.debug("Rule '%s' suppressed (cooldown active)", key)
            continue

        cooldowns.mark_fired(key)

        context: dict[str, str] = {
            **{k: str(v) for k, v in m.groupdict().items()},
            "line": line,
            "rule": key,
        }
        message = render_alert(str(rule["template"]), context)

        logger.warning(
            "ALERT  score=%-3d  severity=%-8s  rule=%s  msg=%s",
            int(rule["score"]),
            str(rule["severity"]).upper(),
            key,
            message,
        )


# ---------------------------------------------------------------------------
# inotify-based tailing with polling fallback
# ---------------------------------------------------------------------------
def tail_with_inotify(
    log_path: str,
    rules: list[Rule],
    cooldowns: CooldownTracker,
    brute: BruteForceDetector | None = None,
) -> None:
    path = Path(log_path)
    fh: TextIOWrapper = path.open("r", errors="replace")
    fh.seek(0, 2)

    watcher = InotifyWatcher(str(path.parent))
    started: bool = watcher.start()

    if not started:
        logger.warning(
            "inotify not available — falling back to 1-second polling for %s", log_path
        )
        try:
            _tail_with_sleep(fh, rules, cooldowns, brute)
        finally:
            fh.close()
        return

    logger.info("inotify watching %s", log_path)
    try:
        for raw_event in watcher.iter_events():
            event: Any = raw_event
            type_names: list[str] = list(event[1])
            filename: str = str(event[3])

            if filename != path.name:
                continue
            if not any(e in type_names for e in ("IN_MODIFY", "IN_MOVED_TO", "IN_CLOSE_WRITE")):
                continue
            if "IN_MOVED_TO" in type_names:
                fh.close()
                fh = path.open("r", errors="replace")
                logger.info("Log rotated, re-opened %s", log_path)

            for line in fh:
                process_line(line.rstrip(), rules, cooldowns, brute)
    finally:
        fh.close()


def _tail_with_sleep(
    fh: TextIOWrapper,
    rules: list[Rule],
    cooldowns: CooldownTracker,
    brute: BruteForceDetector | None = None,
) -> None:
    while True:
        line: str = fh.readline()
        if line:
            process_line(line.rstrip(), rules, cooldowns, brute)
        else:
            time.sleep(1)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
DEFAULT_RULES_PATH = "rules/detection-rules.yml"


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="SIEM-Lite alert scorer — tails log files and emits scored alerts.",
    )
    p.add_argument("--rules", default=DEFAULT_RULES_PATH, metavar="PATH",
                   help=f"Path to detection-rules YAML (default: {DEFAULT_RULES_PATH})")
    p.add_argument("--log", dest="logs", action="append", metavar="PATH",
                   help="Log file to watch (repeatable; auto-detected if omitted)")
    p.add_argument("--brute-threshold", type=int, default=5, metavar="N",
                   help="Failed SSH logins from same IP to trigger brute-force alert (default: 5)")
    p.add_argument("--brute-window", type=int, default=60, metavar="SECS",
                   help="Sliding window in seconds for brute-force counting (default: 60)")
    p.add_argument("--debug", action="store_true", help="Enable DEBUG-level logging")
    return p


def main(argv: list[str] | None = None) -> None:
    parser = build_arg_parser()
    args: argparse.Namespace = parser.parse_args(argv)

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    rules = load_rules(str(args.rules))
    cooldowns = CooldownTracker()
    brute = BruteForceDetector(
        threshold=args.brute_threshold,
        window_secs=args.brute_window,
    )
    logger.info(
        "Brute-force detector: threshold=%d failures / %ds window",
        args.brute_threshold, args.brute_window,
    )

    raw_logs: list[str] | None = args.logs
    log_paths: list[str] = raw_logs if raw_logs is not None else discover_log_paths()

    threads: list[threading.Thread] = []
    for log_path in log_paths:
        lp: str = log_path
        t = threading.Thread(
            target=tail_with_inotify,
            args=(lp, rules, cooldowns, brute),
            daemon=True,
            name=f"watcher-{Path(lp).name}",
        )
        t.start()
        threads.append(t)

    if not threads:
        logger.error("No log files found. Exiting.")
        return

    logger.info("SIEM-Lite alert scorer running. Press Ctrl-C to stop.")
    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        logger.info("Shutting down.")


if __name__ == "__main__":
    main()