#!/usr/bin/env python3
"""
SIEM-Lite Alert Scorer
Monitors auth.log / syslog (and RHEL equivalents), applies detection rules,
and emits scored alerts.

Fixes applied:
  1. Cooldown dict pruning        — prevents unbounded memory growth
  2. YAML config validation       — catches malformed rules at load time
  3. string.Template rendering    — replaces fragile str.replace for alert messages
  4. inotify-based tailing        — replaces time.sleep polling on Linux
  5. logging library              — replaces print() with structured log output
  6. Cross-distro log paths       — detects Debian AND RHEL/Fedora log locations
  7. Rules YAML schema fix        — handles both bare-list and {rules: [...]} formats
  8. Field name normalisation     — maps cooldown_seconds / alert_message_template
"""

from __future__ import annotations

import logging
import re
import time
from io import TextIOWrapper
from pathlib import Path
from string import Template
from typing import Any, cast

import yaml


# ---------------------------------------------------------------------------
# inotify shim — fully contains the untyped library behind a typed facade.
# ---------------------------------------------------------------------------
class _InotifyWatcher:
    """Thin typed wrapper around inotify.adapters.Inotify."""

    def __init__(self, watch_dir: str) -> None:
        self._instance: Any = None
        self._watch_dir = watch_dir

    def start(self) -> bool:
        """Return True if inotify was successfully initialised."""
        try:
            import inotify.adapters as _ia  # type: ignore[import-untyped]
            self._instance = _ia.Inotify()
            self._instance.add_watch(self._watch_dir)
            return True
        except ImportError:
            return False

    def iter_events(self) -> Any:
        """Return the raw inotify generator for use in a for-loop."""
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
# YAML validation schema (cerberus — optional dep)
# ---------------------------------------------------------------------------
RULE_SCHEMA: dict[str, Any] = {
    "rules": {
        "type": "list",
        "required": True,
        "schema": {
            "type": "dict",
            "schema": {
                "name":     {"type": "string",  "required": True},
                "pattern":  {"type": "string",  "required": True},
                "severity": {
                    "type": "string",
                    "required": True,
                    "allowed": ["low", "medium", "high", "critical"],
                },
                "score":    {"type": "integer", "required": True, "min": 0, "max": 100},
                "template": {"type": "string",  "required": True},
                "cooldown": {"type": "integer", "required": False, "min": 0},
            },
        },
    }
}


def _validate_with_cerberus(data: dict[str, Any]) -> None:
    """Run cerberus schema validation if cerberus is installed."""
    try:
        from cerberus import Validator  # type: ignore[import-untyped]
    except ImportError:
        logger.warning("cerberus not installed; skipping schema validation")
        if "rules" not in data:
            raise ValueError("Rules file must contain a top-level 'rules' key")
        return

    ValidatorCls: Any = Validator  # cast: no stubs, Pylance can't see constructor args
    v: Any = ValidatorCls(RULE_SCHEMA, require_all=False)
    valid: bool = bool(v.validate(data))
    if not valid:
        errors: str = str(v.errors)
        raise ValueError(f"Rule validation errors: {errors}")


def _normalise_rule(rule: dict[str, Any]) -> dict[str, Any]:
    """
    Fix 7 & 8: Map old field names to the canonical names the script uses.

    detection-rules.yml previously used:
      cooldown_seconds        -> cooldown
      alert_message_template  -> template
    """
    if "cooldown_seconds" in rule and "cooldown" not in rule:
        rule["cooldown"] = rule.pop("cooldown_seconds")
    if "alert_message_template" in rule and "template" not in rule:
        rule["template"] = rule.pop("alert_message_template")
        # Convert Jinja-style {{ var }} to $var for string.Template
        rule["template"] = re.sub(r"\{\{\s*(\w+)\s*\}\}", r"${\1}", rule["template"])
    return rule


def load_rules(path: str) -> list[Rule]:
    """Load and validate detection rules from a YAML file.

    Handles both formats:
      - bare list:         [{"name": ...}, ...]
      - wrapped dict:      {"rules": [{"name": ...}, ...]}
    """
    raw = Path(path).read_text(encoding="utf-8")
    data: Any = yaml.safe_load(raw)

    # Fix 7: normalise bare list into the expected dict shape
    if isinstance(data, list):
        wrapped: dict[str, Any] = {"rules": cast(list[Any], data)}
    else:
        wrapped = cast(dict[str, Any], data)
    normalised: dict[str, Any] = wrapped

    _validate_with_cerberus(normalised)

    rules: list[Rule] = [_normalise_rule(r) for r in normalised["rules"]]

    # Pre-compile regexes and apply defaults
    for rule in rules:
        rule["_regex"] = re.compile(str(rule["pattern"]))
        rule.setdefault("cooldown", 60)
        rule.setdefault("template", "[ALERT] Rule '$rule' matched.")

    logger.info("Loaded %d detection rule(s) from %s", len(rules), path)
    return rules


# ---------------------------------------------------------------------------
# Fix 3: Template-based alert rendering (string.Template / $var syntax)
# ---------------------------------------------------------------------------
def render_alert(template_str: str, context: dict[str, str]) -> str:
    """Render an alert message using string.Template ($variable syntax)."""
    return Template(template_str).safe_substitute(context)


# ---------------------------------------------------------------------------
# Fix 1: Cooldown dict with pruning
# ---------------------------------------------------------------------------
class CooldownTracker:
    """Tracks per-rule cooldowns and prunes stale entries automatically."""

    def __init__(self, max_age: int = 3600) -> None:
        self._last_fired: dict[str, float] = {}
        self._max_age = max_age

    def _prune(self) -> None:
        now = time.monotonic()
        expired = [k for k, t in self._last_fired.items() if now - t > self._max_age]
        for k in expired:
            del self._last_fired[k]
        if expired:
            logger.debug("Pruned %d expired cooldown entries", len(expired))

    def is_cooled_down(self, key: str, cooldown_secs: int) -> bool:
        self._prune()
        last = self._last_fired.get(key)
        return last is None or (time.monotonic() - last) >= cooldown_secs

    def mark_fired(self, key: str) -> None:
        self._last_fired[key] = time.monotonic()


# ---------------------------------------------------------------------------
# Fix 4: inotify-based real-time log tailing with sleep fallback
# ---------------------------------------------------------------------------
def tail_with_inotify(log_path: str, rules: list[Rule], cooldowns: CooldownTracker) -> None:
    """Watch a log file with inotify (Linux) or poll (other platforms)."""
    path = Path(log_path)
    fh: TextIOWrapper = path.open("r", errors="replace")
    fh.seek(0, 2)  # seek to end — process only new lines

    watcher = _InotifyWatcher(str(path.parent))
    started: bool = watcher.start()

    if not started:
        logger.warning(
            "inotify not available (non-Linux or package missing). "
            "Falling back to 1-second polling."
        )
        try:
            _tail_with_sleep(fh, rules, cooldowns)
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
            if "IN_MODIFY" not in type_names and "IN_MOVED_TO" not in type_names:
                continue

            if "IN_MOVED_TO" in type_names:
                fh.close()
                fh = path.open("r", errors="replace")
                logger.info("Log rotated, re-opened %s", log_path)

            for line in fh:
                process_line(line.rstrip(), rules, cooldowns)
    finally:
        fh.close()


def _tail_with_sleep(fh: TextIOWrapper, rules: list[Rule], cooldowns: CooldownTracker) -> None:
    """Fallback polling loop used when inotify is unavailable."""
    while True:
        line: str = fh.readline()
        if line:
            process_line(line.rstrip(), rules, cooldowns)
        else:
            time.sleep(1)


# ---------------------------------------------------------------------------
# Core: match a log line against all rules and emit alerts
# ---------------------------------------------------------------------------
def process_line(line: str, rules: list[Rule], cooldowns: CooldownTracker) -> None:
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
# Fix 6: Cross-distro log path detection
# ---------------------------------------------------------------------------
def _discover_log_paths() -> list[str]:
    """
    Return existing log paths for the current distro.

    Debian/Ubuntu:  /var/log/auth.log, /var/log/syslog
    RHEL/CentOS:    /var/log/secure,   /var/log/messages
    Fedora/Arch:    may only have systemd journal — warn the user.
    """
    candidates = [
        "/var/log/auth.log",   # Debian / Ubuntu
        "/var/log/secure",     # RHEL / CentOS / Fedora
        "/var/log/syslog",     # Debian / Ubuntu
        "/var/log/messages",   # RHEL / CentOS / Fedora
    ]
    found = [p for p in candidates if Path(p).exists()]
    if not found:
        logger.warning(
            "No standard log files found. Your distro may use systemd-journal only. "
            "Try: journalctl -f | python3 alert_scorer.py --stdin  (not yet implemented)"
        )
    return found


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
DEFAULT_RULES_PATH = "rules/detection-rules.yml"


def main() -> None:
    import threading

    rules = load_rules(DEFAULT_RULES_PATH)
    cooldowns = CooldownTracker()

    log_paths = _discover_log_paths()

    threads: list[threading.Thread] = []
    for log_path in log_paths:
        t = threading.Thread(
            target=tail_with_inotify,
            args=(log_path, rules, cooldowns),
            daemon=True,
            name=f"watcher-{Path(log_path).name}",
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