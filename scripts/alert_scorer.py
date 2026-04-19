#!/usr/bin/env python3
"""
SIEM-Lite Alert Scorer
Monitors auth.log and syslog, applies detection rules, and emits scored alerts.

Changes from senior feedback:
  1. Cooldown dict pruning       — prevents unbounded memory growth
  2. YAML config validation      — catches malformed rules at load time
  3. str.format_map templating   — replaces fragile str.replace for alert messages
  4. inotify-based tailing       — replaces time.sleep polling for real-time detection
  5. logging library             — replaces print() with structured log output
"""

from __future__ import annotations

import logging
import re
import time
from io import TextIOWrapper
from pathlib import Path
from string import Template
from typing import Any

import yaml


# ---------------------------------------------------------------------------
# inotify shim — fully contains the untyped library behind a typed facade.
#
# Because inotify has no PEP 561 stubs, every attribute access on it is
# typed as Unknown by Pylance.  Wrapping it here means the Unknown leakage
# is confined to this one class; everything else in the file sees only the
# clean typed interface below.
# ---------------------------------------------------------------------------
class _InotifyWatcher:
    """Thin typed wrapper around inotify.adapters.Inotify."""

    available: bool = False  # lowercase → not treated as a module constant

    def __init__(self, watch_dir: str) -> None:
        self._instance: Any = None
        self._watch_dir = watch_dir

    def start(self) -> bool:
        """Return True if inotify was successfully initialised."""
        try:
            import inotify.adapters as _ia  # type: ignore[import-untyped]
            self._instance = _ia.Inotify()  # type: ignore[misc]
            self._instance.add_watch(self._watch_dir)  # type: ignore[union-attr]
            return True
        except ImportError:
            return False

    def events(self) -> "list[tuple[str, list[str], str]]":
        """Yield (_, type_names, filename) tuples, typed for Pylance."""
        if self._instance is None:
            return []
        raw: Any = self._instance.event_gen(yield_nones=False)
        result: list[tuple[str, list[str], str]] = []
        for item in raw:
            _hdr: Any
            type_names_raw: Any
            _path_raw: Any
            fname_raw: Any
            _hdr, type_names_raw, _path_raw, fname_raw = item
            result.append(("", list(type_names_raw), str(fname_raw)))
        return result

    def iter_events(self) -> "Any":
        """Return the raw generator for use in a for-loop."""
        if self._instance is None:
            return iter([])
        raw: Any = self._instance.event_gen(yield_nones=False)
        return raw

# ---------------------------------------------------------------------------
# Fix 5: Use the logging library instead of print()
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("siem-lite")

# Type alias used throughout — a parsed YAML rule dict
Rule = dict[str, Any]

# ---------------------------------------------------------------------------
# Fix 2: YAML validation schema (cerberus)
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
    """Run cerberus schema validation if cerberus is installed.

    All cerberus member access is confined here so Pylance's Unknown
    inference cannot escape into the rest of the module.
    Any attribute access on the Validator instance is cast to Any explicitly.
    """
    try:
        from cerberus import Validator  # type: ignore[import-untyped]
    except ImportError:
        logger.warning("cerberus not installed; skipping schema validation")
        if "rules" not in data:
            raise ValueError("Rules file must contain a top-level 'rules' key")
        return

    # Cast to Any once — all subsequent accesses are then typed as Any,
    # which Pylance accepts without reportUnknownVariableType/MemberType.
    v: Any = Validator(RULE_SCHEMA, require_all=False)  # type: ignore[misc]
    valid: bool = bool(v.validate(data))  # type: ignore[union-attr]  # no stubs
    if not valid:
        errors: str = str(v.errors)  # type: ignore[union-attr]  # stringify to known type
        raise ValueError(f"Rule validation errors: {errors}")


def load_rules(path: str) -> list[Rule]:
    """Load and validate detection rules from a YAML file.

    Fix 2: Validates schema on load so malformed configs fail fast with a
    clear error rather than causing a confusing runtime crash later.
    """
    raw = Path(path).read_text()
    data: dict[str, Any] = yaml.safe_load(raw)

    _validate_with_cerberus(data)  # no-op if cerberus not installed

    rules: list[Rule] = list(data["rules"])

    # Pre-compile regexes so we don't recompile on every log line
    for rule in rules:
        rule["_regex"] = re.compile(str(rule["pattern"]))
        rule.setdefault("cooldown", 60)

    logger.info("Loaded %d detection rule(s) from %s", len(rules), path)
    return rules


# ---------------------------------------------------------------------------
# Fix 3: Template-based alert rendering
# ---------------------------------------------------------------------------

def render_alert(template_str: str, context: dict[str, str]) -> str:
    """Render an alert message safely using string.Template.

    Fix 3: Replaces chained str.replace() calls with Python's Template engine.
    Template uses $variable syntax; unknown keys are left as-is via safe_substitute.

    Example template in detection-rules.yml:
        template: "Brute-force detected from $src_ip — $count failed attempts"
    """
    return Template(template_str).safe_substitute(context)


# ---------------------------------------------------------------------------
# Fix 1: Cooldown dict with pruning
# ---------------------------------------------------------------------------

class CooldownTracker:
    """Tracks per-rule cooldowns and prunes stale entries automatically.

    Fix 1: The original dict grows forever because expired entries are never
    removed. This class prunes entries older than max_age seconds on every
    check, keeping memory bounded.
    """

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
        """Return True if enough time has passed since the last firing."""
        self._prune()
        last = self._last_fired.get(key)
        return last is None or (time.monotonic() - last) >= cooldown_secs

    def mark_fired(self, key: str) -> None:
        self._last_fired[key] = time.monotonic()


# ---------------------------------------------------------------------------
# Fix 4: inotify-based real-time log tailing
# ---------------------------------------------------------------------------

def tail_with_inotify(log_path: str, rules: list[Rule], cooldowns: CooldownTracker) -> None:
    """Watch a log file with inotify and process new lines as they arrive.

    Fix 4: Replaces the time.sleep(1) polling loop with Linux inotify events.
    The process wakes up only when the kernel signals the file changed,
    giving sub-millisecond latency instead of up to 1-second delay.
    Falls back to the sleep-based approach on non-Linux platforms.

    All inotify interaction is delegated to _InotifyWatcher so that
    Pylance Unknown-type inference stays contained in that class.
    """
    path = Path(log_path)
    fh: TextIOWrapper = path.open("r", errors="replace")
    fh.seek(0, 2)  # seek to end -- process only new lines

    watcher = _InotifyWatcher(str(path.parent))
    started: bool = watcher.start()

    if not started:
        logger.warning(
            "inotify package not available (non-Linux?). "
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

        # Build template context from named groups + defaults
        context: dict[str, str] = {
            **{k: str(v) for k, v in m.groupdict().items()},
            "line": line,
            "rule": key,
        }
        message = render_alert(str(rule["template"]), context)

        # Fix 5: structured log output instead of bare print()
        logger.warning(
            "ALERT  score=%-3d  severity=%-8s  rule=%s  msg=%s",
            int(rule["score"]),
            str(rule["severity"]).upper(),
            key,
            message,
        )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

DEFAULT_RULES_PATH = "rules/detection-rules.yml"
DEFAULT_LOG_PATHS: list[str] = ["/var/log/auth.log", "/var/log/syslog"]


def main() -> None:
    import threading

    rules = load_rules(DEFAULT_RULES_PATH)
    cooldowns = CooldownTracker()

    threads: list[threading.Thread] = []
    for log_path in DEFAULT_LOG_PATHS:
        if not Path(log_path).exists():
            logger.warning("Log file not found, skipping: %s", log_path)
            continue
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