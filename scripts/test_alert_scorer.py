"""
Tests for alert_scorer.py

Run with:  python -m pytest scripts/test_alert_scorer.py -v
"""
from __future__ import annotations

import logging
import re
import textwrap
import threading
import time
from logging import LogRecord
from pathlib import Path
from typing import TYPE_CHECKING, Any

# ---------------------------------------------------------------------------
# pytest types: imported only during type-checking so the file works even
# when Pylance's selected interpreter does not have pytest installed.
# At runtime pytest injects caplog / monkeypatch as fixture objects; the
# annotations are only needed for static analysis.
# ---------------------------------------------------------------------------
if TYPE_CHECKING:
    from pytest import LogCaptureFixture, MonkeyPatch

import pytest

import sys
sys.path.insert(0, str(Path(__file__).parent))

from alert_scorer import (
    CooldownTracker,
    InotifyWatcher,
    build_arg_parser,
    DEFAULT_RULES_PATH,
    load_rules,
    normalise_rule,
    process_line,
    render_alert,
)


# ===========================================================================
# render_alert
# ===========================================================================
class TestRenderAlert:
    def test_substitutes_named_variable(self) -> None:
        assert render_alert("[ALERT] from $ip", {"ip": "1.2.3.4"}) == "[ALERT] from 1.2.3.4"

    def test_substitutes_multiple_variables(self) -> None:
        msg = render_alert("user=$username ip=$ip", {"username": "bob", "ip": "10.0.0.1"})
        assert msg == "user=bob ip=10.0.0.1"

    def test_missing_variable_left_as_placeholder(self) -> None:
        assert "$username" in render_alert("user=$username", {})

    def test_braced_variable_syntax(self) -> None:
        assert render_alert("${rule} fired", {"rule": "SSH"}) == "SSH fired"

    def test_empty_context(self) -> None:
        assert render_alert("no vars here", {}) == "no vars here"


# ===========================================================================
# normalise_rule
# ===========================================================================
class TestNormaliseRule:
    def test_maps_cooldown_seconds(self) -> None:
        rule: dict[str, Any] = {"cooldown_seconds": 120, "name": "r"}
        out = normalise_rule(rule)
        assert out["cooldown"] == 120
        assert "cooldown_seconds" not in out

    def test_maps_alert_message_template(self) -> None:
        rule: dict[str, Any] = {"alert_message_template": "hit {{ ip }}", "name": "r"}
        out = normalise_rule(rule)
        assert "template" in out
        assert "alert_message_template" not in out
        assert "${ip}" in out["template"] or "$ip" in out["template"]

    def test_canonical_keys_unchanged(self) -> None:
        rule: dict[str, Any] = {"cooldown": 30, "template": "msg $ip", "name": "r"}
        out = normalise_rule(rule)
        assert out["cooldown"] == 30
        assert out["template"] == "msg $ip"

    def test_no_duplicate_overwrite(self) -> None:
        rule: dict[str, Any] = {"cooldown": 10, "cooldown_seconds": 99, "name": "r"}
        assert normalise_rule(rule)["cooldown"] == 10


# ===========================================================================
# load_rules
# ===========================================================================
class TestLoadRules:
    def _write(self, tmp_path: Path, content: str) -> Path:
        p = tmp_path / "rules.yml"
        p.write_text(textwrap.dedent(content))
        return p

    def test_loads_wrapped_format(self, tmp_path: Path) -> None:
        p = self._write(tmp_path, """
            rules:
              - name: test-rule
                pattern: 'FAIL'
                severity: low
                score: 1
        """)
        rules = load_rules(str(p))
        assert len(rules) == 1
        assert rules[0]["name"] == "test-rule"

    def test_loads_bare_list_format(self, tmp_path: Path) -> None:
        p = self._write(tmp_path, """
            - name: bare-rule
              pattern: 'ERROR'
              severity: high
              score: 5
        """)
        rules = load_rules(str(p))
        assert len(rules) == 1
        assert rules[0]["name"] == "bare-rule"

    def test_compiles_regex(self, tmp_path: Path) -> None:
        p = self._write(tmp_path, r"""
            rules:
              - name: r
                pattern: '(?P<ip>\d+\.\d+\.\d+\.\d+)'
                severity: low
                score: 1
        """)
        assert isinstance(load_rules(str(p))[0]["_regex"], re.Pattern)

    def test_default_cooldown_applied(self, tmp_path: Path) -> None:
        p = self._write(tmp_path, """
            rules:
              - name: r
                pattern: 'x'
                severity: low
                score: 1
        """)
        assert load_rules(str(p))[0]["cooldown"] == 60

    def test_invalid_regex_raises(self, tmp_path: Path) -> None:
        p = self._write(tmp_path, """
            rules:
              - name: r
                pattern: '(?P<bad'
                severity: low
                score: 1
        """)
        with pytest.raises(re.error):
            load_rules(str(p))

    def test_multiple_rules_loaded(self, tmp_path: Path) -> None:
        p = self._write(tmp_path, """
            rules:
              - name: r1
                pattern: 'A'
                severity: low
                score: 1
              - name: r2
                pattern: 'B'
                severity: high
                score: 9
        """)
        rules = load_rules(str(p))
        assert len(rules) == 2
        assert {r["name"] for r in rules} == {"r1", "r2"}


# ===========================================================================
# CooldownTracker
# ===========================================================================
class TestCooldownTracker:
    def test_first_fire_is_cooled_down(self) -> None:
        assert CooldownTracker().is_cooled_down("rule-a", 60) is True

    def test_not_cooled_down_immediately_after_fire(self) -> None:
        ct = CooldownTracker()
        ct.mark_fired("rule-a")
        assert ct.is_cooled_down("rule-a", 60) is False

    def test_cooled_down_after_cooldown_expires(self) -> None:
        ct = CooldownTracker()
        ct.mark_fired("rule-a")
        ct.set_fired_at("rule-a", time.monotonic() - 61)
        assert ct.is_cooled_down("rule-a", 60) is True

    def test_independent_keys(self) -> None:
        ct = CooldownTracker()
        ct.mark_fired("rule-a")
        assert ct.is_cooled_down("rule-b", 60) is True

    def test_prune_removes_old_entries(self) -> None:
        ct = CooldownTracker(max_age=1)
        ct.mark_fired("rule-old")
        ct.set_fired_at("rule-old", time.monotonic() - 10)
        ct.is_cooled_down("trigger-prune", 0)   # triggers _prune internally
        assert "rule-old" not in ct.fired_keys()

    def test_thread_safe_concurrent_mark_fired(self) -> None:
        ct = CooldownTracker()
        errors: list[Exception] = []

        def worker(rule_name: str) -> None:
            try:
                for _ in range(200):
                    ct.mark_fired(rule_name)
                    ct.is_cooled_down(rule_name, 0)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(f"rule-{i}",)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == [], f"Thread errors: {errors}"


# ===========================================================================
# process_line
# ===========================================================================
class TestProcessLine:
    def _make_rule(self, pattern: str, name: str = "test", cooldown: int = 0) -> dict[str, Any]:
        return {
            "name": name,
            "pattern": pattern,
            "_regex": re.compile(pattern),
            "severity": "high",
            "score": 5,
            "cooldown": cooldown,
            "template": "[ALERT] matched $line",
        }

    def _alert_messages(self, records: list[LogRecord]) -> list[str]:
        return [r.getMessage() for r in records if "ALERT" in r.getMessage()]

    def test_matching_line_logs_warning(self, caplog: "LogCaptureFixture") -> None:
        ct = CooldownTracker()
        with caplog.at_level(logging.WARNING, logger="siem-lite"):
            process_line("Auth FAIL event", [self._make_rule(r"FAIL")], ct)
        records: list[LogRecord] = list(caplog.records)
        assert any("ALERT" in r.getMessage() for r in records)

    def test_non_matching_line_no_alert(self, caplog: "LogCaptureFixture") -> None:
        ct = CooldownTracker()
        with caplog.at_level(logging.WARNING, logger="siem-lite"):
            process_line("totally unrelated", [self._make_rule(r"SPECIFIC_XYZ")], ct)
        records: list[LogRecord] = list(caplog.records)
        assert not any("ALERT" in r.getMessage() for r in records)

    def test_cooldown_suppresses_second_alert(self, caplog: "LogCaptureFixture") -> None:
        rule = self._make_rule(r"FAIL", cooldown=3600)
        ct = CooldownTracker()
        with caplog.at_level(logging.WARNING, logger="siem-lite"):
            process_line("FAIL line 1", [rule], ct)
            process_line("FAIL line 2", [rule], ct)
        records: list[LogRecord] = list(caplog.records)
        assert len(self._alert_messages(records)) == 1

    def test_named_capture_group_in_template(self, caplog: "LogCaptureFixture") -> None:
        rule = self._make_rule(r"from (?P<ip>\d+\.\d+\.\d+\.\d+)")
        rule["template"] = "[ALERT] ip=$ip"
        ct = CooldownTracker()
        with caplog.at_level(logging.WARNING, logger="siem-lite"):
            process_line("Login failed from 1.2.3.4", [rule], ct)
        records: list[LogRecord] = list(caplog.records)
        assert any("1.2.3.4" in r.getMessage() for r in records)

    def test_multiple_rules_all_evaluated(self, caplog: "LogCaptureFixture") -> None:
        rules = [
            self._make_rule(r"FAIL", name="rule-fail"),
            self._make_rule(r"ERROR", name="rule-error"),
        ]
        ct = CooldownTracker()
        with caplog.at_level(logging.WARNING, logger="siem-lite"):
            process_line("FAIL and ERROR", rules, ct)
        records: list[LogRecord] = list(caplog.records)
        messages: str = " ".join(r.getMessage() for r in records)
        assert "rule-fail" in messages and "rule-error" in messages

    def test_zero_cooldown_fires_every_match(self, caplog: "LogCaptureFixture") -> None:
        rule = self._make_rule(r"HIT", cooldown=0)
        ct = CooldownTracker()
        with caplog.at_level(logging.WARNING, logger="siem-lite"):
            process_line("HIT 1", [rule], ct)
            process_line("HIT 2", [rule], ct)
        records: list[LogRecord] = list(caplog.records)
        assert len(self._alert_messages(records)) == 2


# ===========================================================================
# CLI argument parsing
# ===========================================================================
class TestCLI:
    def test_default_rules_path(self) -> None:
        assert build_arg_parser().parse_args([]).rules == DEFAULT_RULES_PATH

    def test_custom_rules_path(self) -> None:
        assert build_arg_parser().parse_args(["--rules", "/tmp/r.yml"]).rules == "/tmp/r.yml"

    def test_multiple_log_paths(self) -> None:
        args = build_arg_parser().parse_args(["--log", "/var/log/a", "--log", "/var/log/b"])
        assert args.logs == ["/var/log/a", "/var/log/b"]

    def test_debug_flag(self) -> None:
        assert build_arg_parser().parse_args(["--debug"]).debug is True

    def test_no_debug_by_default(self) -> None:
        assert build_arg_parser().parse_args([]).debug is False


# ===========================================================================
# InotifyWatcher
# ===========================================================================
class TestInotifyWatcher:
    def test_returns_false_when_import_fails(self, monkeypatch: "MonkeyPatch") -> None:
        import builtins
        real_import = builtins.__import__

        def mock_import(
            name: str,
            globals: dict[str, Any] | None = None,
            locals: dict[str, Any] | None = None,
            fromlist: list[str] | None = None,
            level: int = 0,
        ) -> Any:
            if name.startswith("inotify"):
                raise ImportError("mocked")
            return real_import(name, globals or {}, locals or {}, fromlist or [], level)

        monkeypatch.setattr(builtins, "__import__", mock_import)
        assert InotifyWatcher("/tmp").start() is False

    def test_iter_events_before_start_returns_empty(self) -> None:
        assert list(InotifyWatcher("/tmp").iter_events()) == []