#!/usr/bin/env python3
"""
SIEM-Lite Unified Scorer
========================
Fuses the rule-based alert engine (alert_scorer) and the ML engine
(ml_scorer) into a single process watching the same log file(s).

Every log line is evaluated by:
  1. BruteForceDetector — sliding-window per-IP SSH failure counter
  2. Regex rule engine  — pattern matching with cooldown suppression
  3. ML classifier      — Random Forest + Isolation Forest (if models exist)

A fused composite risk score is emitted per alert. ML degrades gracefully:
if models are not yet trained, the scorer falls back to rule-only mode.

Usage:
    python scripts/unified_scorer.py
    python scripts/unified_scorer.py --push-to-loki http://localhost:3100
    python scripts/unified_scorer.py --ml-threshold 10 --brute-threshold 5 --brute-window 60
    python scripts/unified_scorer.py --log /var/log/auth.log --debug
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import threading
import time
from io import TextIOWrapper
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "ml"))
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from alert_scorer import (
    BruteForceDetector,
    CooldownTracker,
    load_rules,
    process_line,
    Rule,
)
from utils import discover_log_paths

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("siem-unified")

MODELS_DIR = PROJECT_ROOT / "ml" / "models"
DEFAULT_RULES_PATH = str(PROJECT_ROOT / "rules" / "detection-rules.yml")


# ---------------------------------------------------------------------------
# Optional ML scorer — graceful degradation if models don't exist
# ---------------------------------------------------------------------------
def _try_load_ml_scorer() -> Any | None:
    """Return an MLScorer instance or None if models are not available."""
    try:
        from ml_scorer import MLScorer
        scorer = MLScorer(MODELS_DIR)
        logger.info("ML models loaded — running in rule + ML mode.")
        return scorer
    except FileNotFoundError:
        logger.warning(
            "ML models not found at %s — running in rule-only mode.\n"
            "  To enable ML: run  make train  (or python ml/train_and_evaluate.py)",
            MODELS_DIR,
        )
        return None
    except Exception as exc:
        logger.warning("ML model load failed (%s) — rule-only mode.", exc)
        return None


# ---------------------------------------------------------------------------
# Loki push
# ---------------------------------------------------------------------------
def _push_to_loki(loki_url: str, payload: dict[str, Any]) -> None:
    try:
        import urllib.request
        req = urllib.request.Request(
            f"{loki_url}/loki/api/v1/push",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=5)
    except Exception as exc:
        logger.debug("Loki push failed: %s", exc)


def _severity_label(score: float) -> str:
    if score >= 70:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 30:
        return "medium"
    if score >= 10:
        return "low"
    return "info"


# ---------------------------------------------------------------------------
# Core: process one line through both engines
# ---------------------------------------------------------------------------
def process_unified(
    line: str,
    rules: list[Rule],
    cooldowns: CooldownTracker,
    brute: BruteForceDetector,
    ml_scorer: Any | None,
    ml_threshold: float,
    loki_url: str | None,
) -> None:
    """Run one log line through brute-force, rule engine, and ML (if available)."""

    if not line:
        return

    # -- 1. Brute-force sliding-window check --
    bf_result = brute.process(line)
    if bf_result is not None:
        ip, count = bf_result
        logger.warning(
            "BRUTE-FORCE  score=10   severity=HIGH      "
            "rule=SSH brute force  msg=[ALERT] %d SSH failures from %s in %ds",
            count, ip, brute.window_secs,
        )
        if loki_url:
            _push_to_loki(loki_url, {
                "streams": [{
                    "stream": {"job": "siem_unified", "severity": "high", "type": "brute_force"},
                    "values": [[str(int(time.time() * 1e9)), json.dumps({
                        "event": "brute_force", "ip": ip, "count": count,
                        "window_secs": brute.window_secs, "log_line": line,
                    })]],
                }]
            })

    # -- 2. Regex rule engine --
    process_line(line, rules, cooldowns, brute=None)  # brute already handled above

    # -- 3. ML inference --
    if ml_scorer is None:
        return

    try:
        result: dict[str, Any] = ml_scorer.predict(line)
    except Exception as exc:
        logger.debug("ML inference error: %s", exc)
        return

    composite: float = result["composite_score"]
    if composite < ml_threshold:
        return

    logger.warning(
        "ML-ALERT  composite=%-5.1f  severity=%-8s  rf=%-22s (conf=%.2f)  "
        "iso_anomaly=%-5s  line=%s",
        composite,
        _severity_label(composite).upper(),
        result["rf_label"],
        result["rf_confidence"],
        result["iso_is_anomaly"],
        line[:120],
    )

    if loki_url:
        _push_to_loki(loki_url, {
            "streams": [{
                "stream": {
                    "job": "siem_ml_alerts",
                    "severity": _severity_label(composite),
                    "rf_label": result["rf_label"],
                },
                "values": [[str(int(time.time() * 1e9)), json.dumps({
                    "log_line": line,
                    "composite_score": composite,
                    "rf_label": result["rf_label"],
                    "rf_confidence": result["rf_confidence"],
                    "iso_score": result["iso_score"],
                    "iso_is_anomaly": result["iso_is_anomaly"],
                })]],
            }]
        })


# ---------------------------------------------------------------------------
# Log tailing — inotify (Linux) with 1-second polling fallback
# ---------------------------------------------------------------------------
def tail_unified(
    log_path: str,
    rules: list[Rule],
    cooldowns: CooldownTracker,
    brute: BruteForceDetector,
    ml_scorer: Any | None,
    ml_threshold: float,
    loki_url: str | None,
) -> None:
    path = Path(log_path)
    fh: TextIOWrapper = path.open("r", errors="replace")
    fh.seek(0, 2)

    try:
        import inotify.adapters as _ia  # type: ignore[import-untyped]
        watcher = _ia.Inotify()
        watcher.add_watch(str(path.parent))
        use_inotify = True
    except ImportError:
        use_inotify = False
        logger.warning("inotify unavailable — polling %s every 1s", log_path)

    logger.info("Unified scorer watching %s", log_path)

    def _handle(line: str) -> None:
        process_unified(
            line.rstrip(), rules, cooldowns, brute, ml_scorer, ml_threshold, loki_url
        )

    try:
        if use_inotify:
            for raw_event in watcher.event_gen(yield_nones=False):  # type: ignore[possibly-undefined]
                type_names = list(raw_event[1])
                filename = str(raw_event[3])
                if filename != path.name:
                    continue
                if not any(e in type_names for e in ("IN_MODIFY", "IN_MOVED_TO", "IN_CLOSE_WRITE")):
                    continue
                if "IN_MOVED_TO" in type_names:
                    fh.close()
                    fh = path.open("r", errors="replace")
                    logger.info("Log rotated — re-opened %s", log_path)
                for line in fh:
                    _handle(line)
        else:
            while True:
                line = fh.readline()
                if line:
                    _handle(line)
                else:
                    time.sleep(1)
    finally:
        fh.close()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="SIEM-Lite unified scorer — rule-based + ML on every log line.",
    )
    parser.add_argument("--rules", default=DEFAULT_RULES_PATH, metavar="PATH")
    parser.add_argument("--log", dest="logs", action="append", metavar="PATH",
                        help="Log file to watch (repeatable; auto-detected if omitted)")
    parser.add_argument("--ml-threshold", type=float, default=15.0, metavar="SCORE",
                        help="Minimum ML composite score to emit alert (default: 15.0)")
    parser.add_argument("--brute-threshold", type=int, default=5, metavar="N",
                        help="SSH failures from same IP to trigger brute-force alert (default: 5)")
    parser.add_argument("--brute-window", type=int, default=60, metavar="SECS",
                        help="Sliding window for brute-force counting in seconds (default: 60)")
    parser.add_argument("--push-to-loki", metavar="URL",
                        help="Push alerts to Loki (e.g. http://localhost:3100)")
    parser.add_argument("--rules-only", action="store_true",
                        help="Skip ML inference even if models exist")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    rules = load_rules(args.rules)
    cooldowns = CooldownTracker()
    brute = BruteForceDetector(
        threshold=args.brute_threshold,
        window_secs=args.brute_window,
    )
    ml_scorer = None if args.rules_only else _try_load_ml_scorer()

    logger.info(
        "Mode: %s | Brute-force: %d failures / %ds window | ML threshold: %.1f",
        "rule+ML" if ml_scorer else "rule-only",
        args.brute_threshold, args.brute_window, args.ml_threshold,
    )

    log_paths = args.logs if args.logs else discover_log_paths()
    if not log_paths:
        logger.error("No log files found. Exiting.")
        return

    threads: list[threading.Thread] = []
    for lp in log_paths:
        t = threading.Thread(
            target=tail_unified,
            args=(lp, rules, cooldowns, brute, ml_scorer, args.ml_threshold, args.push_to_loki),
            daemon=True,
            name=f"unified-{Path(lp).name}",
        )
        t.start()
        threads.append(t)

    logger.info("Unified scorer running on %d file(s). Ctrl-C to stop.", len(threads))
    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        logger.info("Shutting down.")


if __name__ == "__main__":
    main()
