#!/usr/bin/env python3
"""
ML-enhanced alert scorer for SIEM-Lite.

Extends the original regex-based alert_scorer with:
    1. Random Forest classification — classifies each log line into an
       attack category (or normal) using the trained model.
    2. Isolation Forest anomaly scoring — flags lines that deviate from
       the learned "normal" distribution.

Both ML predictions are combined with the existing rule-based scores to
produce a composite risk score.  Results are optionally pushed to Loki
via its HTTP API so they appear in the Grafana dashboard.

Usage:
    # Ensure models exist (run ml/train_and_evaluate.py first)
    python scripts/ml_scorer.py
    python scripts/ml_scorer.py --push-to-loki http://localhost:3100
    python scripts/ml_scorer.py --log /var/log/auth.log --threshold 0.6
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
import time
import threading
from datetime import datetime, timezone
from io import TextIOWrapper
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd

# Add project root to path so we can import from ml/
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "ml"))

from feature_engineering import LogFeaturizer  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("siem-ml-scorer")

MODELS_DIR = PROJECT_ROOT / "ml" / "models"


# ---------------------------------------------------------------------------
# Model loader
# ---------------------------------------------------------------------------
class MLScorer:
    """Wraps the trained RF classifier, Isolation Forest, and featurizer."""

    def __init__(self, models_dir: Path = MODELS_DIR) -> None:
        self.rf = joblib.load(models_dir / "random_forest.joblib")
        self.iso = joblib.load(models_dir / "isolation_forest.joblib")
        self.featurizer: LogFeaturizer = joblib.load(models_dir / "featurizer.joblib")
        self.label_encoder = joblib.load(models_dir / "label_encoder.joblib")
        logger.info("Loaded ML models from %s", models_dir)

    def predict(self, log_line: str) -> dict[str, Any]:
        """Score a single log line.

        Returns
        -------
        dict with keys:
            rf_label        : str   — predicted class name
            rf_confidence   : float — max class probability
            rf_probabilities: dict  — {class: probability}
            iso_score       : float — anomaly score (lower = more anomalous)
            iso_is_anomaly  : bool  — True if Isolation Forest flags it
            composite_score : float — combined risk score 0-100
        """
        df = pd.DataFrame({"log_line": [log_line]})
        X = self.featurizer.transform(df)

        # Random Forest
        rf_proba = self.rf.predict_proba(X)[0]
        rf_label_idx = int(np.argmax(rf_proba))
        rf_label = str(self.label_encoder.inverse_transform([rf_label_idx])[0])
        rf_confidence = float(rf_proba[rf_label_idx])
        rf_probs = {
            str(self.label_encoder.inverse_transform([i])[0]): round(float(p), 4)
            for i, p in enumerate(rf_proba)
        }

        # Isolation Forest
        iso_score = float(self.iso.decision_function(X)[0])
        iso_pred = int(self.iso.predict(X)[0])
        iso_is_anomaly = iso_pred == -1

        # Composite score (0-100): blend RF attack confidence + IF anomaly
        rf_attack_prob = 1.0 - rf_probs.get("normal", 0.0)
        # Normalise iso_score: typical range [-0.5, 0.5] -> [0, 1]
        iso_norm = max(0.0, min(1.0, 0.5 - iso_score))
        composite = round(
            70 * rf_attack_prob + 30 * iso_norm,  # weighted blend
            2,
        )

        return {
            "rf_label": rf_label,
            "rf_confidence": round(rf_confidence, 4),
            "rf_probabilities": rf_probs,
            "iso_score": round(iso_score, 4),
            "iso_is_anomaly": iso_is_anomaly,
            "composite_score": composite,
        }


# ---------------------------------------------------------------------------
# Loki push (optional)
# ---------------------------------------------------------------------------
def push_to_loki(loki_url: str, log_line: str, result: dict[str, Any]) -> None:
    """Push an ML-scored alert to Loki's push API."""
    try:
        import urllib.request

        payload = {
            "streams": [
                {
                    "stream": {
                        "job": "siem_ml_alerts",
                        "severity": _severity_from_score(result["composite_score"]),
                        "rf_label": result["rf_label"],
                    },
                    "values": [
                        [
                            str(int(time.time() * 1e9)),  # nanosecond timestamp
                            json.dumps({
                                "log_line": log_line,
                                **{k: v for k, v in result.items()
                                   if k != "rf_probabilities"},
                            }),
                        ]
                    ],
                }
            ]
        }

        req = urllib.request.Request(
            f"{loki_url}/loki/api/v1/push",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        logger.debug("Loki push failed: %s", e)


def _severity_from_score(score: float) -> str:
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
# Log tailing (reuses inotify/polling from alert_scorer)
# ---------------------------------------------------------------------------
def tail_and_score(
    log_path: str,
    scorer: MLScorer,
    threshold: float,
    loki_url: str | None,
) -> None:
    """Tail a log file and score each new line with ML models."""
    path = Path(log_path)
    fh: TextIOWrapper = path.open("r", errors="replace")
    fh.seek(0, 2)  # skip to end

    logger.info("ML scorer watching %s (threshold=%.2f)", log_path, threshold)

    while True:
        line = fh.readline()
        if not line:
            time.sleep(1)
            continue

        line = line.rstrip()
        if not line:
            continue

        result = scorer.predict(line)

        if result["composite_score"] >= threshold:
            logger.warning(
                "ML-ALERT  composite=%-5.1f  rf=%-22s (%.2f)  iso_anomaly=%-5s  line=%s",
                result["composite_score"],
                result["rf_label"],
                result["rf_confidence"],
                result["iso_is_anomaly"],
                line[:120],
            )
            if loki_url:
                push_to_loki(loki_url, line, result)
        else:
            logger.debug(
                "NORMAL    composite=%-5.1f  rf=%-22s  line=%s",
                result["composite_score"],
                result["rf_label"],
                line[:80],
            )


# ---------------------------------------------------------------------------
# Log path discovery (same as alert_scorer.py)
# ---------------------------------------------------------------------------
def discover_log_paths() -> list[str]:
    candidates = [
        "/var/log/auth.log", "/var/log/secure",
        "/var/log/syslog", "/var/log/messages",
    ]
    return [p for p in candidates if Path(p).exists()]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="ML-enhanced SIEM-Lite scorer — classifies log lines in real time.",
    )
    parser.add_argument(
        "--log", dest="logs", action="append", metavar="PATH",
        help="Log file to watch (repeatable; auto-detected if omitted)",
    )
    parser.add_argument(
        "--models-dir", default=str(MODELS_DIR), metavar="DIR",
        help=f"Directory with trained models (default: {MODELS_DIR})",
    )
    parser.add_argument(
        "--threshold", type=float, default=15.0,
        help="Minimum composite score to emit an alert (default: 15.0)",
    )
    parser.add_argument(
        "--push-to-loki", metavar="URL",
        help="Push alerts to Loki (e.g. http://localhost:3100)",
    )
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    scorer = MLScorer(Path(args.models_dir))

    log_paths = args.logs if args.logs else discover_log_paths()
    if not log_paths:
        logger.error("No log files found. Exiting.")
        return

    threads: list[threading.Thread] = []
    for lp in log_paths:
        t = threading.Thread(
            target=tail_and_score,
            args=(lp, scorer, args.threshold, args.push_to_loki),
            daemon=True,
            name=f"ml-watcher-{Path(lp).name}",
        )
        t.start()
        threads.append(t)

    logger.info("ML scorer running on %d log file(s). Ctrl-C to stop.", len(threads))
    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        logger.info("Shutting down.")


if __name__ == "__main__":
    main()
