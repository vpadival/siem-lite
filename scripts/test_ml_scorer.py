"""
Unit tests for ml_scorer.py  (previously completely untested).

Tests: MLScorer.predict output shape/types, composite score formula,
severity mapping, Loki payload structure, and _score_and_emit threshold logic.

Run with:  python -m pytest scripts/test_ml_scorer.py -v
"""
from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).parent))

from ml_scorer import (
    MLScorer,
    _score_and_emit,
    _severity_from_score,
    push_to_loki,
)


# ---------------------------------------------------------------------------
# Fixtures: mock MLScorer so tests run without saved .joblib files
# ---------------------------------------------------------------------------
def _make_mock_scorer(
    rf_proba: list[float] | None = None,
    iso_score: float = 0.1,
    iso_pred: int = 1,
    class_names: list[str] | None = None,
) -> MLScorer:
    """Return an MLScorer whose sklearn internals are fully mocked."""
    if class_names is None:
        class_names = ["after_hours_login", "new_user_created", "normal",
                       "privilege_escalation", "root_login", "ssh_brute_force", "su_failure"]
    if rf_proba is None:
        rf_proba = [0.0] * len(class_names)
        normal_idx = class_names.index("normal")
        rf_proba[normal_idx] = 1.0

    scorer = object.__new__(MLScorer)

    mock_rf = MagicMock()
    mock_rf.predict_proba.return_value = [rf_proba]

    mock_iso = MagicMock()
    mock_iso.decision_function.return_value = [iso_score]
    mock_iso.predict.return_value = [iso_pred]

    mock_featurizer = MagicMock()
    mock_featurizer.transform.return_value = MagicMock()

    mock_le = MagicMock()
    mock_le.inverse_transform.side_effect = lambda idx: [class_names[idx[0]]]

    scorer.rf = mock_rf
    scorer.iso = mock_iso
    scorer.featurizer = mock_featurizer
    scorer.label_encoder = mock_le
    return scorer


# ===========================================================================
# _severity_from_score
# ===========================================================================
class TestSeverityFromScore:
    @pytest.mark.parametrize("score,expected", [
        (0.0,  "info"),
        (9.9,  "info"),
        (10.0, "low"),
        (29.9, "low"),
        (30.0, "medium"),
        (49.9, "medium"),
        (50.0, "high"),
        (69.9, "high"),
        (70.0, "critical"),
        (100.0,"critical"),
    ])
    def test_boundary_values(self, score: float, expected: str) -> None:
        assert _severity_from_score(score) == expected


# ===========================================================================
# MLScorer.predict — output contract
# ===========================================================================
class TestMLScorerPredict:
    def test_returns_all_required_keys(self) -> None:
        scorer = _make_mock_scorer()
        result = scorer.predict("some log line")
        required = {"rf_label", "rf_confidence", "rf_probabilities",
                    "iso_score", "iso_is_anomaly", "composite_score"}
        assert required.issubset(result.keys())

    def test_rf_label_is_string(self) -> None:
        scorer = _make_mock_scorer()
        assert isinstance(scorer.predict("line")["rf_label"], str)

    def test_rf_confidence_between_0_and_1(self) -> None:
        scorer = _make_mock_scorer()
        conf = scorer.predict("line")["rf_confidence"]
        assert 0.0 <= conf <= 1.0

    def test_composite_score_between_0_and_100(self) -> None:
        scorer = _make_mock_scorer()
        score = scorer.predict("line")["composite_score"]
        assert 0.0 <= score <= 100.0

    def test_iso_is_anomaly_true_when_pred_minus_one(self) -> None:
        scorer = _make_mock_scorer(iso_pred=-1)
        assert scorer.predict("line")["iso_is_anomaly"] is True

    def test_iso_is_anomaly_false_when_pred_one(self) -> None:
        scorer = _make_mock_scorer(iso_pred=1)
        assert scorer.predict("line")["iso_is_anomaly"] is False

    def test_normal_line_has_low_composite_score(self) -> None:
        # All probability on "normal", iso score positive (inlier)
        scorer = _make_mock_scorer(iso_score=0.3, iso_pred=1)
        result = scorer.predict("Accepted password for alice from 192.168.1.1 port 50000")
        assert result["composite_score"] < 30.0, (
            f"Expected low score for normal line, got {result['composite_score']}"
        )

    def test_attack_line_has_high_composite_score(self) -> None:
        # All probability on "ssh_brute_force", iso predicts anomaly
        class_names = ["after_hours_login", "new_user_created", "normal",
                       "privilege_escalation", "root_login", "ssh_brute_force", "su_failure"]
        rf_proba = [0.0] * len(class_names)
        rf_proba[class_names.index("ssh_brute_force")] = 1.0
        scorer = _make_mock_scorer(rf_proba=rf_proba, iso_score=-0.4, iso_pred=-1)
        result = scorer.predict("Failed password for root from 45.33.32.156 port 22")
        assert result["composite_score"] > 70.0, (
            f"Expected high score for attack line, got {result['composite_score']}"
        )

    def test_rf_probabilities_sum_to_one(self) -> None:
        scorer = _make_mock_scorer()
        probs = scorer.predict("line")["rf_probabilities"]
        total = sum(probs.values())
        assert abs(total - 1.0) < 1e-6, f"Probabilities should sum to 1, got {total}"


# ===========================================================================
# push_to_loki — payload structure
# ===========================================================================
class TestPushToLoki:
    def test_payload_structure(self) -> None:
        captured: list[Any] = []

        def mock_urlopen(req: Any, timeout: int = 5) -> None:
            import json as _json
            body = _json.loads(req.data.decode())
            captured.append(body)

        with patch("urllib.request.urlopen", side_effect=mock_urlopen):
            push_to_loki(
                "http://localhost:3100",
                "some log line",
                {
                    "composite_score": 80.0,
                    "rf_label": "ssh_brute_force",
                    "iso_score": -0.3,
                    "iso_is_anomaly": True,
                    "rf_probabilities": {"normal": 0.0, "ssh_brute_force": 1.0},
                },
            )

        assert len(captured) == 1
        payload = captured[0]
        assert "streams" in payload
        stream = payload["streams"][0]
        assert stream["stream"]["job"] == "siem_ml_alerts"
        assert stream["stream"]["severity"] == "critical"
        assert stream["stream"]["rf_label"] == "ssh_brute_force"
        # rf_probabilities should be excluded from the Loki value
        value_json = json.loads(stream["values"][0][1])
        assert "rf_probabilities" not in value_json
        assert "composite_score" in value_json

    def test_push_silently_ignores_network_errors(self) -> None:
        """A Loki push failure must never crash the scorer."""
        with patch("urllib.request.urlopen", side_effect=OSError("connection refused")):
            # Should not raise
            push_to_loki(
                "http://localhost:3100",
                "line",
                {"composite_score": 50.0, "rf_label": "normal",
                 "iso_score": 0.1, "iso_is_anomaly": False, "rf_probabilities": {}},
            )


# ===========================================================================
# _score_and_emit — threshold gating
# ===========================================================================
class TestScoreAndEmit:
    def _alerts(self, composite: float, threshold: float) -> list[str]:
        class_names = ["normal", "ssh_brute_force"]
        rf_proba = [0.0, 0.0]
        # Reverse-engineer the proba needed to hit `composite` with iso_score=0
        # composite = 70 * (1 - rf_normal_prob) + 30 * 0.5
        # => rf_normal_prob = 1 - (composite - 15) / 70
        rf_normal_prob = max(0.0, min(1.0, 1.0 - (composite - 15.0) / 70.0))
        rf_proba[0] = rf_normal_prob
        rf_proba[1] = 1.0 - rf_normal_prob

        scorer = _make_mock_scorer(
            rf_proba=rf_proba,
            iso_score=0.0,   # iso_norm = 0.5, contributes 15 to composite
            iso_pred=1 if composite < 50 else -1,
            class_names=class_names,
        )
        captured: list[str] = []

        class _H(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                if "ML-ALERT" in record.getMessage():
                    captured.append(record.getMessage())

        h = _H()
        log = logging.getLogger("siem-ml-scorer")
        log.addHandler(h)
        try:
            _score_and_emit("some log line", scorer, threshold, loki_url=None)
        finally:
            log.removeHandler(h)
        return captured

    def test_above_threshold_emits_alert(self) -> None:
        scorer = _make_mock_scorer(
            rf_proba=[0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0],  # ssh_brute_force
            iso_score=-0.4,
            iso_pred=-1,
        )
        captured: list[str] = []

        class _H(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                if "ML-ALERT" in record.getMessage():
                    captured.append(record.getMessage())

        h = _H()
        log = logging.getLogger("siem-ml-scorer")
        log.setLevel(logging.WARNING)
        log.addHandler(h)
        try:
            _score_and_emit("attack line", scorer, threshold=10.0, loki_url=None)
        finally:
            log.removeHandler(h)
        assert len(captured) >= 1

    def test_empty_line_is_skipped(self) -> None:
        scorer = _make_mock_scorer()
        # Should not raise or call predict
        _score_and_emit("", scorer, threshold=10.0, loki_url=None)
        scorer.rf.predict_proba.assert_not_called()
