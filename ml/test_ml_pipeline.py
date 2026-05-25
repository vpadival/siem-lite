"""
Tests for SIEM-Lite ML pipeline.

Run with:  python -m pytest ml/test_ml_pipeline.py -v
"""

from __future__ import annotations

import re
import textwrap
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import pytest
from scipy.sparse import issparse

import sys
sys.path.insert(0, str(Path(__file__).parent))

from feature_engineering import LogFeaturizer, extract_structured_features


# ---------------------------------------------------------------------------
# Sample data
# ---------------------------------------------------------------------------
SAMPLE_LINES = [
    "May 10 14:23:01 webserver01 sshd[1234]: Accepted password for alice from 192.168.1.10 port 50123 ssh2",
    "May 10 02:15:33 webserver01 sshd[5678]: Failed password for invalid user hacker from 45.33.32.156 port 44321 ssh2",
    "May 10 09:00:01 dbserver02 sudo: bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash",
    "May 10 23:45:12 appserver03 sshd[9999]: Accepted password for root from 185.220.101.34 port 60001 ssh2",
    "May 10 11:00:00 webserver01 CRON[4444]: pam_unix(cron:session): session opened for user alice(uid=1000) by (uid=0)",
    "May 10 16:30:00 dbserver02 useradd[7777]: new user: name=backdoor, UID=1050, GID=1050, home=/home/backdoor, shell=/bin/bash",
    "May 10 03:10:55 webserver01 su[8888]: FAILED su for root by intruder",
]

SAMPLE_LABELS = [
    "normal",
    "ssh_brute_force",
    "privilege_escalation",
    "root_login",
    "normal",
    "new_user_created",
    "su_failure",
]


@pytest.fixture
def sample_df() -> pd.DataFrame:
    return pd.DataFrame({"log_line": SAMPLE_LINES, "label": SAMPLE_LABELS})


# ===========================================================================
# extract_structured_features
# ===========================================================================
class TestStructuredFeatures:
    def test_returns_dataframe(self, sample_df: pd.DataFrame) -> None:
        feats = extract_structured_features(sample_df)
        assert isinstance(feats, pd.DataFrame)
        assert len(feats) == len(sample_df)

    def test_hour_extraction(self, sample_df: pd.DataFrame) -> None:
        feats = extract_structured_features(sample_df)
        # First line: "May 10 14:23:01" -> hour 14
        assert feats.iloc[0]["hour_of_day"] == 14

    def test_after_hours_flag(self, sample_df: pd.DataFrame) -> None:
        feats = extract_structured_features(sample_df)
        # Line at 02:15 should be after-hours
        assert feats.iloc[1]["is_after_hours"] == 1
        # Line at 14:23 should NOT be after-hours
        assert feats.iloc[0]["is_after_hours"] == 0

    def test_ip_detection(self, sample_df: pd.DataFrame) -> None:
        feats = extract_structured_features(sample_df)
        # Lines 0,1,3 have IPs
        assert feats.iloc[0]["has_ip"] == 1
        assert feats.iloc[1]["has_ip"] == 1

    def test_failed_login_flag(self, sample_df: pd.DataFrame) -> None:
        feats = extract_structured_features(sample_df)
        assert feats.iloc[1]["is_failed_login"] == 1  # "Failed password"
        assert feats.iloc[0]["is_failed_login"] == 0  # "Accepted password"

    def test_sudo_flag(self, sample_df: pd.DataFrame) -> None:
        feats = extract_structured_features(sample_df)
        assert feats.iloc[2]["is_sudo"] == 1

    def test_root_target_flag(self, sample_df: pd.DataFrame) -> None:
        feats = extract_structured_features(sample_df)
        assert feats.iloc[3]["is_root_target"] == 1  # root login

    def test_user_creation_flag(self, sample_df: pd.DataFrame) -> None:
        feats = extract_structured_features(sample_df)
        assert feats.iloc[5]["is_user_creation"] == 1

    def test_log_length_positive(self, sample_df: pd.DataFrame) -> None:
        feats = extract_structured_features(sample_df)
        assert all(feats["log_length"] > 0)

    def test_all_expected_columns_present(self, sample_df: pd.DataFrame) -> None:
        feats = extract_structured_features(sample_df)
        expected = {
            "hour_of_day", "is_after_hours", "has_ip", "is_failed_login",
            "is_accepted_login", "is_sudo", "is_su", "is_root_target",
            "is_user_creation", "log_length", "word_count",
        }
        assert expected.issubset(set(feats.columns))


# ===========================================================================
# LogFeaturizer
# ===========================================================================
class TestLogFeaturizer:
    def test_fit_transform_returns_sparse(self, sample_df: pd.DataFrame) -> None:
        f = LogFeaturizer(tfidf_max_features=50)
        X = f.fit_transform(sample_df)
        assert issparse(X)
        assert X.shape[0] == len(sample_df)

    def test_transform_after_fit(self, sample_df: pd.DataFrame) -> None:
        f = LogFeaturizer(tfidf_max_features=50)
        f.fit_transform(sample_df)
        X2 = f.transform(sample_df)
        assert X2.shape[0] == len(sample_df)

    def test_transform_before_fit_raises(self, sample_df: pd.DataFrame) -> None:
        f = LogFeaturizer()
        with pytest.raises(RuntimeError, match="fit_transform"):
            f.transform(sample_df)

    def test_feature_names_length_matches_columns(self, sample_df: pd.DataFrame) -> None:
        f = LogFeaturizer(tfidf_max_features=50)
        X = f.fit_transform(sample_df)
        names = f.get_feature_names()
        assert len(names) == X.shape[1]

    def test_tfidf_features_present(self, sample_df: pd.DataFrame) -> None:
        f = LogFeaturizer(tfidf_max_features=50)
        f.fit_transform(sample_df)
        names = f.get_feature_names()
        tfidf_names = [n for n in names if n.startswith("tfidf_")]
        assert len(tfidf_names) > 0

    def test_single_line_transform(self, sample_df: pd.DataFrame) -> None:
        f = LogFeaturizer(tfidf_max_features=50)
        f.fit_transform(sample_df)
        single = pd.DataFrame({"log_line": [SAMPLE_LINES[0]]})
        X = f.transform(single)
        assert X.shape[0] == 1


# ===========================================================================
# Dataset generator smoke test
# ===========================================================================
class TestDatasetGenerator:
    def test_import_and_generate(self) -> None:
        sys.path.insert(0, str(Path(__file__).parent.parent / "data"))
        from generate_dataset import generate_dataset

        rows = generate_dataset(num_lines=100, attack_ratio=0.3, seed=99)
        assert len(rows) == 100
        labels = {label for _, label in rows}
        assert "normal" in labels
        # At least one attack type should be present
        attack_labels = labels - {"normal"}
        assert len(attack_labels) >= 1

    def test_all_rows_are_tuples(self) -> None:
        sys.path.insert(0, str(Path(__file__).parent.parent / "data"))
        from generate_dataset import generate_dataset

        rows = generate_dataset(num_lines=50, seed=123)
        for row in rows:
            assert isinstance(row, tuple)
            assert len(row) == 2
            assert isinstance(row[0], str)
            assert isinstance(row[1], str)
