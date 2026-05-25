#!/usr/bin/env python3
"""
Feature engineering for SIEM-Lite ML pipeline.

Extracts structured features from raw syslog/auth.log lines for use
with scikit-learn classifiers and the Isolation Forest anomaly detector.

Features extracted:
    Temporal   — hour_of_day, is_after_hours, day_of_week
    Network    — has_ip, ip_octets (4 features), port_number
    Auth       — is_failed_login, is_accepted_login, is_sudo, is_su,
                 is_root_target, is_user_creation
    Textual    — log_length, word_count, has_invalid_user
    TF-IDF     — top-N unigram features from log message body
"""

from __future__ import annotations

import re
from typing import Any

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from scipy.sparse import hstack, csr_matrix


# ---------------------------------------------------------------------------
# Regex patterns for feature extraction
# ---------------------------------------------------------------------------
_RE_IP = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
_RE_PORT = re.compile(r"port\s+(\d+)")
_RE_HOUR = re.compile(r"^(\w{3}\s+\d{1,2}\s+(\d{2}):\d{2}:\d{2})")
_RE_USER = re.compile(r"(?:for|user)\s+(\S+)")
_RE_MONTH_DAY = re.compile(r"^(\w{3})\s+(\d{1,2})")

MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def extract_structured_features(df: pd.DataFrame, col: str = "log_line") -> pd.DataFrame:
    """Extract hand-crafted features from raw log lines.

    Parameters
    ----------
    df : pd.DataFrame
        Must contain a column named *col* with raw log strings.
    col : str
        Column name containing log lines.

    Returns
    -------
    pd.DataFrame
        Feature matrix with one row per log line.
    """
    lines = df[col].astype(str)
    feats: dict[str, Any] = {}

    # -- Temporal features --
    hours = lines.str.extract(_RE_HOUR.pattern, expand=True)
    feats["hour_of_day"] = pd.to_numeric(hours[1], errors="coerce").fillna(12).astype(int)
    feats["is_after_hours"] = feats["hour_of_day"].apply(
        lambda h: 1 if (h >= 23 or h < 5) else 0
    )

    md = lines.str.extract(_RE_MONTH_DAY.pattern, expand=True)
    feats["month"] = md[0].map(MONTH_MAP).fillna(1).astype(int)
    feats["day_of_month"] = pd.to_numeric(md[1], errors="coerce").fillna(15).astype(int)

    # -- Network features --
    ip_match = lines.str.extract(_RE_IP.pattern, expand=False)
    feats["has_ip"] = ip_match.notna().astype(int)

    ip_octets = ip_match.str.split(".", expand=True)
    for i in range(4):
        feats[f"ip_octet_{i}"] = (
            pd.to_numeric(ip_octets[i], errors="coerce").fillna(0).astype(int)
            if ip_octets is not None and i in ip_octets.columns
            else 0
        )

    port_match = lines.str.extract(_RE_PORT.pattern, expand=False)
    feats["port_number"] = pd.to_numeric(port_match, errors="coerce").fillna(0).astype(int)

    # -- Auth event binary features --
    low = lines.str.lower()
    feats["is_failed_login"] = low.str.contains("failed password", na=False).astype(int)
    feats["is_accepted_login"] = low.str.contains("accepted password", na=False).astype(int)
    feats["is_sudo"] = low.str.contains(r"\bsudo\b", regex=True, na=False).astype(int)
    feats["is_su"] = low.str.contains(r"\bsu[\[:\s]", regex=True, na=False).astype(int)
    feats["is_root_target"] = low.str.contains(r"\broot\b", na=False).astype(int)
    feats["is_user_creation"] = low.str.contains(
        r"useradd|adduser|new user", regex=True, na=False
    ).astype(int)
    feats["has_invalid_user"] = low.str.contains("invalid user", na=False).astype(int)
    feats["is_session_open"] = low.str.contains("session opened", na=False).astype(int)
    feats["is_session_close"] = low.str.contains("session closed", na=False).astype(int)
    feats["is_cron"] = low.str.contains("cron", na=False).astype(int)

    # -- Text-level features --
    feats["log_length"] = lines.str.len()
    feats["word_count"] = lines.str.split().str.len()

    return pd.DataFrame(feats)


class LogFeaturizer:
    """Combined hand-crafted + TF-IDF feature extractor.

    Usage::

        featurizer = LogFeaturizer(tfidf_max_features=200)
        X_train = featurizer.fit_transform(df_train)
        X_test  = featurizer.transform(df_test)
    """

    def __init__(self, tfidf_max_features: int = 200) -> None:
        self.tfidf_max_features = tfidf_max_features
        self._tfidf = TfidfVectorizer(
            max_features=tfidf_max_features,
            stop_words="english",
            token_pattern=r"(?u)\b[a-zA-Z_]\w+\b",  # words only, skip numbers
            sublinear_tf=True,
        )
        self._fitted = False

    @property
    def structured_feature_names(self) -> list[str]:
        """Return the list of structured (non-TF-IDF) feature names."""
        return [
            "hour_of_day", "is_after_hours", "month", "day_of_month",
            "has_ip", "ip_octet_0", "ip_octet_1", "ip_octet_2", "ip_octet_3",
            "port_number",
            "is_failed_login", "is_accepted_login", "is_sudo", "is_su",
            "is_root_target", "is_user_creation", "has_invalid_user",
            "is_session_open", "is_session_close", "is_cron",
            "log_length", "word_count",
        ]

    def fit_transform(self, df: pd.DataFrame, col: str = "log_line") -> csr_matrix:
        """Fit on training data and return the combined feature matrix."""
        struct = extract_structured_features(df, col)
        tfidf = self._tfidf.fit_transform(df[col].astype(str))
        self._fitted = True
        return hstack([csr_matrix(struct.values), tfidf])

    def transform(self, df: pd.DataFrame, col: str = "log_line") -> csr_matrix:
        """Transform new data using the fitted TF-IDF vocabulary."""
        if not self._fitted:
            raise RuntimeError("Call fit_transform() before transform()")
        struct = extract_structured_features(df, col)
        tfidf = self._tfidf.transform(df[col].astype(str))
        return hstack([csr_matrix(struct.values), tfidf])

    def get_feature_names(self) -> list[str]:
        """Return all feature names (structured + TF-IDF)."""
        tfidf_names = [
            f"tfidf_{w}" for w in self._tfidf.get_feature_names_out()
        ]
        return self.structured_feature_names + tfidf_names
