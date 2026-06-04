#!/usr/bin/env python3
"""
SIEM-Lite ML Training & Evaluation Pipeline

Trains two models:
    1. Random Forest Classifier — supervised multi-class log classification
       (normal vs 6 attack types)
    2. Isolation Forest — unsupervised anomaly detection (normal vs anomalous)

Outputs:
    - Serialised models   -> ml/models/
    - Classification report, confusion matrix, ROC curves -> ml/results/
    - Serialised featurizer for inference -> ml/models/

Usage:
    # Generate dataset first
    python data/generate_dataset.py --num-lines 50000 --output data/auth_logs_labeled.csv

    # Train and evaluate
    python ml/train_and_evaluate.py --dataset data/auth_logs_labeled.csv
    python ml/train_and_evaluate.py --dataset data/auth_logs_labeled.csv --test-size 0.3
"""

from __future__ import annotations

import argparse
import json
import logging
import warnings
from pathlib import Path

import joblib
import matplotlib
matplotlib.use("Agg")  # non-interactive backend
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.preprocessing import LabelEncoder, label_binarize

from feature_engineering import LogFeaturizer

warnings.filterwarnings("ignore", category=FutureWarning)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("siem-ml")

MODELS_DIR = Path("ml/models")
RESULTS_DIR = Path("ml/results")


# ---------------------------------------------------------------------------
# 1. Random Forest Classifier (supervised multi-class)
# ---------------------------------------------------------------------------
def train_random_forest(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
    label_encoder: LabelEncoder,
    featurizer: LogFeaturizer,          # FIX R4: passed explicitly, no global
) -> RandomForestClassifier:
    """Train a Random Forest, evaluate, and save artefacts."""

    logger.info("Training Random Forest Classifier ...")
    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        min_samples_split=5,
        min_samples_leaf=2,
        class_weight="balanced",   # handle class imbalance
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)

    # -- Predictions --
    y_pred = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)

    # -- Metrics --
    acc = accuracy_score(y_test, y_pred)
    f1_macro = f1_score(y_test, y_pred, average="macro")
    f1_weighted = f1_score(y_test, y_pred, average="weighted")
    prec_macro = precision_score(y_test, y_pred, average="macro")
    rec_macro = recall_score(y_test, y_pred, average="macro")

    class_names = list(label_encoder.classes_)
    report = classification_report(y_test, y_pred, target_names=class_names)

    logger.info("Accuracy:           %.4f", acc)
    logger.info("F1 (macro):         %.4f", f1_macro)
    logger.info("F1 (weighted):      %.4f", f1_weighted)
    logger.info("Precision (macro):  %.4f", prec_macro)
    logger.info("Recall (macro):     %.4f", rec_macro)
    logger.info("\nClassification Report:\n%s", report)

    # -- Cross-validation --
    logger.info("Running 5-fold stratified cross-validation ...")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(clf, X_train, y_train, cv=cv, scoring="f1_macro", n_jobs=-1)
    logger.info("CV F1 (macro): %.4f ± %.4f", cv_scores.mean(), cv_scores.std())

    # -- Save metrics --
    metrics = {
        "accuracy": round(acc, 4),
        "f1_macro": round(f1_macro, 4),
        "f1_weighted": round(f1_weighted, 4),
        "precision_macro": round(prec_macro, 4),
        "recall_macro": round(rec_macro, 4),
        "cv_f1_macro_mean": round(cv_scores.mean(), 4),
        "cv_f1_macro_std": round(cv_scores.std(), 4),
        "n_train": int(X_train.shape[0]),
        "n_test": int(X_test.shape[0]),
        "n_classes": len(class_names),
        "class_names": class_names,
    }
    (RESULTS_DIR / "rf_metrics.json").write_text(json.dumps(metrics, indent=2))
    (RESULTS_DIR / "rf_classification_report.txt").write_text(report)

    # -- Confusion matrix plot --
    cm = confusion_matrix(y_test, y_pred)
    fig, ax = plt.subplots(figsize=(10, 8))
    ConfusionMatrixDisplay(cm, display_labels=class_names).plot(
        ax=ax, cmap="Blues", values_format="d", xticks_rotation=45,
    )
    ax.set_title("Random Forest — Confusion Matrix")
    fig.tight_layout()
    fig.savefig(str(RESULTS_DIR / "rf_confusion_matrix.png"), dpi=150)
    plt.close(fig)
    logger.info("Saved confusion matrix -> %s", RESULTS_DIR / "rf_confusion_matrix.png")

    # -- ROC curves (one-vs-rest) --
    y_test_bin = label_binarize(y_test, classes=list(range(len(class_names))))
    fig, ax = plt.subplots(figsize=(10, 8))
    for i, name in enumerate(class_names):
        if y_test_bin.shape[1] <= i:
            continue
        fpr, tpr, _ = roc_curve(y_test_bin[:, i], y_proba[:, i])
        auc_val = roc_auc_score(y_test_bin[:, i], y_proba[:, i])
        ax.plot(fpr, tpr, label=f"{name} (AUC={auc_val:.3f})")
    ax.plot([0, 1], [0, 1], "k--", alpha=0.4)
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title("Random Forest — One-vs-Rest ROC Curves")
    ax.legend(loc="lower right", fontsize=8)
    fig.tight_layout()
    fig.savefig(str(RESULTS_DIR / "rf_roc_curves.png"), dpi=150)
    plt.close(fig)
    logger.info("Saved ROC curves -> %s", RESULTS_DIR / "rf_roc_curves.png")

    # -- Feature importance (top 25) --
    feat_names = featurizer.get_feature_names()   # FIX R4: use parameter, not global
    importances = clf.feature_importances_
    top_n = 25
    top_idx = np.argsort(importances)[-top_n:][::-1]
    fig, ax = plt.subplots(figsize=(10, 7))
    ax.barh(
        [feat_names[i] if i < len(feat_names) else f"feat_{i}" for i in top_idx][::-1],
        importances[top_idx][::-1],
        color="#4C72B0",
    )
    ax.set_xlabel("Feature Importance (Gini)")
    ax.set_title(f"Top {top_n} Features — Random Forest")
    fig.tight_layout()
    fig.savefig(str(RESULTS_DIR / "rf_feature_importance.png"), dpi=150)
    plt.close(fig)
    logger.info("Saved feature importance -> %s", RESULTS_DIR / "rf_feature_importance.png")

    return clf


# ---------------------------------------------------------------------------
# 2. Isolation Forest (unsupervised anomaly detection)
# ---------------------------------------------------------------------------
def train_isolation_forest(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
    label_encoder: LabelEncoder,        # FIX R5: passed explicitly for safe lookup
) -> IsolationForest:
    """Train an Isolation Forest on normal-only data, evaluate on full test set."""

    # FIX R5: resolve the "normal" label index safely via the encoder,
    # never assume it is always 0 (LabelEncoder sorts alphabetically and
    # the index could change if new classes are added).
    normal_idx = int(label_encoder.transform(["normal"])[0])
    normal_mask = y_train == normal_idx
    X_train_normal = X_train[normal_mask]
    logger.info(
        "Training Isolation Forest on %d normal samples (out of %d total) ...",
        X_train_normal.shape[0], X_train.shape[0],
    )

    iso = IsolationForest(
        n_estimators=200,
        contamination=0.1,  # expected anomaly fraction in production
        max_samples="auto",
        random_state=42,
        n_jobs=-1,
    )
    iso.fit(X_train_normal)

    # -- Evaluate: 1 = normal (inlier), -1 = anomaly (outlier) --
    iso_pred = iso.predict(X_test)
    iso_scores = iso.decision_function(X_test)

    # Map labels: normal -> 1 (inlier), anything else -> -1 (outlier)
    y_binary_true = np.where(y_test == normal_idx, 1, -1)

    tp = int(np.sum((iso_pred == -1) & (y_binary_true == -1)))
    fp = int(np.sum((iso_pred == -1) & (y_binary_true == 1)))
    tn = int(np.sum((iso_pred == 1) & (y_binary_true == 1)))
    fn = int(np.sum((iso_pred == 1) & (y_binary_true == -1)))

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / len(y_test)

    logger.info("Isolation Forest (binary: normal vs anomaly):")
    logger.info("  Accuracy:  %.4f", accuracy)
    logger.info("  Precision: %.4f", precision)
    logger.info("  Recall:    %.4f", recall)
    logger.info("  F1:        %.4f", f1)
    logger.info("  TP=%d  FP=%d  TN=%d  FN=%d", tp, fp, tn, fn)

    iso_metrics = {
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "n_train_normal": int(X_train_normal.shape[0]),
        "n_test": int(X_test.shape[0]),
    }
    (RESULTS_DIR / "iso_metrics.json").write_text(json.dumps(iso_metrics, indent=2))

    # -- Anomaly score distribution plot --
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.hist(
        iso_scores[y_binary_true == 1], bins=60, alpha=0.6, label="Normal", color="#4C72B0",
    )
    ax.hist(
        iso_scores[y_binary_true == -1], bins=60, alpha=0.6, label="Anomaly", color="#DD4444",
    )
    ax.axvline(x=0, color="black", linestyle="--", label="Decision boundary")
    ax.set_xlabel("Anomaly Score (higher = more normal)")
    ax.set_ylabel("Count")
    ax.set_title("Isolation Forest — Anomaly Score Distribution")
    ax.legend()
    fig.tight_layout()
    fig.savefig(str(RESULTS_DIR / "iso_score_distribution.png"), dpi=150)
    plt.close(fig)
    logger.info("Saved score distribution -> %s", RESULTS_DIR / "iso_score_distribution.png")

    return iso


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(description="Train & evaluate SIEM-Lite ML models")
    parser.add_argument("--dataset", default="data/auth_logs_labeled.csv")
    parser.add_argument("--test-size", type=float, default=0.25)
    parser.add_argument("--tfidf-features", type=int, default=200)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    # -- Load data --
    logger.info("Loading dataset from %s ...", args.dataset)
    df = pd.read_csv(args.dataset)
    logger.info("Dataset: %d rows, %d columns", len(df), len(df.columns))
    logger.info("Label distribution:\n%s", df["label"].value_counts().to_string())

    # -- Feature engineering --
    logger.info("Extracting features (structured + TF-IDF) ...")
    featurizer = LogFeaturizer(tfidf_max_features=args.tfidf_features)
    X = featurizer.fit_transform(df)
    logger.info("Feature matrix shape: %s  (sparse, %d nnz)", X.shape, X.nnz)

    # -- Encode labels --
    le = LabelEncoder()
    y = le.fit_transform(df["label"])
    logger.info("Classes: %s", list(le.classes_))

    # -- Train/test split --
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, stratify=y, random_state=args.seed,
    )
    logger.info("Train: %d, Test: %d", X_train.shape[0], X_test.shape[0])

    # -- Train models --
    # FIX R4: featurizer passed as parameter, no module-level global needed
    rf_clf = train_random_forest(X_train, y_train, X_test, y_test, le, featurizer)
    # FIX R5: label_encoder passed so normal index is resolved safely
    iso_clf = train_isolation_forest(X_train, y_train, X_test, y_test, le)

    # -- Serialise --
    joblib.dump(rf_clf, MODELS_DIR / "random_forest.joblib")
    joblib.dump(iso_clf, MODELS_DIR / "isolation_forest.joblib")
    joblib.dump(featurizer, MODELS_DIR / "featurizer.joblib")
    joblib.dump(le, MODELS_DIR / "label_encoder.joblib")
    logger.info("Models saved to %s", MODELS_DIR)

    logger.info("Done. Results in %s", RESULTS_DIR)


if __name__ == "__main__":
    main()