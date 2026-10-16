"""Baseline Training Pipeline for M5 Network Witness.

Trains a Random Forest anomaly classification model using scikit-learn.
Strictly adheres to ML engineering best practices:
- Preprocessing fit on training split ONLY.
- Excludes identity proxies to avoid label leakage.
- Saves model pipeline and metadata safely via joblib.
"""

from __future__ import annotations
import argparse
import json
import logging
from pathlib import Path
import time
from typing import Dict, Any, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import classification_report, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import GroupShuffleSplit, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from m5_network_witness.feature_extractor import FEATURE_COLUMNS

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("m5_train")

ARTIFACTS_DIR = Path(__file__).parent / "artifacts"


def generate_synthetic_training_data(n_samples: int = 1200, random_state: int = 42) -> pd.DataFrame:
    """Generate representative synthetic behavioral feature dataset for offline baseline training.
    
    Simulates:
    - Normal bedside telemetry (steady 2 Hz rate, low jitter, small payload, zero gaps).
    - Network flood / burst attack (high rate, abnormal inter-arrival jitter, packet gaps).
    """
    np.random.seed(random_state)
    n_normal = int(n_samples * 0.75)
    n_attack = n_samples - n_normal

    # Devices to simulate session/device groupings
    devices = [f"bed{i}" for i in range(1, 11)]

    # Normal traffic dynamics
    normal_data = {
        "device_group": np.random.choice(devices[:7], size=n_normal),
        "msg_rate": np.random.normal(2.0, 0.2, size=n_normal).clip(1.0, 3.5),
        "inter_arrival_mean": np.random.normal(0.50, 0.05, size=n_normal).clip(0.3, 0.7),
        "inter_arrival_std": np.random.exponential(0.02, size=n_normal).clip(0.001, 0.08),
        "inter_arrival_min": np.random.uniform(0.42, 0.48, size=n_normal),
        "inter_arrival_max": np.random.uniform(0.52, 0.60, size=n_normal),
        "seq_gap_count": np.zeros(n_normal),
        "seq_dup_count": np.zeros(n_normal),
        "payload_bytes_mean": np.random.normal(88.0, 3.0, size=n_normal),
        "payload_bytes_std": np.random.exponential(1.5, size=n_normal),
        "timestamp_drift_mean": np.random.normal(0.02, 0.01, size=n_normal).clip(0.001, 0.05),
        "timestamp_drift_max": np.random.normal(0.05, 0.02, size=n_normal).clip(0.01, 0.1),
        "label": 0,  # Normal
    }

    # Attack / Anomaly traffic dynamics
    attack_data = {
        "device_group": np.random.choice(devices[7:], size=n_attack),
        "msg_rate": np.random.uniform(15.0, 45.0, size=n_attack),
        "inter_arrival_mean": np.random.uniform(0.02, 0.08, size=n_attack),
        "inter_arrival_std": np.random.uniform(0.10, 0.45, size=n_attack),
        "inter_arrival_min": np.random.uniform(0.001, 0.01, size=n_attack),
        "inter_arrival_max": np.random.uniform(0.8, 2.5, size=n_attack),
        "seq_gap_count": np.random.poisson(2.5, size=n_attack),
        "seq_dup_count": np.random.poisson(1.2, size=n_attack),
        "payload_bytes_mean": np.random.normal(120.0, 25.0, size=n_attack),
        "payload_bytes_std": np.random.uniform(5.0, 30.0, size=n_attack),
        "timestamp_drift_mean": np.random.exponential(1.5, size=n_attack).clip(0.2, 10.0),
        "timestamp_drift_max": np.random.exponential(4.0, size=n_attack).clip(1.0, 20.0),
        "label": 1,  # Suspicious / Anomalous
    }

    df_norm = pd.DataFrame(normal_data)
    df_att = pd.DataFrame(attack_data)
    df = pd.concat([df_norm, df_att], ignore_index=True).sample(frac=1.0, random_state=random_state)
    return df


def train_baseline_pipeline(
    df: pd.DataFrame,
    label_col: str = "label",
    group_col: Optional[str] = "device_group",
    test_size: float = 0.25,
    random_state: int = 42,
    model_version: str = "rf-baseline-v1",
) -> Tuple[Pipeline, Dict[str, Any]]:
    """Train Random Forest baseline with strict train/test isolation."""
    X = df[FEATURE_COLUMNS]
    y = df[label_col].astype(int)

    # Grouped vs Stratified Split
    if group_col and group_col in df.columns:
        logger.info("Splitting dataset using GroupShuffleSplit on '%s' to prevent cross-device leakage...", group_col)
        gss = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=random_state)
        train_idx, test_idx = next(gss.split(X, y, groups=df[group_col]))
        X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
        y_train, y_test = y.iloc[train_idx], y.iloc[test_idx]
        split_strategy = f"GroupShuffleSplit (grouped by {group_col})"
    else:
        logger.warning("No grouping column provided. Using Stratified split (note: risks correlation leakage if packets from same flow).")
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state, stratify=y
        )
        split_strategy = "StratifiedShuffleSplit"

    # Define Pipeline: Imputer -> Scaler -> RandomForest
    pipeline = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
            (
                "classifier",
                RandomForestClassifier(
                    n_estimators=100,
                    max_depth=6,
                    class_weight="balanced",
                    random_state=random_state,
                    n_jobs=-1,
                ),
            ),
        ]
    )

    # Fit pipeline on training data ONLY
    logger.info("Fitting preprocessing and Random Forest classifier on %d training samples...", len(X_train))
    pipeline.fit(X_train, y_train)

    # Evaluate on held-out test data
    y_pred = pipeline.predict(X_test)
    y_prob = pipeline.predict_proba(X_test)[:, 1]

    cm = confusion_matrix(y_test, y_pred)
    # Calculate False Positive Rate (FPR = FP / (FP + TN))
    tn, fp, fn, tp = cm.ravel()
    fpr = float(fp) / float(fp + tn) if (fp + tn) > 0 else 0.0

    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)

    metrics = {
        "precision": round(float(prec), 4),
        "recall": round(float(rec), 4),
        "f1_score": round(float(f1), 4),
        "false_positive_rate": round(fpr, 4),
        "confusion_matrix": {
            "true_negative": int(tn),
            "false_positive": int(fp),
            "false_negative": int(fn),
            "true_positive": int(tp),
        },
        "train_samples": int(len(X_train)),
        "test_samples": int(len(X_test)),
        "split_strategy": split_strategy,
    }

    metadata = {
        "model_version": model_version,
        "algorithm": "RandomForestClassifier(n_estimators=100, max_depth=6, class_weight='balanced')",
        "feature_columns": FEATURE_COLUMNS,
        "metrics": metrics,
        "created_at_epoch": time.time(),
        "random_seed": random_state,
    }

    return pipeline, metadata


def save_artifacts(pipeline: Pipeline, metadata: Dict[str, Any], output_prefix: str = "m5_model_baseline"):
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    model_path = ARTIFACTS_DIR / f"{output_prefix}.joblib"
    meta_path = ARTIFACTS_DIR / f"{output_prefix}_metadata.json"

    logger.info("Saving fitted model pipeline to %s", model_path)
    joblib.dump(pipeline, model_path)

    logger.info("Saving training metadata to %s", meta_path)
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)


def main():
    parser = argparse.ArgumentParser(description="Train M5 Network Witness Baseline")
    parser.add_argument("--data-file", type=str, default=None, help="Path to input features CSV")
    parser.add_argument("--label-col", default="label", help="Target label column (default: label)")
    parser.add_argument("--group-col", default="device_group", help="Session or device grouping column")
    parser.add_argument(
        "--generate-synthetic-baseline",
        action="store_true",
        help="Generate synthetic IoT feature baseline and train baseline model artifact",
    )
    args = parser.parse_args()

    if args.data_file and Path(args.data_file).exists():
        logger.info("Loading training data from %s", args.data_file)
        df = pd.read_csv(args.data_file)
    elif args.generate_synthetic_baseline:
        logger.info("Generating synthetic training baseline data...")
        df = generate_synthetic_training_data()
    else:
        print("\n[M5 TRAIN] No input dataset specified.")
        print("To generate and train on a synthetic baseline dataset, run with:")
        print("  python -m m5_network_witness.train_m5 --generate-synthetic-baseline\n")
        return

    pipeline, metadata = train_baseline_pipeline(df, label_col=args.label_col, group_col=args.group_col)
    save_artifacts(pipeline, metadata)

    print("\n" + "=" * 60)
    print("M5 BASELINE MODEL TRAINING COMPLETED")
    print("=" * 60)
    print(f"Model Version:          {metadata['model_version']}")
    print(f"Features:               {len(metadata['feature_columns'])} features")
    print(f"Split Strategy:         {metadata['metrics']['split_strategy']}")
    print(f"Test Precision:         {metadata['metrics']['precision']}")
    print(f"Test Recall:            {metadata['metrics']['recall']}")
    print(f"Test F1-Score:          {metadata['metrics']['f1_score']}")
    print(f"False Positive Rate:    {metadata['metrics']['false_positive_rate']}")
    print(f"Confusion Matrix:       {metadata['metrics']['confusion_matrix']}")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
