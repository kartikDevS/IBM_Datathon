"""Evaluation Utility for M5 Network Witness Baseline.

Generates a comprehensive diagnostic report detailing precision, recall, F1,
false-positive rate (FPR), confusion matrix, and domain shift limitations.
"""

from __future__ import annotations
import argparse
import json
import logging
from pathlib import Path
from typing import Optional

import joblib
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, f1_score, precision_score, recall_score

from m5_network_witness.feature_extractor import FEATURE_COLUMNS

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("m5_eval")

ARTIFACTS_DIR = Path(__file__).parent / "artifacts"


def evaluate_model_file(
    model_path: Path,
    metadata_path: Path,
    test_data_path: Optional[Path] = None,
    label_col: str = "label",
):
    if not model_path.exists():
        print(f"\n[EVALUATION BLOCKED] Model artifact not found at: {model_path}")
        print("Train a model first using: python -m m5_network_witness.train_m5 --generate-synthetic-baseline\n")
        return

    # Check for metadata
    if metadata_path.exists():
        with open(metadata_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
    else:
        meta = {"model_version": "unknown", "metrics": {}}

    print("\n" + "=" * 70)
    print("M5 NETWORK WITNESS EVALUATION REPORT")
    print("=" * 70)
    print(f"Model File:          {model_path}")
    print(f"Model Version:       {meta.get('model_version')}")
    print(f"Algorithm:           {meta.get('algorithm')}")

    recorded_metrics = meta.get("metrics", {})
    if recorded_metrics:
        print("\n--- Training Validation Benchmark (Held-out Group Split) ---")
        print(f"Split Strategy:      {recorded_metrics.get('split_strategy')}")
        print(f"Train/Test Samples:  {recorded_metrics.get('train_samples')} / {recorded_metrics.get('test_samples')}")
        print(f"Precision:           {recorded_metrics.get('precision')}")
        print(f"Recall:              {recorded_metrics.get('recall')}")
        print(f"F1-Score:            {recorded_metrics.get('f1_score')}")
        print(f"False Positive Rate: {recorded_metrics.get('false_positive_rate')}")
        print(f"Confusion Matrix:    {recorded_metrics.get('confusion_matrix')}")

    # If test data CSV provided, compute fresh evaluation
    if test_data_path and test_data_path.exists():
        print(f"\n--- Fresh Test Set Evaluation: {test_data_path} ---")
        df_test = pd.read_csv(test_data_path)
        X_test = df_test[FEATURE_COLUMNS]
        y_test = df_test[label_col].astype(int)

        pipeline = joblib.load(model_path)
        y_pred = pipeline.predict(X_test)

        cm = confusion_matrix(y_test, y_pred)
        tn, fp, fn, tp = cm.ravel()
        fpr = float(fp) / float(fp + tn) if (fp + tn) > 0 else 0.0

        print(f"Fresh Precision:     {precision_score(y_test, y_pred, zero_division=0):.4f}")
        print(f"Fresh Recall:        {recall_score(y_test, y_pred, zero_division=0):.4f}")
        print(f"Fresh F1-Score:      {f1_score(y_test, y_pred, zero_division=0):.4f}")
        print(f"False Positive Rate: {fpr:.4f}")
        print(f"Confusion Matrix:    TN={tn}, FP={fp}, FN={fn}, TP={tp}")

    print("\n--- Critical Limitations & Risk Notes ---")
    print("1. Accuracy Alone is Misleading: In telemetry monitoring with imbalanced traffic,")
    print("   accuracy masks false alarms. Precision and False Positive Rate (FPR) must govern.")
    print("2. Domain Shift Risk: Models fitted on synthetic traffic or wired testbeds degrade")
    print("   when encountering hospital Wi-Fi jitter, roaming handoffs, or clinical multi-leads.")
    print("3. Adversarial Evasion: Attackers throttling their message rates below normal bounds")
    print("   will not be caught by rate features alone; pairing with M4 sequence verification is essential.")
    print("=" * 70 + "\n")


def main():
    parser = argparse.ArgumentParser(description="Evaluate M5 Model Artifact")
    parser.add_argument(
        "--model",
        default=str(ARTIFACTS_DIR / "m5_model_baseline.joblib"),
        help="Path to joblib model artifact",
    )
    parser.add_argument(
        "--metadata",
        default=str(ARTIFACTS_DIR / "m5_model_baseline_metadata.json"),
        help="Path to metadata json",
    )
    parser.add_argument("--test-file", default=None, help="Optional test dataset CSV")
    args = parser.parse_args()

    evaluate_model_file(
        model_path=Path(args.model),
        metadata_path=Path(args.metadata),
        test_data_path=Path(args.test_file) if args.test_file else None,
    )


if __name__ == "__main__":
    main()
