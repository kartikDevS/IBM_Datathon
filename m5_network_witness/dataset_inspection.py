"""Dataset Inspection Utility for M5 Network Witness.

Analyzes raw network or IoT security datasets (e.g. CICIoMT2024, WUSTL-EHMS-2020).
Identifies class distributions, missing values, potential data leakage columns,
and session-grouping candidates before modeling.
"""

from __future__ import annotations
import argparse
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
import pandas as pd

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("m5_inspection")

# Known potential data leakage patterns (features that memorize devices/sessions rather than behavior)
LEAKAGE_NAME_PATTERNS = [
    "ip", "src_ip", "dst_ip", "source_ip", "destination_ip",
    "mac", "src_mac", "dst_mac",
    "device_id", "device", "host", "hostname",
    "port", "src_port", "dst_port",
    "flow_id", "id", "timestamp_raw", "filename", "file"
]


def inspect_dataframe(df: pd.DataFrame, label_col: Optional[str] = None) -> Dict[str, Any]:
    """Inspect DataFrame metadata, leakage columns, and candidate features."""
    total_rows, total_cols = df.shape
    columns = list(df.columns)
    
    # Missing values
    null_counts = df.isnull().sum()
    cols_with_nulls = {col: int(cnt) for col, cnt in null_counts.items() if cnt > 0}
    
    # Identify leakage columns
    leakage_candidates = []
    candidate_features = []
    candidate_grouping = []

    for col in columns:
        col_lower = str(col).lower()
        if any(pat in col_lower for pat in LEAKAGE_NAME_PATTERNS):
            leakage_candidates.append(col)
            if any(group_pat in col_lower for group_pat in ["device", "session", "file", "host"]):
                candidate_grouping.append(col)
        elif df[col].dtype in ["float64", "float32", "int64", "int32", "int16"]:
            candidate_features.append(col)

    # Class balance if label_col provided
    class_distribution = {}
    if label_col and label_col in df.columns:
        counts = df[label_col].value_counts()
        total = len(df)
        class_distribution = {
            str(k): {"count": int(v), "ratio": round(float(v) / total, 4)}
            for k, v in counts.items()
        }

    return {
        "total_rows": total_rows,
        "total_columns": total_cols,
        "columns_with_missing_values": cols_with_nulls,
        "leakage_candidates_to_exclude": leakage_candidates,
        "candidate_grouping_columns": candidate_grouping,
        "candidate_numeric_features": candidate_features,
        "class_distribution": class_distribution,
    }


def format_inspection_report(report: Dict[str, Any], source_path: str) -> str:
    lines = [
        "=" * 70,
        f"M5 DATASET INSPECTION REPORT: {source_path}",
        "=" * 70,
        f"Total Samples (Rows):    {report['total_rows']:,}",
        f"Total Attributes (Cols): {report['total_columns']}",
        "",
        "--- Missing Values ---",
    ]
    if report["columns_with_missing_values"]:
        for c, count in report["columns_with_missing_values"].items():
            lines.append(f"  - {c}: {count} missing")
    else:
        lines.append("  No missing values detected.")

    lines.extend([
        "",
        "--- Potential Leakage Columns (Must Exclude from ML Features) ---",
    ])
    if report["leakage_candidates_to_exclude"]:
        for c in report["leakage_candidates_to_exclude"]:
            lines.append(f"  [!] {c} (potential identity memorization / shortcut)")
    else:
        lines.append("  None identified.")

    lines.extend([
        "",
        "--- Candidate Session / Grouping Columns (For GroupShuffleSplit) ---",
    ])
    if report["candidate_grouping_columns"]:
        for c in report["candidate_grouping_columns"]:
            lines.append(f"  [*] {c}")
    else:
        lines.append("  No grouping columns identified. (Warning: Random split risks cross-packet leakage)")

    lines.extend([
        "",
        "--- Candidate Behavioral Features (Numeric) ---",
        f"  Total behavioral features: {len(report['candidate_numeric_features'])}",
        f"  Examples: {report['candidate_numeric_features'][:8]}",
        "",
        "--- Class Distribution ---",
    ])
    if report["class_distribution"]:
        for label, info in report["class_distribution"].items():
            lines.append(f"  Label '{label}': {info['count']:,} samples ({info['ratio']*100:.2f}%)")
    else:
        lines.append("  No label column evaluated.")

    lines.append("=" * 70)
    return "\n".join(lines)


def generate_demo_dataset() -> pd.DataFrame:
    """Generate representative synthetic dataset structure matching typical IoT captures for offline testing."""
    import numpy as np
    np.random.seed(42)
    n = 200
    return pd.DataFrame({
        "device_id": np.random.choice(["bed1", "bed2", "bed3", "bed4"], size=n),
        "src_ip": ["192.168.1.10"] * n,
        "src_port": np.random.randint(1024, 65535, size=n),
        "msg_rate": np.random.uniform(1.0, 5.0, size=n),
        "inter_arrival_mean": np.random.uniform(0.18, 0.25, size=n),
        "inter_arrival_jitter": np.random.uniform(0.005, 0.08, size=n),
        "payload_bytes": np.random.randint(70, 110, size=n),
        "label": np.random.choice(["normal", "suspicious"], size=n, p=[0.8, 0.2])
    })


def main():
    parser = argparse.ArgumentParser(description="M5 Dataset Inspection Utility")
    parser.add_argument("--file", type=str, default=None, help="Path to dataset CSV or Parquet file")
    parser.add_argument("--dir", type=str, default="data", help="Directory to search for datasets")
    parser.add_argument("--label-col", type=str, default="label", help="Target label column (default: label)")
    parser.add_argument("--demo-inspection", action="store_true", help="Run demonstration on synthetic representative structure")
    args = parser.parse_args()

    if args.demo_inspection:
        logger.info("Executing demonstration inspection on synthetic IoT telemetry sample...")
        df = generate_demo_dataset()
        report = inspect_dataframe(df, label_col="label")
        print(format_inspection_report(report, "SYNTHETIC_DEMO_SAMPLE"))
        return

    target_file = None
    if args.file and Path(args.file).exists():
        target_file = Path(args.file)
    else:
        # Search dataset dir
        data_dir = Path(args.dir)
        if data_dir.exists():
            csvs = list(data_dir.glob("*.csv")) + list(data_dir.glob("*.parquet"))
            if csvs:
                target_file = csvs[0]

    if not target_file:
        print("\n" + "=" * 70)
        print("M5 DATASET STATUS: NO BENCHMARK DATASET FOUND IN WORKSPACE")
        print("=" * 70)
        print("Neither CICIoMT2024 nor WUSTL-EHMS-2020 are pre-installed in this directory.")
        print("\nInstructions for Acquiring and Inspecting Benchmark Datasets:")
        print("1. CICIoMT2024 (Canadian Institute for Cybersecurity):")
        print("   - Source: https://www.unb.ca/cic/datasets/iomt-dataset-2024.html")
        print("   - Download authorized healthcare IoT traffic captures (CSV format).")
        print("   - Place extracted CSV into 'data/ciciomt2024/'.")
        print("2. WUSTL-EHMS-2020:")
        print("   - Source: Washington University in St. Louis Healthcare Monitoring Dataset")
        print("   - Place extracted CSV into 'data/wustl_ehms_2020/'.")
        print("\nTo test this inspection pipeline immediately, run:")
        print("  python -m m5_network_witness.dataset_inspection --demo-inspection")
        print("=" * 70 + "\n")
        return

    logger.info("Loading dataset file: %s", target_file)
    df = pd.read_csv(target_file, nrows=50000) if target_file.suffix == ".csv" else pd.read_parquet(target_file)
    report = inspect_dataframe(df, label_col=args.label_col)
    print(format_inspection_report(report, str(target_file)))


if __name__ == "__main__":
    main()
