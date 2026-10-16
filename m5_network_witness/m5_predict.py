"""Inference Engine for M5 Network Witness.

Computes behavioral suspicion scores from streaming feature records.
Strictly returns status='unavailable' with null suspicion score if the model artifact
is missing or features are incomplete—never fabricating predictions.
"""

from __future__ import annotations
import argparse
import json
import logging
from pathlib import Path
import time
from typing import Dict, List, Optional, Any

import joblib
import pandas as pd

from m5_network_witness.feature_extractor import FEATURE_COLUMNS

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("m5_predict")

DEFAULT_MODEL_PATH = Path(__file__).parent / "artifacts" / "m5_model_baseline.joblib"
DEFAULT_META_PATH = Path(__file__).parent / "artifacts" / "m5_model_baseline_metadata.json"


class NetworkWitnessInference:
    """Predicts traffic anomaly probabilities using an audited local scikit-learn pipeline."""

    def __init__(
        self,
        model_path: Optional[Path] = None,
        metadata_path: Optional[Path] = None,
        suspicion_threshold: float = 0.70,
    ):
        self.model_path = model_path or DEFAULT_MODEL_PATH
        self.metadata_path = metadata_path or DEFAULT_META_PATH
        self.suspicion_threshold = suspicion_threshold
        self.pipeline = None
        self.model_version = "unavailable"
        self._load_model()

    def _load_model(self):
        if self.model_path.exists():
            try:
                self.pipeline = joblib.load(self.model_path)
                if self.metadata_path.exists():
                    with open(self.metadata_path, "r", encoding="utf-8") as f:
                        meta = json.load(f)
                        self.model_version = meta.get("model_version", "baseline-v1")
                else:
                    self.model_version = "baseline-v1"
                logger.info("Loaded M5 model artifact: %s (version: %s)", self.model_path, self.model_version)
            except Exception as exc:
                logger.error("Failed to load model artifact at %s: %s", self.model_path, exc)
                self.pipeline = None
                self.model_version = "unavailable"
        else:
            logger.warning("No model artifact found at %s. M5 inference will report status 'unavailable'.", self.model_path)
            self.pipeline = None
            self.model_version = "unavailable"

    def predict(self, device_id: str, features: Dict[str, float]) -> Dict[str, Any]:
        """Generate structured M5 detection event."""
        now = time.time()

        if self.pipeline is None:
            return {
                "device_id": device_id,
                "detector": "M5",
                "status": "unavailable",
                "network_suspicion_score": None,
                "model_version": self.model_version,
                "reasons": ["model_artifact_not_found"],
                "observed_at": now,
                "schema_version": "1.0",
            }

        # Check for missing required features
        missing = [f for f in FEATURE_COLUMNS if f not in features]
        if missing:
            return {
                "device_id": device_id,
                "detector": "M5",
                "status": "degraded",
                "network_suspicion_score": None,
                "model_version": self.model_version,
                "reasons": [f"missing_features_{','.join(missing[:3])}"],
                "observed_at": now,
                "schema_version": "1.0",
            }

        # Prepare 1-row DataFrame matching trained column order
        df_in = pd.DataFrame([{col: features[col] for col in FEATURE_COLUMNS}])

        try:
            # Predict probability of the anomalous/suspicious class (index 1)
            prob = float(self.pipeline.predict_proba(df_in)[0, 1])
            prob = round(prob, 4)

            reasons: List[str] = []
            if prob >= self.suspicion_threshold:
                if features.get("msg_rate", 0) > 10.0:
                    reasons.append("high_message_rate_burst")
                if features.get("inter_arrival_std", 0) > 0.15:
                    reasons.append("high_arrival_jitter")
                if features.get("seq_gap_count", 0) > 0:
                    reasons.append("sequence_discontinuity")
                if features.get("seq_dup_count", 0) > 0:
                    reasons.append("sequence_duplication_cluster")

            return {
                "device_id": device_id,
                "detector": "M5",
                "status": "active",
                "network_suspicion_score": prob,
                "model_version": self.model_version,
                "reasons": reasons,
                "observed_at": now,
                "schema_version": "1.0",
            }
        except Exception as exc:
            logger.error("Inference exception: %s", exc)
            return {
                "device_id": device_id,
                "detector": "M5",
                "status": "degraded",
                "network_suspicion_score": None,
                "model_version": self.model_version,
                "reasons": [f"inference_error_{type(exc).__name__}"],
                "observed_at": now,
                "schema_version": "1.0",
            }


def main():
    parser = argparse.ArgumentParser(description="M5 Network Witness Inference Utility")
    parser.add_argument("--device-id", default="bed7", help="Target bedside device ID (default: bed7)")
    parser.add_argument("--features", type=str, default=None, help="JSON string with behavioral features")
    parser.add_argument("--model", type=str, default=str(DEFAULT_MODEL_PATH), help="Path to joblib model")
    args = parser.parse_args()

    engine = NetworkWitnessInference(model_path=Path(args.model))

    if args.features:
        feat_dict = json.loads(args.features)
        result = engine.predict(device_id=args.device_id, features=feat_dict)
        print(json.dumps(result, indent=2))
    else:
        # Example feature demonstration
        sample_normal = {
            "msg_rate": 2.0,
            "inter_arrival_mean": 0.5,
            "inter_arrival_std": 0.01,
            "inter_arrival_min": 0.45,
            "inter_arrival_max": 0.55,
            "seq_gap_count": 0.0,
            "seq_dup_count": 0.0,
            "payload_bytes_mean": 85.0,
            "payload_bytes_std": 2.0,
            "timestamp_drift_mean": 0.02,
            "timestamp_drift_max": 0.04,
        }
        res = engine.predict(device_id=args.device_id, features=sample_normal)
        print("\nM5 Inference output for sample normal vector:")
        print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
