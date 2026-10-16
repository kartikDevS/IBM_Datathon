# M5 Network Witness — Behavioral Anomaly Classification

M5 evaluates streaming network behavior and MQTT transmission dynamics to detect flooding bursts, abnormal timing jitter, and sequence irregularities.

---

## 1. Directory Structure

```
m5_network_witness/
├── dataset_inspection.py   # Audits datasets, checks for missing data & leakage columns
├── feature_extractor.py    # Rolling window behavioral feature extractor (no identity leakage)
├── train_m5.py             # Preprocessing & Random Forest training pipeline
├── evaluate_m5.py          # Detailed evaluation (precision, recall, F1, FPR, confusion matrix)
├── m5_predict.py           # Real-time inference engine outputting standardized JSON events
├── model_card.md           # Formal model documentation, risk analysis, and deployment requirements
└── artifacts/              # Serialized model pipeline (.joblib) and metadata (.json)
```

---

## 2. Dataset Acquisition & Inspection

Neither CICIoMT2024 nor WUSTL-EHMS-2020 are pre-installed in this repository to prevent bloated commits.

To inspect external datasets or run the built-in synthetic verification:
```bash
# Run demonstration inspection on synthetic IoT structures
python -m m5_network_witness.dataset_inspection --demo-inspection

# Inspect an external CSV dataset:
python -m m5_network_witness.dataset_inspection --file data/ciciomt2024.csv --label-col Label
```

---

## 3. Training & Evaluation Workflow

To train the baseline model on synthetic IoT telemetry:
```bash
python -m m5_network_witness.train_m5 --generate-synthetic-baseline
```
This saves:
- `m5_network_witness/artifacts/m5_model_baseline.joblib`
- `m5_network_witness/artifacts/m5_model_baseline_metadata.json`

To evaluate the saved baseline:
```bash
python -m m5_network_witness.evaluate_m5
```

---

## 4. Inference Usage

To run inference from the command line:
```bash
# Demonstrate sample inference with normal features
python -m m5_network_witness.m5_predict

# Custom behavioral input
python -m m5_network_witness.m5_predict --device-id bed7 --features '{"msg_rate": 35.0, "inter_arrival_mean": 0.03, "inter_arrival_std": 0.25, "inter_arrival_min": 0.005, "inter_arrival_max": 1.2, "seq_gap_count": 4.0, "seq_dup_count": 2.0, "payload_bytes_mean": 95.0, "payload_bytes_std": 15.0, "timestamp_drift_mean": 2.1, "timestamp_drift_max": 5.0}'
```

Output adheres strictly to `contracts/m5_output.schema.json`. If the model is absent, status is gracefully reported as `unavailable`.
