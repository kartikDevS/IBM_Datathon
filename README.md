# TessNova — Patient, Sensor, or Hacker?
## Modular Cybersecurity & Diagnostic Witness Contribution for the IBM Z Datathon

This repository contains the complete cybersecurity contribution for **TessNova**, an ICU bedside monitor simulation designed for integration and deployment on **IBM LinuxONE**.

---

## 1. System Overview

In a connected hospital intensive care unit (ICU), abnormal telemetry can originate from three distinct sources:
1. **The Patient:** A legitimate cardiac event or medical emergency requiring immediate clinical intervention.
2. **The Sensor:** A physical hardware malfunction, electrode disconnection, or calibration drift.
3. **The Hacker:** A malicious cyber intrusion, replay attack, data manipulation, or denial-of-service flood.

This subsystem provides independent, modular cybersecurity witnesses that feed structured detection evidence to the team's central decision engine:
- **Telemetry Contract:** Proposed strict JSON telemetry schema for bedside ECG monitors.
- **Attack & Fault Simulators:** 8 standalone, rate-bounded scenarios for authorized testing (`normal`, `spike`, `stuck`, `bias`, `drift`, `replay`, `spoof`, `flood`).
- **M4 Replay Catcher:** Transport-agnostic metadata replay engine that evaluates sequence monotonicity, freshness, and duplicates per-device without advancing state on rejected packets.
- **M5 Network Witness:** Leakage-free behavioral feature extractor and Random Forest classifier that detects traffic bursts, timing jitter, and queue drift.
- **Mosquitto Containment Wrapper:** Subprocess-safe administrative wrapper around `mosquitto_ctrl` with dry-run mode, input sanitization, and tamper-evident audit logging.

---

## 2. Repository Structure

```
.
├── README.md                           # Master project guide & demo runbook
├── PROJECT_STATUS.md                   # Workspace audit, dependencies, and implementation status
├── requirements.txt                    # Locked Python dependencies
├── pytest.ini                          # Automated test discovery configuration
├── .gitignore                          # Standard git ignore (secrets, venv, caches)
├── .env.example                        # Template for environment variables and secrets
├── config/
│   └── config.example.yaml             # Central configuration template
├── contracts/                          # Formal JSON Schemas
│   ├── telemetry.schema.json
│   ├── m4_output.schema.json
│   ├── m5_output.schema.json
│   └── incident_event.schema.json
├── samples/                            # Standard JSON fixtures
│   ├── normal_message.json
│   ├── duplicate_sequence.json
│   ├── stale_timestamp.json
│   └── sample_incident.json
├── attack_simulator/                   # Synthetic attack & fault publishers
│   ├── README.md
│   ├── common.py
│   ├── normal_sender.py
│   ├── attack_spike.py
│   ├── attack_stuck.py
│   ├── attack_bias.py
│   ├── attack_drift.py
│   ├── attack_replay.py
│   ├── attack_spoof.py
│   └── attack_flood.py
├── m4_replay/                          # M4 Metadata Replay Catcher
│   ├── models.py
│   ├── replay_detector.py
│   ├── mqtt_replay_listener.py
│   └── test_replay_detector.py
├── m5_network_witness/                 # M5 Behavioral Anomaly Witness
│   ├── dataset_inspection.py
│   ├── feature_extractor.py
│   ├── train_m5.py
│   ├── evaluate_m5.py
│   ├── m5_predict.py
│   ├── model_card.md
│   ├── README.md
│   └── artifacts/                      # Serialized model (.joblib) & metadata (.json)
├── mqtt_security/                      # Broker Security & Containment
│   ├── mosquitto.conf.example
│   ├── setup_lab.md
│   ├── containment.py
│   ├── test_containment.py
│   ├── test_containment.md
│   ├── recovery.md
│   └── containment_audit.log
├── tests/                              # Integration & Schema Tests
│   ├── test_schemas.py
│   └── test_integration_local.py
└── docs/                               # Architecture & Handoff Documentation
    ├── architecture.md
    ├── threat_model.md
    ├── team_handoff.md
    ├── linuxone_integration.md
    └── test_results.md
```

---

## 3. Quick Setup

```bash
# 1. Create and activate virtual environment
python -m venv .venv

# On Linux / LinuxONE:
source .venv/bin/activate
# On Windows:
.venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run all automated tests (26 passing tests)
pytest -v
```

---

## 4. End-to-End Demonstration Runbook

Follow this 10-step sequence to demonstrate the cybersecurity contribution:

### Step 1: Start Local Mosquitto Broker (or use Dry-Run Mode)
```bash
# In target lab with Mosquitto installed:
mosquitto -c mqtt_security/mosquitto.conf.example -v
# (If offline or without broker, all components support standalone dry-run)
```

### Step 2: Start Normal Synthetic Bed 7 Telemetry
```bash
python -m attack_simulator.normal_sender --device-id bed7 --count 10 --interval 0.5 --dry-run
```

### Step 3: Run M4 Replay Catcher on Normal Telemetry
```bash
python -m m4_replay.mqtt_replay_listener --local-test
```
*Observation:* Normal monotonic packets receive `replay_suspected: false` with reasons `["normal"]`.

### Step 4: Run Replay Attack Scenario
```bash
python -m attack_simulator.attack_replay --device-id bed7 --mode verbatim --count 10 --dry-run
```
*Observation:* M4 flags `duplicate_sequence` and `stale_timestamp`, refusing to advance trusted sequence state.

### Step 5: Run Sensor Fault vs Cyber Tamper Scenario
```bash
# Hardware freeze:
python -m attack_simulator.attack_stuck --device-id bed7 --count 5 --dry-run
# Waveform tampering:
python -m attack_simulator.attack_spike --device-id bed7 --count 5 --dry-run
```

### Step 6: Run M5 Network Witness Inference
```bash
python -m m5_network_witness.m5_predict --device-id bed7 --features '{"msg_rate": 35.0, "inter_arrival_mean": 0.03, "inter_arrival_std": 0.18, "inter_arrival_min": 0.005, "inter_arrival_max": 1.2, "seq_gap_count": 3.0, "seq_dup_count": 1.0, "payload_bytes_mean": 95.0, "payload_bytes_std": 12.0, "timestamp_drift_mean": 1.8, "timestamp_drift_max": 4.5}'
```
*Observation:* Returns structured event with elevated suspicion score (`> 0.70`).

### Step 7: Demonstrate Containment in Dry-Run Mode
```bash
python -m mqtt_security.containment --action isolate --device-id bed7 --reason "m4_replay_confirmed" --dry-run
```
*Observation:* Simulates `disableClient bed7` safely and writes record to `containment_audit.log`.

### Step 8: Execute Containment Against Lab Client (Live Mode)
```bash
python -m mqtt_security.containment --action isolate --device-id bed7 --live --reason "m4_replay_confirmed"
```

### Step 9: Verify Broker Operational Stability
Verify that sibling monitors (e.g. `bed8`) continue publishing without disruption and broker remains active.

### Step 10: Restore Device & Verify Remediation
```bash
python -m mqtt_security.containment --action restore --device-id bed7 --live --reason "remediation_complete"
```

---

## 5. Documentation Links

- [System Architecture](file:///d:/Btech/IBM_Z_Datathon/docs/architecture.md)
- [Threat Model (STRIDE / MITRE)](file:///d:/Btech/IBM_Z_Datathon/docs/threat_model.md)
- [Team Lead Handoff Guide](file:///d:/Btech/IBM_Z_Datathon/docs/team_handoff.md)
- [IBM LinuxONE (s390x) Integration](file:///d:/Btech/IBM_Z_Datathon/docs/linuxone_integration.md)
- [Test Execution Results](file:///d:/Btech/IBM_Z_Datathon/docs/test_results.md)
- [M5 Model Card](file:///d:/Btech/IBM_Z_Datathon/m5_network_witness/model_card.md)
- [Containment & Session Analysis](file:///d:/Btech/IBM_Z_Datathon/mqtt_security/test_containment.md)
- [Device Recovery Runbook](file:///d:/Btech/IBM_Z_Datathon/mqtt_security/recovery.md)
