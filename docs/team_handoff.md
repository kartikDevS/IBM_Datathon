# TessNova Cybersecurity Contribution: Team Lead Integration Handoff

**To:** TessNova System Integration Lead  
**From:** Cybersecurity Module Lead (Kartik)  
**Package:** `kartik-security` / TessNova Security Core  
**Target Environment:** Local Integration Testbed & IBM LinuxONE (s390x)  

---

## 1. Deliverable Summary & Component Directory

| Module Directory | Primary Scripts | Responsibility & Status |
| :--- | :--- | :--- |
| **`contracts/`** | `telemetry.schema.json`<br>`m4_output.schema.json`<br>`m5_output.schema.json`<br>`incident_event.schema.json` | Formal JSON Schemas governing telemetry and detection event exchanges. Fully tested against strict validation suites. |
| **`m4_replay/`** | `replay_detector.py`<br>`mqtt_replay_listener.py`<br>`models.py` | Metadata replay catcher. Identifies duplicates, lower sequences, stale timestamps, and sequence gaps per device. Independent of MQTT transport. |
| **`m5_network_witness/`** | `feature_extractor.py`<br>`train_m5.py`<br>`evaluate_m5.py`<br>`m5_predict.py`<br>`model_card.md` | Behavioral anomaly detector. Rolling window extraction (rate, jitter, payload variance, drift) and Random Forest classifier. Fully audited against data leakage. |
| **`attack_simulator/`** | `normal_sender.py`<br>`attack_spike.py`<br>`attack_stuck.py`<br>`attack_bias.py`<br>`attack_drift.py`<br>`attack_replay.py`<br>`attack_spoof.py`<br>`attack_flood.py` | Standalone synthetic test suite. Supports `--dry-run` and bounded local broker testing. Safe defaults, zero real patient data. |
| **`mqtt_security/`** | `containment.py`<br>`mosquitto.conf.example`<br>`setup_lab.md`<br>`recovery.md` | Dynamic Security administrative wrapper. Idempotent isolation and restoration via `mosquitto_ctrl` with dry-run safety gates and audit logging. |

---

## 2. Installation & Quickstart

### Step 2.1: Python Environment Setup
```bash
# Recommended Python version: 3.11+ (Tested on Python 3.14.3)
python -m venv .venv

# On Linux / LinuxONE:
source .venv/bin/activate

# On Windows:
.venv\Scripts\activate

# Install locked dependencies:
pip install -r requirements.txt
```

### Step 2.2: Environment Configuration
Copy the template and fill in local or broker credentials:
```bash
cp .env.example .env
```

Key environment variables:
```bash
MQTT_BROKER_HOST=localhost
MQTT_BROKER_PORT=1883
DYNSEC_ADMIN_USER=admin
DYNSEC_ADMIN_PASSWORD=your_secure_password
DYNSEC_CLI_PATH=mosquitto_ctrl
```

---

## 3. Running Automated Test Suites

### Run All Unit and Integration Tests:
```bash
pytest -v
```
**Test Coverage Breakdown (26 Tests Passing):**
- `tests/test_schemas.py`: Verifies telemetry, M4, M5, and incident contracts. Rejects legacy floats and booleans.
- `m4_replay/test_replay_detector.py`: Verifies monotonicity, duplicate catch, stale timestamps, clock skew, multi-device isolation, and reset policies.
- `mqtt_security/test_containment.py`: Verifies input validation, injection rejection, dry-run safety, and audit logging.
- `tests/test_integration_local.py`: End-to-end integration of telemetry generator -> M4 -> feature extractor -> M5 -> containment manager.

---

## 4. How the Team Decision Layer Ingests Events

### Telemetry Topic Convention
- **Monitor Telemetry:** `ward/<device_id>/ecg`
- **M4 Output Topic:** `hospital/security/m4_replay`
- **M5 Output Topic:** `hospital/security/m5_network_witness`
- **Incident Escalation:** `hospital/security/incidents`

### M4 Output Schema (`contracts/m4_output.schema.json`)
```json
{
  "device_id": "bed7",
  "detector": "M4",
  "replay_suspected": true,
  "reasons": ["duplicate_sequence", "stale_timestamp"],
  "sequence_number": 101,
  "event_timestamp": 1791389000.0,
  "observed_at": 1791389002.5,
  "schema_version": "1.0"
}
```

### M5 Output Schema (`contracts/m5_output.schema.json`)
```json
{
  "device_id": "bed7",
  "detector": "M5",
  "status": "active",
  "network_suspicion_score": 0.88,
  "model_version": "rf-baseline-v1",
  "reasons": ["high_message_rate_burst", "high_arrival_jitter"],
  "observed_at": 1791389005.0,
  "schema_version": "1.0"
}
```

### Decision Engine Correlation Logic (A1 / A2 Guidance)
1. **Patient Emergency vs. Cyber Attack:**
   - If clinical layer flags arrhythmia (e.g. ECG > 180 bpm), check M4 and M5.
   - If M4 `replay_suspected == false` and M5 `network_suspicion_score < 0.25`: **Prioritize clinical emergency** (real patient).
   - If clinical spike coincides with M4 `replay_suspected == true` or M5 `network_suspicion_score > 0.65`: **Investigate cyber intrusion / replay attack**.
2. **Sensor Fault vs. Cyber Attack:**
   - `attack_stuck` produces flatline ECG with advancing sequence numbers and normal network cadence. Treat as physical sensor/lead failure.

---

## 5. Containment & Remediation API

### Requesting Device Isolation:
```python
from mqtt_security.containment import ContainmentManager

mgr = ContainmentManager(dry_run_default=False)
result = mgr.isolate_device(
    device_id="bed7",
    reason="confirmed_replay_tamper_alert",
    operator="a1_decision_agent"
)
if result["success"]:
    print("Bed 7 disabled in Mosquitto Dynamic Security.")
```

### Restoring Device Post-Remediation:
```python
result = mgr.restore_device(
    device_id="bed7",
    reason="sensor_recalibrated_credentials_rotated",
    operator="team_lead"
)
```

---

## 6. Known Boundaries & Unresolved Dependencies

1. **Persistent MQTT Session Clearing:**
   - Disabling a client via Dynamic Security blocks future authentication and publishes.
   - However, if the client connected with `clean_session=False`, subscription queues in Mosquitto may remain.
   - Team lead must review the recommended administrative session purge sequence in `mqtt_security/test_containment.md`.
2. **Benchmark Datasets:**
   - Raw CICIoMT2024 / WUSTL-EHMS-2020 are not committed. Synthetic feature baselines are trained and tested. If the team acquires the full 10GB dataset, use `dataset_inspection.py` before retraining.
