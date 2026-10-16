# TessNova Cybersecurity Contribution: Test Execution Results

**Execution Date:** October 2026  
**Environment:** Windows 64-bit Workstation, Python 3.14.3, pytest 9.1.1  
**Target Deployment:** IBM LinuxONE (s390x)  
**Total Automated Tests:** 26 Tests Executed | **26 PASSED** | **0 FAILED** | **0 ERRORS**  

---

## 1. Automated Test Suite Summary (`pytest -v`)

```
============================= test session starts =============================
platform win32 -- Python 3.14.3, pytest-9.1.1, pluggy-1.7.0
rootdir: D:\Btech\IBM_Z_Datathon
configfile: pytest.ini
testpaths: tests, m4_replay, mqtt_security
collected 26 items

tests/test_integration_local.py::test_end_to_end_normal_telemetry_flow PASSED     [  3%]
tests/test_integration_local.py::test_end_to_end_replay_attack_detection PASSED   [  7%]
tests/test_integration_local.py::test_end_to_end_flood_anomaly_detection PASSED   [ 11%]
tests/test_integration_local.py::test_end_to_end_containment_execution PASSED    [ 15%]
tests/test_schemas.py::test_telemetry_valid_samples PASSED                         [ 19%]
tests/test_schemas.py::test_telemetry_rejections PASSED                            [ 23%]
tests/test_schemas.py::test_telemetry_rejects_raw_legacy_floats PASSED             [ 26%]
tests/test_schemas.py::test_m4_output_validity PASSED                              [ 30%]
tests/test_schemas.py::test_m5_output_validity PASSED                              [ 34%]
tests/test_schemas.py::test_incident_sample_validity PASSED                        [ 38%]
m4_replay/test_replay_detector.py::test_normal_increasing_sequence PASSED           [ 42%]
m4_replay/test_replay_detector.py::test_duplicate_sequence_number PASSED           [ 46%]
m4_replay/test_replay_detector.py::test_lower_sequence_number PASSED               [ 50%]
m4_replay/test_replay_detector.py::test_stale_timestamp PASSED                     [ 53%]
m4_replay/test_replay_detector.py::test_future_timestamp PASSED                    [ 57%]
m4_replay/test_replay_detector.py::test_decreasing_timestamp_on_higher_seq PASSED [ 61%]
m4_replay/test_replay_detector.py::test_state_not_updated_on_rejected_packet PASSED [ 65%]
m4_replay/test_replay_detector.py::test_multi_device_isolation PASSED              [ 69%]
m4_replay/test_replay_detector.py::test_malformed_json_and_field_validations PASSED [ 73%]
m4_replay/test_replay_detector.py::test_device_reset_workflow PASSED               [ 76%]
mqtt_security/test_containment.py::test_device_id_validation_valid PASSED          [ 80%]
mqtt_security/test_containment.py::test_device_id_validation_rejections PASSED    [ 84%]
mqtt_security/test_containment.py::test_dry_run_isolation_and_audit PASSED        [ 88%]
mqtt_security/test_containment.py::test_live_command_argument_construction PASSED [ 92%]
mqtt_security/test_containment.py::test_restore_command_construction PASSED       [ 96%]
mqtt_security/test_containment.py::test_missing_binary_graceful_handling PASSED   [100%]

============================= 26 passed in 3.13s ==============================
```

---

## 2. Test Category Breakdown

### A. Contract Schema Compliance (`tests/test_schemas.py`)
- **Passed:** Normal sample validation (`normal_message.json`).
- **Passed:** Duplicate sequence sample validation (`duplicate_sequence.json`).
- **Passed:** Stale timestamp sample validation (`stale_timestamp.json`).
- **Passed:** Negative sequence rejection.
- **Passed:** Boolean sequence / boolean ECG rejection.
- **Passed:** Empty device_id rejection.
- **Passed:** Disallowing unexpected / injected command fields.
- **Passed:** Legacy raw scalar float rejection (ensuring raw ECG numbers are not silently treated as valid structured telemetry).
- **Passed:** M4 and M5 event schema compliance.
- **Passed:** Generic incident schema compliance.

### B. M4 Metadata Replay Catcher (`m4_replay/test_replay_detector.py`)
- **Passed:** Monotonic sequence progression.
- **Passed:** Duplicate sequence detection (`duplicate_sequence`).
- **Passed:** Lower/out-of-order sequence detection (`lower_sequence`).
- **Passed:** Stale timestamp detection (> 5.0s age).
- **Passed:** Future timestamp detection (> 2.0s drift).
- **Passed:** Decreasing timestamp on advancing sequence numbers.
- **Passed:** Ensuring trusted sequence state is **NOT** advanced on rejected packets.
- **Passed:** Multi-device isolation (Bed 7 vs. Bed 8 state independence).
- **Passed:** Malformed JSON and type validation rejections.
- **Passed:** Operational device state reset (`reset_device`).

### C. Containment Wrapper Safety (`mqtt_security/test_containment.py`)
- **Passed:** Strict validation of device identifiers.
- **Passed:** Rejection of command injection strings (semicolons, backticks, spaces, `rm -rf`).
- **Passed:** Dry-run execution without subprocess invocation.
- **Passed:** Tamper-evident audit logging to `containment_audit.log`.
- **Passed:** Safe subprocess argument array construction (`shell=False`).
- **Passed:** Graceful handling of missing `mosquitto_ctrl` binary (exit code 127).

### D. End-to-End Local Integration (`tests/test_integration_local.py`)
- **Passed:** Normal telemetry stream yields M4 clean approval and M5 suspicion `< 0.20`.
- **Passed:** Replay scenario flags `duplicate_sequence` in M4.
- **Passed:** Bounded flood stream yields elevated M5 suspicion (`>= 0.65`).
- **Passed:** Full containment isolation and restoration workflow with audit logging.

---

## 3. Simulator Dry-Run Execution Results

All 8 simulator scripts were executed in `--dry-run` mode to confirm safe argument parsing, payload formatting, and rate throttling:
- `python -m attack_simulator.normal_sender --count 2 --dry-run`: **SUCCESS**
- `python -m attack_simulator.attack_spike --count 2 --dry-run`: **SUCCESS**
- `python -m attack_simulator.attack_stuck --count 2 --dry-run`: **SUCCESS**
- `python -m attack_simulator.attack_bias --count 2 --dry-run`: **SUCCESS**
- `python -m attack_simulator.attack_drift --count 2 --dry-run`: **SUCCESS**
- `python -m attack_simulator.attack_replay --count 4 --dry-run`: **SUCCESS**
- `python -m attack_simulator.attack_spoof --count 2 --dry-run`: **SUCCESS**
- `python -m attack_simulator.attack_flood --count 5 --enable-flood-test --dry-run`: **SUCCESS**

---

## 4. Tests Requiring External Resources / Deferred to Target Lab

| Test Type | Requirement | Status | Reason / Deferred Plan |
| :--- | :--- | :--- | :--- |
| **Live Dynamic Security Execution** | Host with `mosquitto_ctrl` and running broker | **Simulated / Mocked** | Mosquitto broker is not installed natively on this Windows workstation. Tested via subprocess mocking, exit code emulation, and dry-run mode. Live execution deferred to target LinuxONE lab. |
| **Full Benchmark Model Training** | 10GB raw CICIoMT2024 / WUSTL-EHMS-2020 dataset | **Synthetic Baseline** | Datasets were not pre-downloaded in workspace. Dataset inspection utility (`dataset_inspection.py`) and synthetic baseline model pipeline (`train_m5.py`) were validated instead. |
| **Network Wiretap / PCAP Verification** | Packet capture interface (tcpdump/Wireshark) | **Application-Layer Observed** | M5 extracts application-layer arrival timestamps and payload sizes directly from MQTT transport. Future packet-level capture deferred to team integration. |

---

## 5. Unresolved Risks & Dependencies

1. **Persistent MQTT Session State:**
   - Mosquitto Dynamic Security `disableClient` revokes authentication.
   - However, persistent subscriptions with `clean_session=False` retain broker queues.
   - Flagged in all containment audit outputs as `persistent_session_cleared: false`.
   - Resolution runbook documented in `mqtt_security/test_containment.md`.
