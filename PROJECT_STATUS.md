# Project Status: TessNova Cybersecurity Contribution

**Project Name:** TessNova — Patient, Sensor, or Hacker?  
**Track/Event:** IBM Z Datathon  
**Author/Role:** Cybersecurity Module Lead (Local Simulation, M4 Replay, M5 Network Witness, Mosquitto Containment)  
**Date:** October 2026  
**Target Environment:** Local test environment (Windows/Linux) & Team Lead Deployment on IBM LinuxONE  

---

## 1. Executive Summary & Workspace Inspection

An exhaustive baseline inspection of the development environment was conducted:

| Item | Status | Details / Notes |
| :--- | :--- | :--- |
| **Workspace Repository** | Clean Initial State | Workspace initialized at repository root. Git initialized. |
| **Python Runtime** | Active (Python 3.14.3) | Standard local Python interpreter available on Windows host. |
| **Virtual Environment** | Created (`.venv`) | Dedicated virtual environment isolated with pip, pytest, paho-mqtt, scikit-learn, pandas, jsonschema, pyyaml, joblib. |
| **Local Mosquitto Broker** | Not Present on Windows Host | Mosquitto broker is not installed natively on this development box. Architecture decoupled to allow offline unit testing, dry-run simulation, and live broker integration on Linux/LinuxONE. |
| **Dynamic Security Plugin** | Pending Target Lab Verification | Mosquitto Dynamic Security (`mosquitto_ctrl`) operations will be managed via a defensive containment wrapper supporting strict dry-run modes, validation, and audit logs. |
| **Benchmark Datasets** | Missing from Repository | CICIoMT2024 / WUSTL-EHMS-2020 are not present in workspace. Dataset inspection tooling and synthetic feature extractor validation will be provided along with acquisition documentation. |

---

## 2. Key Architecture & Scope Boundaries

### Within My Scope (Module Responsibilities)
1. **MQTT Telemetry Contract:** Documented JSON schema for bedside ECG monitor telemetry.
2. **Attack & Fault Simulation Suite:** Standalone, rate-bounded, synthetic generators (Normal, Spike, Stuck, Bias, Drift, Replay, Spoof, Flood).
3. **M4 Replay Detector:** Transport-agnostic metadata replay engine with deterministic clock injection, sequence reset handling, and an MQTT listener.
4. **M5 Network Witness:** Behavior-based feature extractor and Random Forest classification baseline with strict leakage prevention and safe unavailable-model fallbacks.
5. **Mosquitto Security & Containment:** Subprocess-safe containment wrapper for `mosquitto_ctrl`, dry-run mode, and audit logging.
6. **Documentation & Handoff:** Complete integration guides and schemas for the team lead deploying on IBM LinuxONE.

### Out of Scope (Team Integration Layer Responsibilities)
- Central incident correlation decision engine (A1/A2).
- Clinical dashboard UI.
- A3 Evidence Collection Agent and A4 Fleet-Hunting Agent.
- Production broker deployment on IBM LinuxONE infrastructure.

---

## 3. Critical Architectural Assumptions & Security Decisions

1. **Zero-Trust Payloads:** Device identifiers and payload parameters in MQTT messages are treated as untrusted inputs. Under no circumstances are shell commands constructed via string interpolation of MQTT payload contents.
2. **Deterministic & Isolated Testing:** The M4 detector is designed with an injectable clock (`time_fn`) and in-memory device state tracking, ensuring 100% test coverage without requiring a live broker during unit tests.
3. **No Fabricated Data or Predictions:** If a machine learning model artifact is missing or untrained, M5 will explicitly report an `unavailable` status rather than fabricating predictions.
4. **Unresolved Persistent Session Issue:** In prior lab testing, disabling a client under Mosquitto Dynamic Security revoked authorization for new operations, but persistent MQTT sessions and queued subscriptions were not guaranteed to be wiped upon client recreation. This behavior is treated as an **open integration dependency** and documented accordingly.

---

## 4. Work Breakdown & Stage Roadmap

- [x] **Stage 1: Workspace Inspection & Scaffolding** (Environment validation, `.venv`, `.gitignore`, `.env.example`, `config.example.yaml`, `PROJECT_STATUS.md`).
- [ ] **Stage 2: Event Contracts & JSON Schemas** (`telemetry.schema.json`, `m4_output.schema.json`, `m5_output.schema.json`, `incident_event.schema.json`, fixtures, `test_schemas.py`).
- [ ] **Stage 3: M4 Replay Catcher** (`replay_detector.py`, `models.py`, `mqtt_replay_listener.py`, `test_replay_detector.py`).
- [ ] **Stage 4: Attack & Fault Simulator Suite** (`normal_sender.py`, `attack_spike.py`, `attack_stuck.py`, `attack_bias.py`, `attack_drift.py`, `attack_replay.py`, `attack_spoof.py`, `attack_flood.py`, `README.md`).
- [ ] **Stage 5: M5 Network Witness** (`dataset_inspection.py`, `feature_extractor.py`, `train_m5.py`, `evaluate_m5.py`, `m5_predict.py`, `model_card.md`, `README.md`).
- [ ] **Stage 6: Mosquitto Dynamic Security & Containment** (`mosquitto.conf.example`, `setup_lab.md`, `containment.py`, `test_containment.py`, `recovery.md`, `test_containment.md`).
- [ ] **Stage 7: Integration, Testing & Team Handoff** (`test_integration_local.py`, `architecture.md`, `threat_model.md`, `team_handoff.md`, `linuxone_integration.md`, `test_results.md`).
