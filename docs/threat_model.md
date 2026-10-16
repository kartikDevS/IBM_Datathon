# TessNova Threat Model & Security Posture

**Framework:** STRIDE & MITRE ATT&CK for Enterprise / ICS / IoMT  
**Scope:** Bedside Telemetry Monitoring, MQTT Transport, Anomaly Detection, Dynamic Security Containment  

---

## 1. Threat Actors & Assumptions

| Threat Actor | Capabilities & Access | Motivation |
| :--- | :--- | :--- |
| **Rogue Device / Attacker on Hospital LAN** | Network tap, packet sniffing, packet replaying, broker port access. No broker root privileges. | Induce panic, trigger false alarms, mask real clinical emergencies. |
| **Compromised Sensor Firmware** | Can alter reported ECG readings, manipulate timestamps, or crash. | Sabotage medical device telemetry, generate stealth drift. |
| **Malicious Operator / Compromised Agent** | Access to containment CLI commands or decision engine feeds. | Illegitimately isolate legitimate life-support monitors. |

---

## 2. STRIDE Analysis & Defense Posture

### A. Spoofing Identity
- **Threat:** Attacker modifies payload `"device_id": "bed7"` to impersonate Bed 7 while publishing from Bed 99.
- **Defense:**
  - Mosquitto Dynamic Security enforces **Topic ACLs** at the broker layer.
  - A client authenticated as `bed99` is prohibited by broker ACL from publishing to `ward/bed7/ecg`.
  - The telemetry contract explicitly acknowledges that payload JSON fields are untrusted; identity is established strictly by MQTT client authentication.

### B. Tampering with Data
- **Threat:** Attacker injects sudden spikes (`attack_spike`), constant bias (`attack_bias`), or gradual drift (`attack_drift`) into ECG waveforms.
- **Defense:**
  - Clinical alarms flag sudden physiological changes.
  - M4 and M5 evaluate whether clinical alarms are accompanied by cyber/network anomalies (e.g., sequence jumps, payload changes, traffic bursts).
  - This allows the central decision layer to differentiate a real patient arrhythmia from sensor tampering.

### C. Repudiation
- **Threat:** Containment actions or malicious disconnection cannot be traced to an operator.
- **Defense:**
  - `mqtt_security/containment.py` records every action, timestamp (epoch and ISO 8601), operator ID, target device, return code, and reason into `mqtt_security/containment_audit.log`.

### D. Information Disclosure
- **Threat:** Eavesdropping on cleartext clinical telemetry on the local network.
- **Defense:**
  - Local testbed supports dry-run/TLS flags. Production deployment on IBM LinuxONE mandates TLS 1.3 listener on port 8883 with mutual certificate authentication (mTLS).

### E. Denial of Service (DoS)
- **Threat:** Attacker floods broker with thousands of messages per second (`attack_flood`), exhausting broker buffers or saturating the decision engine.
- **Defense:**
  - Mosquitto `max_queued_messages` caps in-memory queue depth.
  - M5 Network Witness identifies flood bursts within rolling windows (`msg_rate > 20 msgs/s`, arrival delta variance) and generates an elevated suspicion alert (`> 0.65`).

### F. Elevation of Privilege & Remote Command Execution
- **Threat:** Malicious payload strings (e.g. `{"device_id": "bed7; rm -rf /"}`) passed to containment scripts execute arbitrary shell commands.
- **Defense:**
  - `validate_device_id` enforces strict regex `^[a-zA-Z0-9_\-]{1,64}$`, rejecting any semicolons, backticks, spaces, or control characters.
  - `subprocess.run` is invoked **strictly with `shell=False`** and argument lists, eliminating shell interpolation vulnerabilities.

---

## 3. MITRE ATT&CK for IoT / Healthcare Mapping

| Technique ID | Technique Name | TessNova Context | Module Detection / Mitigation |
| :--- | :--- | :--- | :--- |
| **T0856** | Spoof Reporting Message | Replaying old ICU telemetry packets | **M4 Replay Catcher:** Flags `duplicate_sequence` and `stale_timestamp`. |
| **T0814** | Denial of Service | Flooding MQTT broker with messages | **M5 Network Witness:** Identifies burst rate, timing jitter, and queue drift. |
| **T0830** | Adversary-in-the-Middle | Altering sensor readings in transit | **Broker ACLs & TLS:** Blocks unauthorized topic injection. |
| **T0828** | Loss of Availability | Disabling valid sensor accounts | **Containment Safety:** Requires human-in-the-loop authorization; dry-run default. |

---

## 4. Open Threat Vector: Persistent MQTT Session Retention

- **Vulnerability:** Disabling a client via Mosquitto Dynamic Security revokes authentication for future connections, but existing persistent subscriptions and undelivered QoS 1 messages in the persistence database (`mosquitto.db`) may persist.
- **Mitigation Strategy:** Documented in `mqtt_security/test_containment.md`. Administrative cleanup clients connect with `clean_session=True` to explicitly flush the broker's session table for the quarantined device.
