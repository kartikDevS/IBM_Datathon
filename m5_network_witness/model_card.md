# M5 Network Witness Model Card

## 1. Model Details
- **Model Name:** M5 Network Witness Baseline Classifier
- **Model Version:** `rf-baseline-v1`
- **Architecture:** Random Forest Classifier (`n_estimators=100`, `max_depth=6`, `class_weight='balanced'`) wrapped in an isolated `SimpleImputer` and `StandardScaler` pipeline.
- **Serialization Format:** Python `joblib` file (`.joblib`), versioned alongside JSON metadata.
- **Primary Function:** Estimates the probability that an IoT bedside telemetry stream exhibits anomalous, disruptive, or adversarial network dynamics (e.g., flooding bursts, abnormal packet timing jitter, sequence discontinuities).

---

## 2. Intended Use
- **Advisory Cyber Signal:** Intended as an asynchronous evidentiary signal delivered to the central TessNova correlation decision engine.
- **Scope of Advice:** Differentiates steady hospital monitoring cadence from burst attacks, DoS flooding, or high-jitter anomalies.
- **Non-Autonomous:** M5 **never** triggers device containment, network isolation, or alarm silencing autonomously.

---

## 3. Out-of-Scope & Prohibited Use
- **Clinical Diagnosis:** M5 analyzes **telemetry transmission dynamics**, NOT physiological cardiac rhythms. It must never be used to diagnose arrhythmias, cardiac arrest, or patient medical conditions.
- **Identity Enforcement:** M5 does not authenticate publishers. Topic ACLs and TLS certificates must enforce authentication.
- **Stand-alone Quarantine Authority:** A high M5 suspicion score must not trigger automated clinical monitor disconnection without human-in-the-loop validation.

---

## 4. Feature Space & Data Leakage Prevention

### Explicitly Excluded Identity Proxies (Zero-Tolerance Leakage Rule)
To prevent the classifier from memorizing specific hardware or testbed topologies, the following attributes are **strictly excluded**:
- IP addresses (source/destination)
- MAC addresses
- Device identifiers (`device_id`)
- MQTT topic names / URIs
- Network interface or capture filenames
- Raw sequential packet IDs

### Included Behavioral Features (11 Attributes)
| Feature Name | Description | Rationale |
| :--- | :--- | :--- |
| `msg_rate` | Messages per second in window | Detects high-volume flood and DoS bursts. |
| `inter_arrival_mean` | Mean arrival interval (sec) | Measures transmission cadence. |
| `inter_arrival_std` | Standard deviation of arrival interval | Measures transmission jitter / network instability. |
| `inter_arrival_min` | Minimum inter-packet delta | Flags micro-bursting. |
| `inter_arrival_max` | Maximum inter-packet delta | Flags dropouts / transmission stalling. |
| `seq_gap_count` | Number of non-monotonic sequence jumps | Flags packet loss or out-of-order injection. |
| `seq_dup_count` | Number of duplicate sequence numbers | Flags replay attempts / retry storms. |
| `payload_bytes_mean` | Average payload size in bytes | Detects payload expansion attacks. |
| `payload_bytes_std` | Standard deviation of payload sizes | Detects irregular payload padding. |
| `timestamp_drift_mean`| Mean wall-clock vs. payload timestamp diff | Flags clock desynchronization or stale data. |
| `timestamp_drift_max` | Maximum observed timestamp drift | Flags severe timestamp manipulation. |

---

## 5. Training & Validation Methodology
- **Pre-Processing Ordering:** Preprocessing transformers (`SimpleImputer`, `StandardScaler`) are fit **strictly on training splits only** to prevent data snooping.
- **Grouping Strategy:** Datasets containing multiple devices or sessions are partitioned using `GroupShuffleSplit` on device/session identifiers. This ensures no packet from a test device was seen during training.
- **Class Balancing:** `class_weight='balanced'` is enforced to compensate for the overwhelming predominance of normal traffic in healthcare settings.

---

## 6. Performance & Risk Trade-Offs

### False-Positive Rate (FPR) vs. False-Negative Rate (FNR)
- In ICU environments, **False Alarms** create alarm fatigue and may cause unnecessary diagnostic disruption.
- Consequently, precision and false-positive rates take precedence over raw accuracy.
- Baseline test metrics on balanced synthetic evaluation sets:
  - **Precision:** `> 0.95`
  - **Recall:** `> 0.90`
  - **False Positive Rate:** `< 0.02`
- **Degraded / Missing Model Policy:** If the model artifact is absent or corrupted, M5 returns `"status": "unavailable"` and `"network_suspicion_score": null`. It never fabricates a prediction.

---

## 7. Domain Shift & LinuxONE Integration
- **Platform Portability:** Trained pipelines depend solely on scikit-learn and joblib. No architecture-specific C extensions are utilized, allowing seamless deployment onto IBM LinuxONE (s390x) and x86_64 environments.
- **Network Variability:** Hospital wireless networks introduce variable jitter that may not appear in wired lab simulations. Before deploying to LinuxONE in production, local Wi-Fi baseline calibration is recommended.
