# TessNova Attack & Fault Simulator Suite

This suite provides configurable, bounded, and modular telemetry publishers designed **strictly for authorized local laboratory testing and IBM LinuxONE integration validation**.

> [!CAUTION]
> These utilities generate synthetic telemetry and test faults. They must **never** be targeted at production clinical networks, external infrastructure, or public brokers. All physiological waveforms are synthetic mathematical approximations and contain zero real patient health information (PHI).

---

## 1. Scenario Catalog & Expected Signals

| Script | Type | Description | Expected M4 Signal | Expected M5 Signal | Expected Broker / ACL Signal |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `normal_sender.py` | Baseline | Monotonic `seq`, fresh `timestamp`, normal sinusoidal ECG. | `replay_suspected: false` (`normal`) | Low suspicion score (`< 0.2`) | Authorized publish accepted. |
| `attack_spike.py` | Cyber/Clinical | Sudden abrupt ECG jump (+120 bpm). | `normal` (valid metadata) | Low suspicion (rate normal) | Clean MQTT transport; alarms downstream clinical layer. |
| `attack_stuck.py` | Hardware Fault | Fixed ECG reading while `seq` and `ts` advance. | `normal` (valid metadata) | Low network suspicion | Hardware freeze; proves fault != cyber intrusion. |
| `attack_bias.py` | Integrity Tamper | Constant offset (+35 bpm) added to ECG. | `normal` (valid metadata) | Low network suspicion | Silent data corruption / MitM integrity violation. |
| `attack_drift.py` | Sensor Degrade | Linear gradual drift (+2.5 bpm/step). | `normal` (valid metadata) | Low network suspicion | Calibration / impedance failure. |
| `attack_replay.py` | Replay Attack | Replays captured packets (verbatim or duplicate seq). | **`replay_suspected: true`** (`duplicate_sequence`, `stale_timestamp`) | Moderate/High suspicion | M4 catches replayed sequence and stale timestamps. |
| `attack_spoof.py` | Identity Spoof | Publishes to `ward/bed7/ecg` with client `bed99_rogue`. | Payload accepted if format valid | Suspicious if topic mismatched | **Mosquitto ACL rejects unauthorized client publishing to bed7 topic.** |
| `attack_flood.py` | DoS / Stress | High-rate burst (bounded to <= 50 msgs/s). | `normal` (if monotonic) | **High suspicion** (high rate, low jitter) | Broker throughput stress; rate limiter triggers. |

---

## 2. CLI Execution & Dry-Run Mode

All scripts support standalone execution without requiring an active MQTT broker via the `--dry-run` flag.

### A. Normal Sender
```bash
python -m attack_simulator.normal_sender --count 10 --interval 0.2 --dry-run
```

### B. Spike Injection
```bash
python -m attack_simulator.attack_spike --count 15 --spike-at 5 --spike-magnitude 150.0 --dry-run
```

### C. Stuck Sensor Fault
```bash
python -m attack_simulator.attack_stuck --count 10 --stuck-value 82.0 --dry-run
```

### D. Bias Injection
```bash
python -m attack_simulator.attack_bias --count 10 --bias-offset 40.0 --dry-run
```

### E. Slow Drift
```bash
python -m attack_simulator.attack_drift --count 15 --drift-rate 3.0 --dry-run
```

### F. Replay Simulation
```bash
# Verbatim replay of captured sequence numbers and timestamps
python -m attack_simulator.attack_replay --count 10 --mode verbatim --dry-run
```

### G. Spoofing Simulation
```bash
python -m attack_simulator.attack_spoof --target-device bed7 --spoofed-id bed99_unauthorized --dry-run
```

### H. Bounded Flood Stress Test
```bash
# Requires explicit opt-in safety flag --enable-flood-test
python -m attack_simulator.attack_flood --rate 25.0 --count 50 --enable-flood-test --dry-run
```

---

## 3. Safety Controls & Boundaries

1. **Opt-in Authorization for Flooding:** `attack_flood.py` strictly requires `--enable-flood-test` and rejects any target host other than `localhost` or `127.0.0.1`.
2. **Hard Upper Bounds:** Message counts are capped at 500 packets and intervals are floored at 20 milliseconds.
3. **Structured Logging:** Every generated message clearly labels whether it is legitimate, a hardware fault, or simulated malicious activity in log headers.
