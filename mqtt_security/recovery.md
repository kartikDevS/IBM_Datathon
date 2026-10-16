# Device Remediation & Recovery Runbook

This runbook outlines the operational procedure to restore a quarantined or contained bedside monitor after an incident is remediated.

---

## 1. Remediation Verification Checklist

Before restoring a device to active telemetry transmission, the integration team must verify:
- [ ] Hardware sensor fault resolved (for `attack_stuck` or physical lead disconnect).
- [ ] Rogue publisher client stopped or isolated at the network layer.
- [ ] Device credentials rotated if credential compromise was suspected.
- [ ] Device clock verified and synchronized via NTP (to eliminate false stale timestamp alerts).

---

## 2. Restoration Procedure

### Step 1: Re-enable Client in Mosquitto Dynamic Security
Using the containment wrapper:
```bash
python -m mqtt_security.containment --action restore --device-id bed7 --live --reason "sensor_recalibrated_credentials_rotated"
```

Or directly via `mosquitto_ctrl`:
```bash
mosquitto_ctrl -u admin -p <admin_password> dynsec enableClient bed7
```

### Step 2: Reset M4 Replay Tracking State
When a physical monitor reboots or resets its sequence counter after remediation, M4 would normally flag sequence #0 as an unexpected drop (`lower_sequence`).

To reset M4 tracking state for this device:
- Programmatically invoke: `replay_detector.reset_device("bed7")`.
- Or restart the `mqtt_replay_listener` if managing batch resets.

### Step 3: Verify Telemetry Resumption
Start a brief transmission test:
```bash
python -m attack_simulator.normal_sender --device-id bed7 --count 5 --start-seq 0
```
Verify that M4 produces:
```json
{
  "device_id": "bed7",
  "detector": "M4",
  "replay_suspected": false,
  "reasons": ["normal"],
  "sequence_number": 0
}
```

### Step 4: Verify Broker & Sibling Device Health
Confirm that neighboring ICU monitors (e.g., `bed1` through `bed6`) experienced zero dropped messages during restoration:
```bash
# Check Mosquitto service status
systemctl status mosquitto
```

---

## 3. Emergency Rollback / Recovery

If `dynamic-security.json` becomes corrupted:
1. Stop the broker: `sudo systemctl stop mosquitto`
2. Restore backup: `sudo cp /var/lib/mosquitto/dynamic-security.json.bak /var/lib/mosquitto/dynamic-security.json`
3. Restart broker: `sudo systemctl start mosquitto`
4. Confirm broker health: `mosquitto_sub -t '$SYS/broker/version' -C 1`
