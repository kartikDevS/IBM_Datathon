# Mosquitto Containment Testing & Persistent Session Analysis

This document outlines the testing protocol for device containment using Mosquitto Dynamic Security and analyzes the **unresolved persistent MQTT session clearing issue**.

---

## 1. Containment Architecture & Action Lifecycle

When an anomaly is confirmed by the decision layer, containment is executed via `mqtt_security.containment`:

1. **Authorization Revocation (`disableClient`):**
   - Calls `mosquitto_ctrl dynsec disableClient <device_id>`.
   - Prevents any new TCP/TLS connection from authenticating under that username.
   - Any attempt to reconnect with valid credentials immediately yields `MQTT_RC_CONNACK_NOT_AUTHORIZED` (code 5 in MQTT v3.1.1, code 135 in MQTT v5.0).

2. **Active Connection Disconnect:**
   - Mosquitto dynamic security disconnects existing connected sockets associated with disabled accounts upon next publish/keepalive cycle.

3. **Audit Logging:**
   - Every containment invocation records target ID, operator ID, UTC timestamp, reason, and return codes into `mqtt_security/containment_audit.log`.

---

## 2. CRITICAL ANALYSIS: The Persistent Session State Problem

### The Problem Discovered in Lab Experiments
During previous datathon lab experimentation, when a device client was disabled:
1. Publishing was successfully blocked.
2. However, if the client previously connected with **`clean_session = False`** (MQTT v3.1.1) or **`Session Expiry Interval > 0`** (MQTT v5.0):
   - The broker continued to retain existing topic subscriptions for that `ClientID`.
   - Re-creating or deleting the client in Dynamic Security did **not** automatically purge previously queued messages stored in the broker's memory or persistence store (`/var/lib/mosquitto/mosquitto.db`).

### Key Distinctions
| Dimension | Dynamic Security Mechanism | MQTT Broker Engine State |
| :--- | :--- | :--- |
| **Authentication / Authorization** | `disableClient` revokes credentials | Broker denies new CONNECT and PUBLISH |
| **Active Network Sockets** | Disconnected upon action | Socket closed |
| **Persistent Subscription Queue** | **NOT cleared by dynsec** | Broker retains queue until session expiry |
| **Queued QoS 1/2 Messages** | **NOT cleared by dynsec** | Undelivered messages remain in memory/disk |

### Safe Containment Protocol Recommendation
Do **not** restart the broker or wipe `/var/lib/mosquitto/mosquitto.db`, as doing so destroys telemetry streams for all other bedside monitors.

Instead, the team should adopt this recommended sequence:
1. **Immediate Revocation:** Invoke `isolate_device(device_id)` to prevent attacker publications.
2. **Quarantine ACL Assignment:** Reassign the client to a quarantine role with zero publish and subscribe permissions (`mosquitto_ctrl dynsec setClientDefaultACLAccess 0`).
3. **Session Purge (Client-Side Cleansing):** Connect an authorized administrative MQTT client with the target device's `ClientID` and flag **`clean_session=True`**, immediately disconnecting. Under MQTT standard specs, this replaces and wipes the broker-side persistent session.
4. **Mark Unresolved:** Until a native Mosquitto API command (e.g. `clearClientSession`) is added upstream, this state is flagged in containment audit records as `persistent_session_cleared: false`.

---

## 3. Repeatable Lab Verification Protocol

1. **Start Normal Stream:**
   ```bash
   python -m attack_simulator.normal_sender --device-id bed7 --count 20 &
   ```

2. **Verify M4 / Broker Reception:**
   Verify messages arrive on `ward/bed7/ecg`.

3. **Execute Isolation:**
   ```bash
   python -m mqtt_security.containment --action isolate --device-id bed7 --live --reason "m4_replay_detected"
   ```

4. **Verify Immediate Publish Rejection:**
   Subsequent publish attempts from `bed7` fail with `Not Authorized`.

5. **Verify Broker Health:**
   Other monitors (e.g., `bed8`) continue publishing without interruption. Broker does NOT crash or restart.

6. **Restore Device:**
   ```bash
   python -m mqtt_security.containment --action restore --device-id bed7 --live --reason "remediation_complete"
   ```
