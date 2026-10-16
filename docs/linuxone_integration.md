# IBM LinuxONE (s390x) Deployment & Integration Guide

**Target Hardware:** IBM LinuxONE Emperor 4 / LinuxONE III  
**Operating System:** Red Hat Enterprise Linux 9 / SUSE Linux Enterprise Server 15 / Ubuntu on s390x  
**Deployment Scope:** Mosquitto Dynamic Security, M4 Replay Catcher, M5 Witness, and Containment  

---

## 1. Platform Specifics & LinuxONE Architecture Notes

| Consideration | Development (x86_64 / Windows) | IBM LinuxONE (s390x) |
| :--- | :--- | :--- |
| **CPU Architecture** | Little-Endian (x86_64) | **Big-Endian (s390x)** |
| **Standard Library Path** | `/usr/lib/x86_64-linux-gnu/` | **`/usr/lib64/`** (RHEL/SLES) or **`/usr/lib/s390x-linux-gnu/`** (Ubuntu) |
| **Dynamic Security Plugin** | `mosquitto_dynamic_security.so` | `/usr/lib64/mosquitto_dynamic_security.so` |
| **Python Packages** | Wheel downloads from PyPI | Pre-built s390x wheels or native compilation via GCC/Clang |
| **Mosquitto Path** | `/usr/bin/mosquitto` | `/usr/sbin/mosquitto` or `/usr/bin/mosquitto` |

> [!IMPORTANT]
> The codebase was engineered with pure Python abstractions and standard IEEE-754 JSON float formatting to ensure seamless compatibility with the big-endian architecture of s390x. Do not use raw binary C struct unpackers without explicit endianness indicators (`>` or `<`).

---

## 2. LinuxONE Host Preparation

### Step 2.1: System Packages (RHEL 9 on s390x)
```bash
sudo dnf install -y python3.11 python3.11-pip python3.11-devel \
                    mosquitto mosquitto-utils gcc
```

### Step 2.2: Virtual Environment Setup
```bash
cd /opt/tessnova/security
python3.11 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
```

---

## 3. Mosquitto Broker Configuration on LinuxONE

### Step 3.1: Locate the Dynamic Security Shared Object
Verify the exact installation path on your s390x system:
```bash
rpm -ql mosquitto | grep -i dynamic_security
# Typical output: /usr/lib64/mosquitto_dynamic_security.so
```

### Step 3.2: Configure `/etc/mosquitto/mosquitto.conf`
Ensure the plugin path reflects s390x:
```ini
listener 1883 0.0.0.0
allow_anonymous false

plugin /usr/lib64/mosquitto_dynamic_security.so
plugin_opt_config_file /var/lib/mosquitto/dynamic-security.json

persistence true
persistence_location /var/lib/mosquitto/
```

### Step 3.3: Permissions & Ownership
```bash
sudo mkdir -p /var/lib/mosquitto /var/log/mosquitto
sudo chown -R mosquitto:mosquitto /var/lib/mosquitto /var/log/mosquitto
sudo chmod 700 /var/lib/mosquitto
```

---

## 4. Systemd Service Units

### Unit 1: M4 Replay Listener Service (`/etc/systemd/system/tessnova-m4.service`)
```ini
[Unit]
Description=TessNova M4 Replay Catcher Service
After=network.target mosquitto.service
Requires=mosquitto.service

[Service]
Type=simple
User=tessnova
WorkingDirectory=/opt/tessnova/security
EnvironmentFile=/opt/tessnova/security/.env
ExecStart=/opt/tessnova/security/.venv/bin/python -m m4_replay.mqtt_replay_listener \
    --broker localhost \
    --port 1883 \
    --topic "ward/+/ecg" \
    --event-topic "hospital/security/m4_replay" \
    --stale-threshold 5.0
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now tessnova-m4.service
```

---

## 5. Team Lead Pre-Deployment Verification Checklist

Before connecting live hospital bedside simulator feeds, verify:
- [ ] `pytest` passes on LinuxONE: `.venv/bin/pytest -v` (all 26 tests).
- [ ] Mosquitto is running with Dynamic Security enabled: `systemctl status mosquitto`.
- [ ] `mosquitto_ctrl` CLI is in PATH or configured in `.env` (`DYNSEC_CLI_PATH`).
- [ ] Topic ACLs are verified: Unauthorized device cannot publish to Bed 7 topic.
- [ ] Containment dry-run verified: `python -m mqtt_security.containment --action isolate --device-id bed7 --dry-run`.
- [ ] Persistent session cleanup protocol reviewed in `mqtt_security/test_containment.md`.
