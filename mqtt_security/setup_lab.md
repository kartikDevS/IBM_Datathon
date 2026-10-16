# Mosquitto Dynamic Security & ACL Lab Setup Guide

This guide details setting up Mosquitto with Dynamic Security plugin for the TessNova ICU monitoring environment.

---

## 1. Package Installation

### On Debian / Ubuntu (x86_64 or ARM64 testbed)
```bash
sudo apt-get update
sudo apt-get install -y mosquitto mosquitto-clients libmosquitto-dev
```

### On RHEL / SLES on IBM LinuxONE (s390x)
```bash
sudo dnf install -y mosquitto mosquitto-utils
```

---

## 2. Dynamic Security Initialization

The Mosquitto Dynamic Security plugin stores runtime accounts, groups, roles, and ACLs in a JSON configuration file.

1. **Initialize the Dynamic Security DB:**
   ```bash
   sudo mosquitto_ctrl dynsec init /var/lib/mosquitto/dynamic-security.json admin
   # Enter a secure password for the dynamic security administrator
   ```

2. **Ensure File Ownership:**
   ```bash
   sudo chown -R mosquitto:mosquitto /var/lib/mosquitto/
   sudo chmod 700 /var/lib/mosquitto/
   sudo chmod 600 /var/lib/mosquitto/dynamic-security.json
   ```

3. **Deploy Configuration:**
   Copy `mqtt_security/mosquitto.conf.example` to `/etc/mosquitto/mosquitto.conf`, verifying plugin path:
   ```bash
   sudo cp mqtt_security/mosquitto.conf.example /etc/mosquitto/mosquitto.conf
   sudo systemctl restart mosquitto
   ```

---

## 3. Provisioning Roles, Devices, and Least-Privilege Topic ACLs

Use `mosquitto_ctrl` to configure least-privilege policies:

### Step 3.1: Create Bedside Monitor Role & ACL
```bash
# Create role for Bed 7
mosquitto_ctrl -u admin -p <admin_pwd> dynsec createRole bed7_monitor_role

# Grant publish permission ONLY to Bed 7's assigned topic
mosquitto_ctrl -u admin -p <admin_pwd> dynsec addRoleACL bed7_monitor_role publishClientSend ward/bed7/ecg allow 1

# Grant subscribe permission for incoming commands
mosquitto_ctrl -u admin -p <admin_pwd> dynsec addRoleACL bed7_monitor_role subscribePattern ward/bed7/commands allow 1
```

### Step 3.2: Create Device User & Assign Role
```bash
# Create client account
mosquitto_ctrl -u admin -p <admin_pwd> dynsec createClient bed7_device

# Assign password
mosquitto_ctrl -u admin -p <admin_pwd> dynsec setClientPassword bed7_device <device_secure_pwd>

# Attach role
mosquitto_ctrl -u admin -p <admin_pwd> dynsec addClientRole bed7_device bed7_monitor_role
```

### Step 3.3: Create Security Agent Role (M4 / M5 Subscriber)
```bash
# Create security observer role
mosquitto_ctrl -u admin -p <admin_pwd> dynsec createRole security_observer_role

# Allow subscribing to all ward telemetry
mosquitto_ctrl -u admin -p <admin_pwd> dynsec addRoleACL security_observer_role subscribePattern ward/+/ecg allow 1

# Allow publishing detection events
mosquitto_ctrl -u admin -p <admin_pwd> dynsec addRoleACL security_observer_role publishClientSend hospital/security/# allow 1

# Assign to security agent client
mosquitto_ctrl -u admin -p <admin_pwd> dynsec createClient sec_agent_01
mosquitto_ctrl -u admin -p <admin_pwd> dynsec addClientRole sec_agent_01 security_observer_role
```

---

## 4. Verification Tests

### Test Authorized Publish (Should Succeed)
```bash
mosquitto_pub -h localhost -p 1883 -u bed7_device -P <device_secure_pwd> -t ward/bed7/ecg -m '{"device_id":"bed7","seq":100,"timestamp":1700000000,"ecg":80.0}'
```

### Test Unauthorized Publish to Bed 8 (Should Be Rejected by Broker ACL)
```bash
mosquitto_pub -h localhost -p 1883 -u bed7_device -P <device_secure_pwd> -t ward/bed8/ecg -m '{"device_id":"bed8","seq":100,"timestamp":1700000000,"ecg":80.0}'
```
Mosquitto will drop or reject this message due to ACL mismatch.
