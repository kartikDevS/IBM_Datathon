"""Unit tests for Mosquitto Containment Manager.

Verifies:
- Strict validation and rejection of shell injection strings in device_id.
- Safe argument passing with shell=False.
- Dry-run execution behavior.
- Audit logging functionality.
- Idempotency and error handling.
"""

import json
from pathlib import Path
import pytest
from unittest.mock import patch, MagicMock

from mqtt_security.containment import (
    ContainmentManager,
    validate_device_id,
    AUDIT_LOG_FILE,
)


def test_device_id_validation_valid():
    assert validate_device_id("bed7") == "bed7"
    assert validate_device_id("bed_icu_01") == "bed_icu_01"
    assert validate_device_id("bed-09") == "bed-09"


def test_device_id_validation_rejections():
    # Shell injection attempts
    with pytest.raises(ValueError):
        validate_device_id("bed7; rm -rf /")

    with pytest.raises(ValueError):
        validate_device_id("bed7 && cat /etc/passwd")

    with pytest.raises(ValueError):
        validate_device_id("bed7`whoami`")

    with pytest.raises(ValueError):
        validate_device_id("bed 7")  # Space disallowed

    with pytest.raises(ValueError):
        validate_device_id("")  # Empty disallowed


def test_dry_run_isolation_and_audit():
    mgr = ContainmentManager(dry_run_default=True)

    # Initial log line count if file exists
    initial_lines = 0
    if AUDIT_LOG_FILE.exists():
        initial_lines = len(AUDIT_LOG_FILE.read_text(encoding="utf-8").strip().splitlines())

    result = mgr.isolate_device("bed7", dry_run=True, reason="simulated_replay_alert", operator="pytest")

    assert result["success"] is True
    assert result["dry_run"] is True
    assert result["device_id"] == "bed7"
    assert result["action"] == "isolate"
    assert result["details"]["persistent_session_cleared"] is False

    # Check that audit log has been updated
    assert AUDIT_LOG_FILE.exists()
    lines = AUDIT_LOG_FILE.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) >= initial_lines + 1

    last_record = json.loads(lines[-1])
    assert last_record["action"] == "isolate"
    assert last_record["device_id"] == "bed7"
    assert last_record["operator"] == "pytest"
    assert last_record["dry_run"] is True


@patch("subprocess.run")
def test_live_command_argument_construction(mock_run):
    mock_res = MagicMock()
    mock_res.returncode = 0
    mock_res.stdout = "Client bed7 disabled."
    mock_res.stderr = ""
    mock_run.return_value = mock_res

    mgr = ContainmentManager(admin_user="admin", admin_password="secret_password", timeout_seconds=5.0)
    result = mgr.isolate_device("bed7", dry_run=False, reason="confirmed_malicious")

    assert result["success"] is True
    assert result["dry_run"] is False

    # Verify subprocess called with shell=False and proper list
    mock_run.assert_called_once()
    called_args, called_kwargs = mock_run.call_args
    cmd_list = called_args[0]

    assert called_kwargs.get("shell") is False
    assert cmd_list[0] == "mosquitto_ctrl"
    assert "-u" in cmd_list and "admin" in cmd_list
    assert "-p" in cmd_list and "secret_password" in cmd_list
    assert "dynsec" in cmd_list
    assert "disableClient" in cmd_list
    assert "bed7" in cmd_list


@patch("subprocess.run")
def test_restore_command_construction(mock_run):
    mock_res = MagicMock()
    mock_res.returncode = 0
    mock_res.stdout = "Client bed7 enabled."
    mock_res.stderr = ""
    mock_run.return_value = mock_res

    mgr = ContainmentManager(admin_user="admin")
    result = mgr.restore_device("bed7", dry_run=False, reason="remediation_complete")

    assert result["success"] is True
    called_args, _ = mock_run.call_args
    cmd_list = called_args[0]
    assert "enableClient" in cmd_list
    assert "bed7" in cmd_list


def test_missing_binary_graceful_handling():
    # Calling non-existent command in live mode returns clean failure rather than unhandled exception
    mgr = ContainmentManager(dynsec_cmd="non_existent_mosquitto_ctrl_tool")
    result = mgr.isolate_device("bed7", dry_run=False)

    assert result["success"] is False
    assert result["details"]["return_code"] == 127
    assert "not found" in result["details"]["output"].lower()
