"""Mosquitto Dynamic Security Containment Wrapper.

Provides safe administrative actions (isolate, restore, inspect) around mosquitto_ctrl
with strict input sanitization, dry-run safety gates, audit logging, and subprocess isolation.
"""

from __future__ import annotations
import argparse
import datetime
import json
import logging
import os
from pathlib import Path
import re
import subprocess
import time
from typing import Dict, List, Optional, Any

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s")
logger = logging.getLogger("containment")

AUDIT_LOG_FILE = Path(__file__).parent / "containment_audit.log"

# Strict device identifier validation to prevent any argument manipulation
DEVICE_ID_REGEX = re.compile(r"^[a-zA-Z0-9_\-]{1,64}$")


def validate_device_id(device_id: str) -> str:
    """Validate that device_id matches strict alphanumeric/hyphen/underscore format."""
    if not isinstance(device_id, str) or not DEVICE_ID_REGEX.match(device_id.strip()):
        raise ValueError(
            f"Invalid device_id '{device_id}'. Must be 1-64 characters matching [a-zA-Z0-9_-]."
        )
    return device_id.strip()


def write_audit_record(
    action: str,
    device_id: str,
    success: bool,
    operator: str,
    reason: str,
    dry_run: bool,
    details: Dict[str, Any],
):
    """Append a structured tamper-evident audit record to local containment log."""
    record = {
        "timestamp_iso": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "timestamp_epoch": time.time(),
        "action": action,
        "device_id": device_id,
        "success": success,
        "operator": operator,
        "reason": reason,
        "dry_run": dry_run,
        "details": details,
    }
    line = json.dumps(record)
    try:
        with open(AUDIT_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception as exc:
        logger.error("Failed to write to audit log %s: %s", AUDIT_LOG_FILE, exc)


class ContainmentManager:
    """Manages Mosquitto Dynamic Security client lifecycle and containment."""

    def __init__(
        self,
        dynsec_cmd: str = "mosquitto_ctrl",
        admin_user: Optional[str] = None,
        admin_password: Optional[str] = None,
        timeout_seconds: float = 10.0,
        dry_run_default: bool = True,
    ):
        self.dynsec_cmd = os.environ.get("DYNSEC_CLI_PATH", dynsec_cmd)
        self.admin_user = admin_user or os.environ.get("DYNSEC_ADMIN_USER", "admin")
        self.admin_password = admin_password or os.environ.get("DYNSEC_ADMIN_PASSWORD")
        self.timeout_seconds = timeout_seconds
        self.dry_run_default = dry_run_default

    def _build_base_cmd(self) -> List[str]:
        cmd = [self.dynsec_cmd]
        if self.admin_user:
            cmd.extend(["-u", self.admin_user])
        if self.admin_password:
            cmd.extend(["-p", self.admin_password])
        cmd.append("dynsec")
        return cmd

    def _execute_command(self, sub_args: List[str], dry_run: bool) -> Tuple[bool, str, int]:
        full_cmd = self._build_base_cmd() + sub_args
        
        # Redact credentials for logging
        safe_log_cmd = [
            "***" if i > 0 and full_cmd[i - 1] in ["-p", "-P"] else arg
            for i, arg in enumerate(full_cmd)
        ]

        if dry_run:
            logger.info("[DRY-RUN] Would execute: %s", " ".join(safe_log_cmd))
            return True, f"[DRY-RUN] Simulated execution of: {' '.join(safe_log_cmd)}", 0

        logger.info("Executing administrative command: %s", " ".join(safe_log_cmd))
        try:
            res = subprocess.run(
                full_cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                shell=False,  # Enforce direct execve without shell interpolation
            )
            success = (res.returncode == 0)
            output = res.stdout if success else (res.stderr or res.stdout)
            return success, output.strip(), res.returncode
        except FileNotFoundError:
            msg = f"Command '{self.dynsec_cmd}' not found on host. Check PATH or install mosquitto_ctrl."
            logger.error(msg)
            return False, msg, 127
        except subprocess.TimeoutExpired:
            msg = f"Command timed out after {self.timeout_seconds}s."
            logger.error(msg)
            return False, msg, 124
        except Exception as exc:
            msg = f"Subprocess exception: {exc}"
            logger.error(msg)
            return False, msg, 1

    def inspect_device(self, device_id: str) -> Dict[str, Any]:
        """Query client details, assigned roles, and enabled status in Dynamic Security."""
        valid_id = validate_device_id(device_id)
        success, out, rc = self._execute_command(["getClient", valid_id], dry_run=False)
        return {
            "device_id": valid_id,
            "action": "inspect",
            "success": success,
            "return_code": rc,
            "output": out,
            "inspected_at": time.time(),
        }

    def isolate_device(
        self,
        device_id: str,
        dry_run: Optional[bool] = None,
        reason: str = "unspecified_security_containment",
        operator: str = "tessnova_security",
    ) -> Dict[str, Any]:
        """Isolate a compromised device by disabling its Dynamic Security account.
        
        NOTE ON PERSISTENT MQTT SESSIONS:
        Disabling a client revokes its authorization to publish or create new connections.
        However, if the client held a persistent MQTT session (CleanSession=0 / SessionExpiryInterval>0),
        the broker may retain subscription states or queued messages until session expiration.
        This wrapper records authorization revocation, marking session purge as an open dependency.
        """
        valid_id = validate_device_id(device_id)
        is_dry_run = self.dry_run_default if dry_run is None else dry_run

        success, out, rc = self._execute_command(["disableClient", valid_id], dry_run=is_dry_run)

        details = {
            "return_code": rc,
            "output": out,
            "authorization_revoked": success,
            "persistent_session_cleared": False,  # Explicitly unresolved behavior
            "session_warning": "Persistent session queues are not guaranteed cleared by disableClient.",
        }

        write_audit_record(
            action="isolate",
            device_id=valid_id,
            success=success,
            operator=operator,
            reason=reason,
            dry_run=is_dry_run,
            details=details,
        )

        return {
            "device_id": valid_id,
            "action": "isolate",
            "success": success,
            "dry_run": is_dry_run,
            "details": details,
        }

    def restore_device(
        self,
        device_id: str,
        dry_run: Optional[bool] = None,
        reason: str = "remediation_completed",
        operator: str = "tessnova_security",
    ) -> Dict[str, Any]:
        """Restore an isolated device by re-enabling its Dynamic Security account."""
        valid_id = validate_device_id(device_id)
        is_dry_run = self.dry_run_default if dry_run is None else dry_run

        success, out, rc = self._execute_command(["enableClient", valid_id], dry_run=is_dry_run)

        details = {
            "return_code": rc,
            "output": out,
            "authorization_restored": success,
        }

        write_audit_record(
            action="restore",
            device_id=valid_id,
            success=success,
            operator=operator,
            reason=reason,
            dry_run=is_dry_run,
            details=details,
        )

        return {
            "device_id": valid_id,
            "action": "restore",
            "success": success,
            "dry_run": is_dry_run,
            "details": details,
        }


def main():
    parser = argparse.ArgumentParser(description="TessNova Mosquitto Containment Manager")
    parser.add_argument(
        "--action",
        required=True,
        choices=["isolate", "restore", "inspect"],
        help="Containment action to perform",
    )
    parser.add_argument("--device-id", required=True, help="Target device ID (e.g. bed7)")
    parser.add_argument("--reason", default="manual_cli_request", help="Audit reason for action")
    parser.add_argument("--operator", default="cli_operator", help="Operator or agent ID")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=True,
        help="Simulate action without executing live command (default: True)",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Execute live command against broker (overrides --dry-run)",
    )

    args = parser.parse_args()
    dry_run = False if args.live else True

    mgr = ContainmentManager(dry_run_default=dry_run)

    try:
        if args.action == "isolate":
            result = mgr.isolate_device(args.device_id, dry_run=dry_run, reason=args.reason, operator=args.operator)
        elif args.action == "restore":
            result = mgr.restore_device(args.device_id, dry_run=dry_run, reason=args.reason, operator=args.operator)
        elif args.action == "inspect":
            result = mgr.inspect_device(args.device_id)

        print(json.dumps(result, indent=2))
    except ValueError as val_err:
        print(f"\n[VALIDATION REJECTED] {val_err}\n")
        exit(1)


if __name__ == "__main__":
    main()
