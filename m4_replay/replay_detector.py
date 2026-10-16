"""M4 — Metadata-Based Replay Catcher.

A transport-agnostic replay and sequence anomaly detector for hospital bedside telemetry.
Evaluates sequence freshness, monotonic progression, duplicates, and stale timestamps
per-device without altering trusted sequence state on rejected packets.
"""

from __future__ import annotations
import argparse
import json
import logging
import time
from typing import Callable, Dict, List, Optional, Tuple, Any

from m4_replay.models import (
    DeviceReplayState,
    M4DetectionEvent,
    ReplayReason,
    TelemetryMessage,
)

logger = logging.getLogger("m4_replay")


class ReplayDetector:
    """Core M4 metadata replay detection engine.
    
    Evaluates telemetry packets against strictly isolated per-device state.
    Clock functions are injectable for deterministic testing.
    """

    def __init__(
        self,
        stale_threshold_seconds: float = 5.0,
        future_tolerance_seconds: float = 2.0,
        max_sequence_history: int = 2000,
        allow_auto_reset: bool = False,
        reboot_gap_seconds: float = 10.0,
        time_fn: Optional[Callable[[], float]] = None,
        mono_fn: Optional[Callable[[], float]] = None,
    ):
        """Initialize ReplayDetector with configurable timing and sequence policies.
        
        Args:
            stale_threshold_seconds: Max acceptable age in seconds before packet is marked stale.
            future_tolerance_seconds: Max acceptable drift into future before clock skew warning.
            max_sequence_history: Sliding window size of observed sequence numbers per device.
            allow_auto_reset: If True, sequence dropping to 0 after reboot_gap is treated as valid reboot.
            reboot_gap_seconds: Minimum elapsed time required to consider a sequence reset legitimate.
            time_fn: Injectable wall-clock provider returning Unix epoch in seconds.
            mono_fn: Injectable monotonic clock provider.
        """
        self.stale_threshold_seconds = float(stale_threshold_seconds)
        self.future_tolerance_seconds = float(future_tolerance_seconds)
        self.max_sequence_history = int(max_sequence_history)
        self.allow_auto_reset = allow_auto_reset
        self.reboot_gap_seconds = float(reboot_gap_seconds)
        self.time_fn = time_fn or time.time
        self.mono_fn = mono_fn or time.monotonic
        
        # Per-device state storage
        self._devices: Dict[str, DeviceReplayState] = {}

    def get_device_state(self, device_id: str) -> Optional[DeviceReplayState]:
        """Return the current replay state for a specific device, or None if never seen."""
        return self._devices.get(device_id)

    def reset_device(self, device_id: str) -> bool:
        """Explicitly reset state for an authorized device (e.g. during sanctioned maintenance/testing)."""
        if device_id in self._devices:
            del self._devices[device_id]
            logger.info("Explicitly reset M4 tracking state for device=%s", device_id)
            return True
        return False

    def reset_all(self):
        """Clear state for all devices."""
        self._devices.clear()

    def process_raw_payload(self, raw_payload: str | bytes) -> M4DetectionEvent:
        """Parse raw MQTT payload bytes/string and evaluate replay metadata."""
        now_wall = self.time_fn()
        try:
            if isinstance(raw_payload, bytes):
                raw_payload = raw_payload.decode("utf-8")
            data = json.loads(raw_payload)
        except Exception as exc:
            return M4DetectionEvent(
                device_id="unknown",
                detector="M4",
                replay_suspected=True,
                reasons=[ReplayReason.MALFORMED_PAYLOAD.value],
                sequence_number=None,
                event_timestamp=None,
                observed_at=now_wall,
            )

        return self.process_dict(data)

    def process_dict(self, data: Any) -> M4DetectionEvent:
        """Validate dictionary structure and evaluate message metadata."""
        now_wall = self.time_fn()

        if not isinstance(data, dict):
            return M4DetectionEvent(
                device_id="unknown",
                detector="M4",
                replay_suspected=True,
                reasons=[ReplayReason.MALFORMED_PAYLOAD.value],
                sequence_number=None,
                event_timestamp=None,
                observed_at=now_wall,
            )

        # Validate required fields
        device_id = data.get("device_id")
        seq = data.get("seq")
        ts = data.get("timestamp")
        ecg = data.get("ecg")

        reasons: List[str] = []

        if not isinstance(device_id, str) or not device_id.strip():
            reasons.append(ReplayReason.MALFORMED_PAYLOAD.value)
            return M4DetectionEvent(
                device_id=str(device_id or "invalid"),
                detector="M4",
                replay_suspected=True,
                reasons=reasons,
                sequence_number=seq if isinstance(seq, int) and not isinstance(seq, bool) else None,
                event_timestamp=ts if isinstance(ts, (int, float)) and not isinstance(ts, bool) else None,
                observed_at=now_wall,
            )

        # Ensure seq is an integer, rejecting booleans explicitly
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            reasons.append(ReplayReason.MALFORMED_PAYLOAD.value)

        # Ensure timestamp is numeric, non-boolean, and positive
        if isinstance(ts, bool) or not isinstance(ts, (int, float)) or ts < 0:
            reasons.append(ReplayReason.MALFORMED_PAYLOAD.value)

        # Ensure ecg is numeric
        if isinstance(ecg, bool) or not isinstance(ecg, (int, float)):
            reasons.append(ReplayReason.MALFORMED_PAYLOAD.value)

        if reasons:
            return M4DetectionEvent(
                device_id=device_id,
                detector="M4",
                replay_suspected=True,
                reasons=reasons,
                sequence_number=seq if isinstance(seq, int) and not isinstance(seq, bool) else None,
                event_timestamp=ts if isinstance(ts, (int, float)) and not isinstance(ts, bool) else None,
                observed_at=now_wall,
            )

        msg = TelemetryMessage(
            device_id=device_id,
            seq=int(seq),
            timestamp=float(ts),
            ecg=float(ecg),
            schema_version=str(data.get("schema_version", "1.0")),
        )

        return self.evaluate_message(msg)

    def evaluate_message(self, msg: TelemetryMessage) -> M4DetectionEvent:
        """Inspect telemetry metadata against the device's recorded baseline state."""
        now_wall = self.time_fn()
        now_mono = self.mono_fn()
        reasons: List[str] = []

        state = self._devices.setdefault(
            msg.device_id,
            DeviceReplayState(device_id=msg.device_id)
        )

        # 1. Freshness check against wall clock
        age = now_wall - msg.timestamp
        if age > self.stale_threshold_seconds:
            reasons.append(ReplayReason.STALE_TIMESTAMP.value)
        elif age < -self.future_tolerance_seconds:
            reasons.append(ReplayReason.FUTURE_TIMESTAMP.value)

        # 2. First message from this device
        if state.highest_seq == -1:
            if reasons:
                state.record_rejected()
                return M4DetectionEvent(
                    device_id=msg.device_id,
                    detector="M4",
                    replay_suspected=True,
                    reasons=reasons,
                    sequence_number=msg.seq,
                    event_timestamp=msg.timestamp,
                    observed_at=now_wall,
                )
            state.record_accepted(msg.seq, msg.timestamp, now_mono)
            return M4DetectionEvent(
                device_id=msg.device_id,
                detector="M4",
                replay_suspected=False,
                reasons=[ReplayReason.NORMAL.value],
                sequence_number=msg.seq,
                event_timestamp=msg.timestamp,
                observed_at=now_wall,
            )

        # 3. Duplicate sequence check
        if msg.seq in state.recent_seq_set or msg.seq == state.highest_seq:
            reasons.append(ReplayReason.DUPLICATE_SEQUENCE.value)

        # 4. Out-of-order or lower sequence check
        if msg.seq < state.highest_seq:
            # Check if this qualifies under explicit restart policy
            is_valid_reboot = (
                self.allow_auto_reset
                and msg.seq == 0
                and (msg.timestamp - state.last_accepted_timestamp) > self.reboot_gap_seconds
            )
            if is_valid_reboot:
                logger.info("Device %s reboot detected (seq reset to 0 after gap)", msg.device_id)
                state.recent_seq_set.clear()
                state.recent_seq_history.clear()
                state.highest_seq = -1
            else:
                reasons.append(ReplayReason.LOWER_SEQUENCE.value)

        # 5. Decreasing timestamp check
        if msg.timestamp < state.last_accepted_timestamp:
            reasons.append(ReplayReason.DECREASING_TIMESTAMP.value)

        # Decision
        if reasons:
            # IMPORTANT: Do NOT advance trusted high-water mark sequence state on rejected packet!
            state.record_rejected()
            return M4DetectionEvent(
                device_id=msg.device_id,
                detector="M4",
                replay_suspected=True,
                reasons=reasons,
                sequence_number=msg.seq,
                event_timestamp=msg.timestamp,
                observed_at=now_wall,
            )

        # Valid monotonic sequence advance
        state.record_accepted(msg.seq, msg.timestamp, now_mono)
        return M4DetectionEvent(
            device_id=msg.device_id,
            detector="M4",
            replay_suspected=False,
            reasons=[ReplayReason.NORMAL.value],
            sequence_number=msg.seq,
            event_timestamp=msg.timestamp,
            observed_at=now_wall,
        )


def main():
    parser = argparse.ArgumentParser(
        description="M4 Metadata Replay Catcher - evaluates telemetry message JSON for replay anomalies."
    )
    parser.add_argument(
        "--json",
        type=str,
        help="Raw JSON telemetry string to evaluate (e.g. '{\"device_id\":\"bed7\",\"seq\":101,\"timestamp\":1700000000,\"ecg\":80.0}')",
    )
    parser.add_argument(
        "--stale-threshold",
        type=float,
        default=5.0,
        help="Maximum allowable age in seconds before message is flagged as stale (default: 5.0)",
    )
    args = parser.parse_args()

    detector = ReplayDetector(stale_threshold_seconds=args.stale_threshold)

    if args.json:
        result = detector.process_raw_payload(args.json)
        print(result.to_json())
    else:
        print("M4 Replay Detector ready. Run with --help for options or provide --json payload.")


if __name__ == "__main__":
    main()
