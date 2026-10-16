"""Data models and reason definitions for the M4 Replay Catcher."""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Set, Deque
from collections import deque
import json


class ReplayReason(str, Enum):
    NORMAL = "normal"
    DUPLICATE_SEQUENCE = "duplicate_sequence"
    LOWER_SEQUENCE = "lower_sequence"
    STALE_TIMESTAMP = "stale_timestamp"
    FUTURE_TIMESTAMP = "future_timestamp"
    DECREASING_TIMESTAMP = "decreasing_timestamp"
    MALFORMED_PAYLOAD = "malformed_payload"
    UNEXPECTED_RESET = "unexpected_reset"
    PAYLOAD_FINGERPRINT_REPEATED = "payload_fingerprint_repeated"


@dataclass(frozen=True)
class TelemetryMessage:
    device_id: str
    seq: int
    timestamp: float
    ecg: float
    schema_version: str = "1.0"


@dataclass
class DeviceReplayState:
    device_id: str
    highest_seq: int = -1
    last_accepted_timestamp: float = -1.0
    last_observed_mono: float = 0.0
    recent_seq_history: Deque[int] = field(default_factory=lambda: deque(maxlen=2000))
    recent_seq_set: Set[int] = field(default_factory=set)
    total_accepted: int = 0
    total_rejected: int = 0

    def record_accepted(self, seq: int, ts: float, mono: float):
        self.highest_seq = max(self.highest_seq, seq)
        self.last_accepted_timestamp = ts
        self.last_observed_mono = mono
        self.total_accepted += 1
        
        # Maintain bounded sequence sliding window
        if len(self.recent_seq_history) == self.recent_seq_history.maxlen:
            evicted = self.recent_seq_history[0]
            self.recent_seq_set.discard(evicted)
        self.recent_seq_history.append(seq)
        self.recent_seq_set.add(seq)

    def record_rejected(self):
        self.total_rejected += 1


@dataclass(frozen=True)
class M4DetectionEvent:
    device_id: str
    detector: str
    replay_suspected: bool
    reasons: List[str]
    sequence_number: Optional[int]
    event_timestamp: Optional[float]
    observed_at: float
    schema_version: str = "1.0"

    def to_dict(self) -> dict:
        return {
            "device_id": self.device_id,
            "detector": self.detector,
            "replay_suspected": self.replay_suspected,
            "reasons": self.reasons,
            "sequence_number": self.sequence_number,
            "event_timestamp": self.event_timestamp,
            "observed_at": self.observed_at,
            "schema_version": self.schema_version,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=None)
