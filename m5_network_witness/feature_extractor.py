"""Feature Extraction Pipeline for M5 Network Witness.

Extracts statistical and temporal behavioral features from streaming MQTT telemetry packets
over rolling time windows.

LEAKAGE PREVENTION RULES:
1. Excludes all identity proxies (IP addresses, MAC addresses, device IDs, topic strings, ports).
2. Computes aggregate behavioral dynamics (rate, inter-arrival statistics, jitter, sequence anomalies).
3. Distinguishes application-layer observed features from future pcap/kernel network features.
"""

from __future__ import annotations
from collections import deque
from dataclasses import dataclass, field
import math
import statistics
import time
from typing import Dict, List, Optional, Any


FEATURE_COLUMNS = [
    "msg_rate",
    "inter_arrival_mean",
    "inter_arrival_std",
    "inter_arrival_min",
    "inter_arrival_max",
    "seq_gap_count",
    "seq_dup_count",
    "payload_bytes_mean",
    "payload_bytes_std",
    "timestamp_drift_mean",
    "timestamp_drift_max",
]


@dataclass
class TelemetryRecord:
    device_id: str
    seq: int
    timestamp: float
    observed_mono: float
    observed_wall: float
    payload_size: int


class WindowedFeatureExtractor:
    """Maintains a rolling window of telemetry arrivals per device and computes behavioral vectors."""

    def __init__(self, window_size: int = 10, max_time_window_seconds: float = 15.0):
        self.window_size = window_size
        self.max_time_window_seconds = max_time_window_seconds
        self._buffers: Dict[str, deque[TelemetryRecord]] = {}

    def add_packet(
        self,
        device_id: str,
        seq: int,
        timestamp: float,
        payload_size: int,
        wall_time: Optional[float] = None,
        mono_time: Optional[float] = None,
    ) -> Optional[Dict[str, float]]:
        """Ingest a packet arrival and return computed features if minimum window is satisfied."""
        wall_time = wall_time or time.time()
        mono_time = mono_time or time.monotonic()

        record = TelemetryRecord(
            device_id=device_id,
            seq=seq,
            timestamp=timestamp,
            observed_mono=mono_time,
            observed_wall=wall_time,
            payload_size=payload_size,
        )

        buf = self._buffers.setdefault(device_id, deque(maxlen=self.window_size))
        buf.append(record)

        # Evict records older than max_time_window_seconds
        while len(buf) > 1 and (mono_time - buf[0].observed_mono) > self.max_time_window_seconds:
            buf.popleft()

        # Minimum packets required to compute variance and inter-arrival intervals
        if len(buf) < 4:
            return None

        return self.compute_features(list(buf))

    @staticmethod
    def compute_features(records: List[TelemetryRecord]) -> Dict[str, float]:
        """Compute statistical features from a sequence of records."""
        n = len(records)
        if n < 2:
            return {col: 0.0 for col in FEATURE_COLUMNS}

        # Inter-arrival times based on local monotonic clock
        deltas = [
            max(0.0001, records[i].observed_mono - records[i - 1].observed_mono)
            for i in range(1, n)
        ]
        total_time = sum(deltas)
        msg_rate = (n - 1) / max(total_time, 0.001)

        ia_mean = statistics.fmean(deltas)
        ia_std = statistics.stdev(deltas) if len(deltas) > 1 else 0.0
        ia_min = min(deltas)
        ia_max = max(deltas)

        # Sequence gap and duplicate counts
        seq_gap_count = 0
        seq_dup_count = 0
        for i in range(1, n):
            diff = records[i].seq - records[i - 1].seq
            if diff == 0:
                seq_dup_count += 1
            elif diff > 1 or diff < 0:
                seq_gap_count += 1

        # Payload sizes
        sizes = [r.payload_size for r in records]
        pb_mean = statistics.fmean(sizes)
        pb_std = statistics.stdev(sizes) if len(sizes) > 1 else 0.0

        # Timestamp drift (arrival wall clock - packet claimed timestamp)
        drifts = [abs(r.observed_wall - r.timestamp) for r in records]
        drift_mean = statistics.fmean(drifts)
        drift_max = max(drifts)

        return {
            "msg_rate": round(msg_rate, 4),
            "inter_arrival_mean": round(ia_mean, 4),
            "inter_arrival_std": round(ia_std, 4),
            "inter_arrival_min": round(ia_min, 4),
            "inter_arrival_max": round(ia_max, 4),
            "seq_gap_count": float(seq_gap_count),
            "seq_dup_count": float(seq_dup_count),
            "payload_bytes_mean": round(pb_mean, 2),
            "payload_bytes_std": round(pb_std, 2),
            "timestamp_drift_mean": round(drift_mean, 4),
            "timestamp_drift_max": round(drift_max, 4),
        }
