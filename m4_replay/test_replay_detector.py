"""Unit tests for M4 Replay Detector.

Verifies:
- Monotonic sequence advancement.
- Duplicate sequence rejection.
- Out-of-order / lower sequence rejection.
- Stale timestamp rejection.
- Clock drift / future timestamp detection.
- Decreasing timestamp detection.
- Malformed payloads and boolean field rejections.
- Multi-device isolation.
- State reset and explicit reboot policies.
- Ensuring state is not updated on rejected packets.
"""

import pytest
from m4_replay.replay_detector import ReplayDetector
from m4_replay.models import ReplayReason, TelemetryMessage


class MockClock:
    def __init__(self, start_time: float = 1791389000.0):
        self.current_time = start_time
        self.monotonic_time = 100.0

    def time(self) -> float:
        return self.current_time

    def monotonic(self) -> float:
        return self.monotonic_time

    def advance(self, seconds: float):
        self.current_time += seconds
        self.monotonic_time += seconds


@pytest.fixture
def mock_clock():
    return MockClock()


@pytest.fixture
def detector(mock_clock):
    return ReplayDetector(
        stale_threshold_seconds=5.0,
        future_tolerance_seconds=2.0,
        time_fn=mock_clock.time,
        mono_fn=mock_clock.monotonic,
    )


def test_normal_increasing_sequence(detector, mock_clock):
    msg1 = TelemetryMessage(device_id="bed7", seq=100, timestamp=mock_clock.time(), ecg=80.0)
    event1 = detector.evaluate_message(msg1)
    assert not event1.replay_suspected
    assert event1.reasons == [ReplayReason.NORMAL.value]

    mock_clock.advance(1.0)
    msg2 = TelemetryMessage(device_id="bed7", seq=101, timestamp=mock_clock.time(), ecg=81.0)
    event2 = detector.evaluate_message(msg2)
    assert not event2.replay_suspected
    assert event2.reasons == [ReplayReason.NORMAL.value]
    assert event2.sequence_number == 101


def test_duplicate_sequence_number(detector, mock_clock):
    msg1 = TelemetryMessage(device_id="bed7", seq=100, timestamp=mock_clock.time(), ecg=80.0)
    detector.evaluate_message(msg1)

    mock_clock.advance(0.5)
    # Replay of seq 100
    msg_dup = TelemetryMessage(device_id="bed7", seq=100, timestamp=mock_clock.time(), ecg=80.0)
    event_dup = detector.evaluate_message(msg_dup)

    assert event_dup.replay_suspected
    assert ReplayReason.DUPLICATE_SEQUENCE.value in event_dup.reasons


def test_lower_sequence_number(detector, mock_clock):
    msg1 = TelemetryMessage(device_id="bed7", seq=100, timestamp=mock_clock.time(), ecg=80.0)
    detector.evaluate_message(msg1)

    mock_clock.advance(0.5)
    # Out of order / lower sequence
    msg_lower = TelemetryMessage(device_id="bed7", seq=95, timestamp=mock_clock.time(), ecg=80.0)
    event_lower = detector.evaluate_message(msg_lower)

    assert event_lower.replay_suspected
    assert ReplayReason.LOWER_SEQUENCE.value in event_lower.reasons


def test_stale_timestamp(detector, mock_clock):
    # Message timestamp is 10 seconds older than detector current time (threshold is 5.0)
    stale_time = mock_clock.time() - 10.0
    msg_stale = TelemetryMessage(device_id="bed7", seq=100, timestamp=stale_time, ecg=80.0)
    event = detector.evaluate_message(msg_stale)

    assert event.replay_suspected
    assert ReplayReason.STALE_TIMESTAMP.value in event.reasons


def test_future_timestamp(detector, mock_clock):
    # Message timestamp is 5 seconds in the future (threshold is 2.0)
    future_time = mock_clock.time() + 5.0
    msg_future = TelemetryMessage(device_id="bed7", seq=100, timestamp=future_time, ecg=80.0)
    event = detector.evaluate_message(msg_future)

    assert event.replay_suspected
    assert ReplayReason.FUTURE_TIMESTAMP.value in event.reasons


def test_decreasing_timestamp_on_higher_seq(detector, mock_clock):
    # Sequence increases, but timestamp drops backwards
    msg1 = TelemetryMessage(device_id="bed7", seq=100, timestamp=mock_clock.time(), ecg=80.0)
    detector.evaluate_message(msg1)

    # seq 101 arrives but has a timestamp earlier than seq 100's timestamp
    msg2 = TelemetryMessage(device_id="bed7", seq=101, timestamp=mock_clock.time() - 1.0, ecg=81.0)
    event2 = detector.evaluate_message(msg2)

    assert event2.replay_suspected
    assert ReplayReason.DECREASING_TIMESTAMP.value in event2.reasons


def test_state_not_updated_on_rejected_packet(detector, mock_clock):
    msg1 = TelemetryMessage(device_id="bed7", seq=100, timestamp=mock_clock.time(), ecg=80.0)
    detector.evaluate_message(msg1)
    state = detector.get_device_state("bed7")
    assert state.highest_seq == 100

    # Send a duplicate with seq 100
    mock_clock.advance(0.5)
    msg_dup = TelemetryMessage(device_id="bed7", seq=100, timestamp=mock_clock.time(), ecg=80.0)
    detector.evaluate_message(msg_dup)
    assert state.highest_seq == 100
    assert state.total_rejected == 1

    # Send a lower seq
    msg_low = TelemetryMessage(device_id="bed7", seq=50, timestamp=mock_clock.time(), ecg=80.0)
    detector.evaluate_message(msg_low)
    assert state.highest_seq == 100
    assert state.total_rejected == 2


def test_multi_device_isolation(detector, mock_clock):
    msg_bed7 = TelemetryMessage(device_id="bed7", seq=100, timestamp=mock_clock.time(), ecg=80.0)
    msg_bed8 = TelemetryMessage(device_id="bed8", seq=50, timestamp=mock_clock.time(), ecg=60.0)

    event7 = detector.evaluate_message(msg_bed7)
    event8 = detector.evaluate_message(msg_bed8)

    assert not event7.replay_suspected
    assert not event8.replay_suspected

    state7 = detector.get_device_state("bed7")
    state8 = detector.get_device_state("bed8")
    assert state7.highest_seq == 100
    assert state8.highest_seq == 50


def test_malformed_json_and_field_validations(detector):
    # Completely broken JSON
    event = detector.process_raw_payload("{invalid_json: 123")
    assert event.replay_suspected
    assert ReplayReason.MALFORMED_PAYLOAD.value in event.reasons

    # Missing seq
    event_missing_seq = detector.process_dict({
        "device_id": "bed7",
        "timestamp": 1791389000.0,
        "ecg": 80.0
    })
    assert event_missing_seq.replay_suspected
    assert ReplayReason.MALFORMED_PAYLOAD.value in event_missing_seq.reasons

    # Boolean as seq
    event_bool_seq = detector.process_dict({
        "device_id": "bed7",
        "seq": True,
        "timestamp": 1791389000.0,
        "ecg": 80.0
    })
    assert event_bool_seq.replay_suspected
    assert ReplayReason.MALFORMED_PAYLOAD.value in event_bool_seq.reasons

    # Boolean as ecg
    event_bool_ecg = detector.process_dict({
        "device_id": "bed7",
        "seq": 1,
        "timestamp": 1791389000.0,
        "ecg": False
    })
    assert event_bool_ecg.replay_suspected
    assert ReplayReason.MALFORMED_PAYLOAD.value in event_bool_ecg.reasons


def test_device_reset_workflow(detector, mock_clock):
    msg1 = TelemetryMessage(device_id="bed7", seq=500, timestamp=mock_clock.time(), ecg=80.0)
    detector.evaluate_message(msg1)
    assert detector.get_device_state("bed7").highest_seq == 500

    # Authorized operational reset
    assert detector.reset_device("bed7") is True
    assert detector.get_device_state("bed7") is None

    # After reset, seq 0 is accepted as a new start
    mock_clock.advance(1.0)
    msg_new = TelemetryMessage(device_id="bed7", seq=0, timestamp=mock_clock.time(), ecg=80.0)
    event_new = detector.evaluate_message(msg_new)
    assert not event_new.replay_suspected
    assert event_new.sequence_number == 0
