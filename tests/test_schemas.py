"""Automated Schema Validation Tests for TessNova Contracts.

Verifies strict compliance of:
1. telemetry.schema.json
2. m4_output.schema.json
3. m5_output.schema.json
4. incident_event.schema.json
"""

import json
from pathlib import Path
import pytest
from jsonschema import Draft202012Validator, ValidationError

CONTRACTS_DIR = Path(__file__).parent.parent / "contracts"
SAMPLES_DIR = Path(__file__).parent.parent / "samples"


def load_schema(name: str) -> dict:
    path = CONTRACTS_DIR / name
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(scope="module")
def telemetry_validator():
    schema = load_schema("telemetry.schema.json")
    return Draft202012Validator(schema)


@pytest.fixture(scope="module")
def m4_validator():
    schema = load_schema("m4_output.schema.json")
    return Draft202012Validator(schema)


@pytest.fixture(scope="module")
def m5_validator():
    schema = load_schema("m5_output.schema.json")
    return Draft202012Validator(schema)


@pytest.fixture(scope="module")
def incident_validator():
    schema = load_schema("incident_event.schema.json")
    return Draft202012Validator(schema)


def test_telemetry_valid_samples(telemetry_validator):
    normal_sample = json.loads((SAMPLES_DIR / "normal_message.json").read_text(encoding="utf-8"))
    assert telemetry_validator.is_valid(normal_sample)

    dup_sample = json.loads((SAMPLES_DIR / "duplicate_sequence.json").read_text(encoding="utf-8"))
    assert telemetry_validator.is_valid(dup_sample)

    stale_sample = json.loads((SAMPLES_DIR / "stale_timestamp.json").read_text(encoding="utf-8"))
    assert telemetry_validator.is_valid(stale_sample)


def test_telemetry_rejections(telemetry_validator):
    # Missing required field 'seq'
    with pytest.raises(ValidationError):
        telemetry_validator.validate({
            "device_id": "bed7",
            "timestamp": 1791389000.0,
            "ecg": 82.0
        })

    # Negative seq
    with pytest.raises(ValidationError):
        telemetry_validator.validate({
            "device_id": "bed7",
            "seq": -1,
            "timestamp": 1791389000.0,
            "ecg": 82.0
        })

    # Empty device_id
    with pytest.raises(ValidationError):
        telemetry_validator.validate({
            "device_id": "",
            "seq": 10,
            "timestamp": 1791389000.0,
            "ecg": 82.0
        })

    # Disallow unexpected fields
    with pytest.raises(ValidationError):
        telemetry_validator.validate({
            "device_id": "bed7",
            "seq": 10,
            "timestamp": 1791389000.0,
            "ecg": 82.0,
            "injected_command": "rm -rf /"
        })

    # In Python, True is an instance of int (bool subclass of int), but JSON schema type check
    # when parsed from JSON string {"seq": true} yields bool, which fails schema integer.
    raw_json_bool = '{"device_id": "bed7", "seq": true, "timestamp": 1791389000.0, "ecg": 82.0}'
    with pytest.raises(ValidationError):
        telemetry_validator.validate(json.loads(raw_json_bool))


def test_telemetry_rejects_raw_legacy_floats(telemetry_validator):
    """Verify that raw scalar numbers (legacy ECG values) are rejected as invalid JSON objects."""
    with pytest.raises(ValidationError):
        telemetry_validator.validate(82.5)


def test_m4_output_validity(m4_validator):
    valid_m4_event = {
        "device_id": "bed7",
        "detector": "M4",
        "replay_suspected": True,
        "reasons": ["duplicate_sequence"],
        "sequence_number": 101,
        "event_timestamp": 1791389000.0,
        "observed_at": 1791389002.0,
        "schema_version": "1.0"
    }
    assert m4_validator.is_valid(valid_m4_event)

    # Missing detector const fails
    with pytest.raises(ValidationError):
        invalid_detector = dict(valid_m4_event)
        invalid_detector["detector"] = "M3"
        m4_validator.validate(invalid_detector)


def test_m5_output_validity(m5_validator):
    valid_active = {
        "device_id": "bed7",
        "detector": "M5",
        "status": "active",
        "network_suspicion_score": 0.88,
        "model_version": "rf-baseline-v1",
        "reasons": ["high_message_jitter", "burst_rate_exceeded"],
        "observed_at": 1791389005.0
    }
    assert m5_validator.is_valid(valid_active)

    # Unavailable model status with null score
    valid_unavailable = {
        "device_id": "bed7",
        "detector": "M5",
        "status": "unavailable",
        "network_suspicion_score": None,
        "model_version": "none",
        "reasons": ["model_artifact_not_found"],
        "observed_at": 1791389005.0
    }
    assert m5_validator.is_valid(valid_unavailable)


def test_incident_sample_validity(incident_validator):
    incident_sample = json.loads((SAMPLES_DIR / "sample_incident.json").read_text(encoding="utf-8"))
    assert incident_validator.is_valid(incident_sample)
