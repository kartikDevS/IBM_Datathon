"""Common utilities and base publisher for TessNova Attack and Fault Simulators."""

from __future__ import annotations
import argparse
import json
import logging
import math
import sys
import time
import uuid
from typing import Callable, Generator, Optional, Tuple, Any

try:
    import paho.mqtt.client as mqtt
except ImportError:
    mqtt = None

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
)


def get_base_parser(description: str) -> argparse.ArgumentParser:
    """Standardized command line options across all simulation scripts."""
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--broker", default="localhost", help="MQTT broker host (default: localhost)")
    parser.add_argument("--port", type=int, default=1883, help="MQTT broker port (default: 1883)")
    parser.add_argument("--device-id", default="bed7", help="Target bedside monitor ID (default: bed7)")
    parser.add_argument("--topic", default=None, help="Custom MQTT topic (default: ward/<device_id>/ecg)")
    parser.add_argument("--count", type=int, default=20, help="Number of telemetry messages to publish (default: 20)")
    parser.add_argument("--interval", type=float, default=0.5, help="Publish interval in seconds (default: 0.5s)")
    parser.add_argument("--start-seq", type=int, default=100, help="Initial sequence number (default: 100)")
    parser.add_argument("--dry-run", action="store_true", help="Print messages to console without sending over network")
    parser.add_argument("--client-id", default=None, help="Explicit MQTT client ID")
    return parser


def generate_synthetic_ecg(step: int, base_rate: float = 75.0) -> float:
    """Generate plausible, non-clinical synthetic waveform sample.
    
    Combines a sine wave with pseudo-respiratory oscillation for test visualization.
    NOT a real patient ECG and not intended for clinical use.
    """
    t = step * 0.1
    # Base sinusoidal component + secondary harmonic
    reading = base_rate + 12.0 * math.sin(t * 3.14159) + 4.0 * math.cos(t * 1.5)
    return round(reading, 2)


class BaseSimulator:
    """Base runner for publishing telemetry scenarios with strict safety bounds."""

    def __init__(
        self,
        scenario_name: str,
        device_id: str,
        broker_host: str = "localhost",
        broker_port: int = 1883,
        topic: Optional[str] = None,
        count: int = 20,
        interval: float = 0.5,
        start_seq: int = 100,
        dry_run: bool = False,
        client_id: Optional[str] = None,
    ):
        self.scenario_name = scenario_name
        self.device_id = device_id
        self.broker_host = broker_host
        self.broker_port = broker_port
        self.topic = topic or f"ward/{device_id}/ecg"
        self.count = max(1, min(count, 5000))  # strictly bounded
        self.interval = max(0.01, interval)    # bounded floor
        self.start_seq = max(0, start_seq)
        self.dry_run = dry_run
        self.client_id = client_id or f"sim_{scenario_name}_{uuid.uuid4().hex[:6]}"
        self.logger = logging.getLogger(f"sim.{scenario_name}")
        self.client: Optional[mqtt.Client] = None

    def connect(self) -> bool:
        if self.dry_run:
            self.logger.info("[DRY RUN] Simulating local execution without broker connection.")
            return True

        if mqtt is None:
            self.logger.error("paho-mqtt is not installed. Use --dry-run or install dependencies.")
            return False

        try:
            self.client = mqtt.Client(
                callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
                client_id=self.client_id,
            )
            self.client.connect(self.broker_host, self.broker_port, keepalive=60)
            self.client.loop_start()
            self.logger.info("Connected to broker at %s:%d as client '%s'", self.broker_host, self.broker_port, self.client_id)
            return True
        except Exception as exc:
            self.logger.warning("Could not connect to broker (%s). Falling back to dry-run output mode.", exc)
            self.dry_run = True
            return True

    def publish_message(self, payload_dict: dict, custom_topic: Optional[str] = None) -> bool:
        raw_json = json.dumps(payload_dict)
        target_topic = custom_topic or self.topic

        if self.dry_run:
            print(f"[{self.scenario_name}] [DRY-RUN] Topic: {target_topic} -> Payload: {raw_json}")
            return True

        if self.client:
            res = self.client.publish(target_topic, raw_json, qos=1)
            res.wait_for_publish(timeout=2.0)
            self.logger.info("Published to %s (seq=%s, ecg=%s)", target_topic, payload_dict.get("seq"), payload_dict.get("ecg"))
            return True
        return False

    def close(self):
        if self.client:
            self.client.loop_stop()
            self.client.disconnect()
            self.logger.info("Simulator client disconnected.")
