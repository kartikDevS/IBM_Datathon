"""MQTT Replay Listener for M4.

Subscribes to hospital telemetry MQTT topics, parses incoming JSON payloads,
evaluates them with ReplayDetector, and publishes detection events to a security topic.
Includes offline mock mode for testing without a live broker.
"""

from __future__ import annotations
import argparse
import json
import logging
import sys
import time
import uuid
from typing import Optional

try:
    import paho.mqtt.client as mqtt
except ImportError:
    mqtt = None

from m4_replay.replay_detector import ReplayDetector

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
)
logger = logging.getLogger("m4_listener")


class MqttReplayListener:
    """MQTT subscriber that ingests ward telemetry and emits M4 replay detection events."""

    def __init__(
        self,
        broker_host: str = "localhost",
        broker_port: int = 1883,
        telemetry_topic: str = "ward/+/ecg",
        event_topic: str = "hospital/security/m4_replay",
        client_id: Optional[str] = None,
        stale_threshold: float = 5.0,
        detector: Optional[ReplayDetector] = None,
    ):
        self.broker_host = broker_host
        self.broker_port = broker_port
        self.telemetry_topic = telemetry_topic
        self.event_topic = event_topic
        self.client_id = client_id or f"m4_listener_{uuid.uuid4().hex[:8]}"
        self.detector = detector or ReplayDetector(stale_threshold_seconds=stale_threshold)
        self.client: Optional[mqtt.Client] = None
        self._running = False

    def on_connect(self, client, userdata, flags, rc, properties=None):
        if rc == 0:
            logger.info("Connected to broker at %s:%d. Subscribing to %s", self.broker_host, self.broker_port, self.telemetry_topic)
            client.subscribe(self.telemetry_topic, qos=1)
        else:
            logger.error("Failed to connect to MQTT broker with return code: %d", rc)

    def on_disconnect(self, client, userdata, rc, properties=None):
        if rc != 0:
            logger.warning("Unexpected MQTT broker disconnection (rc=%d). Auto-reconnecting...", rc)
        else:
            logger.info("Gracefully disconnected from MQTT broker.")

    def on_message(self, client, userdata, msg):
        try:
            event = self.detector.process_raw_payload(msg.payload)
            event_json = event.to_json()

            if event.replay_suspected:
                logger.warning(
                    "ALERT [M4]: Replay suspected on device %s! Reasons: %s (seq=%s)",
                    event.device_id,
                    event.reasons,
                    event.sequence_number,
                )
            else:
                logger.debug("M4 OK: device %s seq=%s", event.device_id, event.sequence_number)

            # Publish detection event to security channel
            if client:
                client.publish(self.event_topic, event_json, qos=1)
        except Exception as exc:
            logger.error("Error processing message from topic %s: %s", msg.topic, exc)

    def start(self):
        """Connect to broker and start listener loop."""
        if mqtt is None:
            logger.error("paho-mqtt library is not installed.")
            sys.exit(1)

        self.client = mqtt.Client(
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
            client_id=self.client_id,
        )
        self.client.on_connect = self.on_connect
        self.client.on_disconnect = self.on_disconnect
        self.client.on_message = self.on_message

        logger.info("Starting M4 MQTT Replay Listener (client_id: %s)...", self.client_id)
        try:
            self.client.connect(self.broker_host, self.broker_port, keepalive=60)
            self._running = True
            self.client.loop_forever()
        except KeyboardInterrupt:
            logger.info("M4 listener stopping due to KeyboardInterrupt.")
            self.stop()
        except Exception as exc:
            logger.error("Connection error: %s", exc)
            self.stop()
            raise

    def stop(self):
        self._running = False
        if self.client:
            self.client.disconnect()


def run_local_mock_test(stale_threshold: float = 5.0):
    """Run an offline demonstration of M4 without requiring a live MQTT broker."""
    logger.info("--- Starting M4 Offline Mock Simulation ---")
    detector = ReplayDetector(stale_threshold_seconds=stale_threshold)

    # Simulated stream of packets
    now = time.time()
    packets = [
        {"desc": "Normal initial packet", "data": {"device_id": "bed7", "seq": 100, "timestamp": now, "ecg": 72.0}},
        {"desc": "Normal sequence advance", "data": {"device_id": "bed7", "seq": 101, "timestamp": now + 0.1, "ecg": 72.5}},
        {"desc": "Duplicate sequence replay", "data": {"device_id": "bed7", "seq": 101, "timestamp": now + 0.2, "ecg": 72.5}},
        {"desc": "Stale timestamp packet", "data": {"device_id": "bed7", "seq": 102, "timestamp": now - 20.0, "ecg": 73.0}},
        {"desc": "Lower sequence packet", "data": {"device_id": "bed7", "seq": 90, "timestamp": now + 0.3, "ecg": 71.0}},
        {"desc": "Independent device (bed8) normal", "data": {"device_id": "bed8", "seq": 1, "timestamp": now + 0.4, "ecg": 65.0}},
    ]

    for p in packets:
        print(f"\nProcessing: {p['desc']}")
        raw = json.dumps(p["data"])
        event = detector.process_raw_payload(raw)
        print(f"Result: {event.to_json()}")

    logger.info("--- Offline Mock Simulation Complete ---")


def main():
    parser = argparse.ArgumentParser(description="M4 MQTT Replay Listener")
    parser.add_argument("--broker", default="localhost", help="MQTT broker address (default: localhost)")
    parser.add_argument("--port", type=int, default=1883, help="MQTT broker port (default: 1883)")
    parser.add_argument("--topic", default="ward/+/ecg", help="Topic filter to subscribe (default: ward/+/ecg)")
    parser.add_argument("--event-topic", default="hospital/security/m4_replay", help="Topic to publish M4 alerts")
    parser.add_argument("--stale-threshold", type=float, default=5.0, help="Freshness threshold in seconds")
    parser.add_argument("--local-test", action="store_true", help="Run local offline mock test without broker")

    args = parser.parse_args()

    if args.local_test:
        run_local_mock_test(stale_threshold=args.stale_threshold)
    else:
        listener = MqttReplayListener(
            broker_host=args.broker,
            broker_port=args.port,
            telemetry_topic=args.topic,
            event_topic=args.event_topic,
            stale_threshold=args.stale_threshold,
        )
        listener.start()


if __name__ == "__main__":
    main()
