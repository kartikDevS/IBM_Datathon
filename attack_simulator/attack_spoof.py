"""Identity and Topic Spoofing Simulator.

Simulates an unauthorized publisher injecting messages into another device's MQTT topic
or mismatching the payload device_id with the MQTT topic destination.

SECURITY NOTE:
Altering a JSON `device_id` field inside a payload does NOT constitute authenticated identity!
Legitimate authentication and authorization are strictly enforced by the MQTT broker via
client credentials (username/password or TLS client certificates) and Mosquitto Topic ACLs.
This script demonstrates why payload validation alone is insufficient without broker-level ACL enforcement.
"""

import time
from attack_simulator.common import BaseSimulator, generate_synthetic_ecg, get_base_parser


def run_spoofing_simulation(
    target_device: str = "bed7",
    spoofed_identity: str = "bed99_unauthorized",
    target_topic: str = "ward/bed7/ecg",
    count: int = 10,
    interval: float = 0.5,
    start_seq: int = 500,
    broker_host: str = "localhost",
    broker_port: int = 1883,
    dry_run: bool = False,
):
    sim = BaseSimulator(
        scenario_name="attack_spoof",
        device_id=spoofed_identity,
        broker_host=broker_host,
        broker_port=broker_port,
        topic=target_topic,
        count=count,
        interval=interval,
        start_seq=start_seq,
        dry_run=dry_run,
        client_id=f"rogue_publisher_{spoofed_identity}",
    )

    if not sim.connect():
        return

    sim.logger.warning(
        "[SPOOFING SIMULATION] Unauthorized client '%s' attempting to publish into topic '%s' claiming device_id='%s'",
        sim.client_id,
        target_topic,
        spoofed_identity,
    )
    try:
        for i in range(count):
            seq = start_seq + i
            ts = time.time()
            val = generate_synthetic_ecg(i, base_rate=140.0)  # Abnormal tachycardia

            payload = {
                "device_id": spoofed_identity,  # Identity mismatch relative to target topic bed7
                "seq": seq,
                "timestamp": round(ts, 3),
                "ecg": val,
                "schema_version": "1.0",
            }
            sim.publish_message(payload, custom_topic=target_topic)
            time.sleep(interval)
    finally:
        sim.close()


def main():
    parser = get_base_parser("Identity and Topic Spoofing Telemetry Simulator")
    parser.add_argument("--target-device", default="bed7", help="Legitimate device whose topic is targeted (default: bed7)")
    parser.add_argument("--spoofed-id", default="bed99_rogue", help="Spoofed device_id in JSON payload (default: bed99_rogue)")
    parser.add_argument("--target-topic", default="ward/bed7/ecg", help="Target MQTT topic to inject into")
    args = parser.parse_args()

    run_spoofing_simulation(
        target_device=args.target_device,
        spoofed_identity=args.spoofed_id,
        target_topic=args.target_topic,
        count=args.count,
        interval=args.interval,
        start_seq=args.start_seq,
        broker_host=args.broker,
        broker_port=args.port,
        dry_run=args.dry_run,
    )


if __name__ == "__main__":
    main()
