"""Normal Telemetry Sender.

Publishes valid, standard-compliant telemetry messages with monotonically increasing
sequence numbers, current timestamps, and plausible synthetic ECG readings.
"""

import time
from attack_simulator.common import BaseSimulator, generate_synthetic_ecg, get_base_parser


def run_normal_sender(
    device_id: str = "bed7",
    count: int = 20,
    interval: float = 0.5,
    start_seq: int = 100,
    broker_host: str = "localhost",
    broker_port: int = 1883,
    dry_run: bool = False,
):
    sim = BaseSimulator(
        scenario_name="normal_sender",
        device_id=device_id,
        broker_host=broker_host,
        broker_port=broker_port,
        count=count,
        interval=interval,
        start_seq=start_seq,
        dry_run=dry_run,
    )

    if not sim.connect():
        return

    sim.logger.info("Starting Normal Telemetry stream: device=%s, count=%d, interval=%.2fs", device_id, count, interval)
    try:
        for i in range(count):
            seq = start_seq + i
            ts = time.time()
            val = generate_synthetic_ecg(i)

            payload = {
                "device_id": device_id,
                "seq": seq,
                "timestamp": round(ts, 3),
                "ecg": val,
                "schema_version": "1.0",
            }
            sim.publish_message(payload)
            time.sleep(interval)
    finally:
        sim.close()


def main():
    parser = get_base_parser("Normal Bedside Monitor Telemetry Sender")
    args = parser.parse_args()

    run_normal_sender(
        device_id=args.device_id,
        count=args.count,
        interval=args.interval,
        start_seq=args.start_seq,
        broker_host=args.broker,
        broker_port=args.port,
        dry_run=args.dry_run,
    )


if __name__ == "__main__":
    main()
