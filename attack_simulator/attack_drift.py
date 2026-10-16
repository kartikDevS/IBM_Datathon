"""Slow Drift Attack / Sensor Degradation Simulation.

Gradually shifts the reading over time with a configurable rate of change.
Can represent subtle stealth sensor spoofing or progressive electrode impedance drift.
"""

import time
from attack_simulator.common import BaseSimulator, generate_synthetic_ecg, get_base_parser


def run_drift_simulation(
    device_id: str = "bed7",
    count: int = 25,
    interval: float = 0.5,
    start_seq: int = 100,
    drift_rate: float = 2.5,
    broker_host: str = "localhost",
    broker_port: int = 1883,
    dry_run: bool = False,
):
    sim = BaseSimulator(
        scenario_name="attack_drift",
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

    sim.logger.info("Starting Drift Simulation: device=%s, drift_rate=%.2f bpm/sample", device_id, drift_rate)
    try:
        for i in range(count):
            seq = start_seq + i
            ts = time.time()
            base_val = generate_synthetic_ecg(i)
            drift_offset = i * drift_rate
            drifted_val = round(base_val + drift_offset, 2)

            payload = {
                "device_id": device_id,
                "seq": seq,
                "timestamp": round(ts, 3),
                "ecg": drifted_val,
                "schema_version": "1.0",
            }
            sim.publish_message(payload)
            time.sleep(interval)
    finally:
        sim.close()


def main():
    parser = get_base_parser("Slow Drift Telemetry Simulator")
    parser.add_argument("--drift-rate", type=float, default=2.5, help="Drift increment added per message (default: 2.5)")
    args = parser.parse_args()

    run_drift_simulation(
        device_id=args.device_id,
        count=args.count,
        interval=args.interval,
        start_seq=args.start_seq,
        drift_rate=args.drift_rate,
        broker_host=args.broker,
        broker_port=args.port,
        dry_run=args.dry_run,
    )


if __name__ == "__main__":
    main()
