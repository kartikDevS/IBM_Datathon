"""Stuck-Value Sensor Fault Simulator.

Repeatedly publishes the exact same ECG reading while sequence numbers and timestamps
continue to advance normally.
NOTE: This represents a physical sensor freeze or ADC fault scenario, NOT automatically a cyberattack.
Used to test whether diagnostic agents can differentiate hardware faults from cyber intrusions.
"""

import time
from attack_simulator.common import BaseSimulator, get_base_parser


def run_stuck_fault(
    device_id: str = "bed7",
    count: int = 20,
    interval: float = 0.5,
    start_seq: int = 100,
    stuck_value: float = 78.4,
    broker_host: str = "localhost",
    broker_port: int = 1883,
    dry_run: bool = False,
):
    sim = BaseSimulator(
        scenario_name="fault_stuck_sensor",
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

    sim.logger.info("Starting Stuck-Value Sensor Fault: device=%s, fixed_value=%.2f", device_id, stuck_value)
    try:
        for i in range(count):
            seq = start_seq + i
            ts = time.time()

            payload = {
                "device_id": device_id,
                "seq": seq,
                "timestamp": round(ts, 3),
                "ecg": stuck_value,
                "schema_version": "1.0",
            }
            sim.publish_message(payload)
            time.sleep(interval)
    finally:
        sim.close()


def main():
    parser = get_base_parser("Stuck-Value Sensor Fault Simulator")
    parser.add_argument("--stuck-value", type=float, default=78.4, help="Constant stuck ECG reading (default: 78.4)")
    args = parser.parse_args()

    run_stuck_fault(
        device_id=args.device_id,
        count=args.count,
        interval=args.interval,
        start_seq=args.start_seq,
        stuck_value=args.stuck_value,
        broker_host=args.broker,
        broker_port=args.port,
        dry_run=args.dry_run,
    )


if __name__ == "__main__":
    main()
