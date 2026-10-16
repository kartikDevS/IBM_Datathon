"""Bias Injection Attack Simulation.

Adds a configurable constant offset to the legitimate waveform.
Simulates a Man-in-the-Middle (MitM) integrity tamper or calibration bias.
"""

import time
from attack_simulator.common import BaseSimulator, generate_synthetic_ecg, get_base_parser


def run_bias_injection(
    device_id: str = "bed7",
    count: int = 20,
    interval: float = 0.5,
    start_seq: int = 100,
    bias_offset: float = 35.0,
    broker_host: str = "localhost",
    broker_port: int = 1883,
    dry_run: bool = False,
):
    sim = BaseSimulator(
        scenario_name="attack_bias",
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

    sim.logger.info("Starting Bias Injection: device=%s, constant_offset=+%.1f", device_id, bias_offset)
    try:
        for i in range(count):
            seq = start_seq + i
            ts = time.time()
            base_val = generate_synthetic_ecg(i)
            biased_val = round(base_val + bias_offset, 2)

            payload = {
                "device_id": device_id,
                "seq": seq,
                "timestamp": round(ts, 3),
                "ecg": biased_val,
                "schema_version": "1.0",
            }
            sim.publish_message(payload)
            time.sleep(interval)
    finally:
        sim.close()


def main():
    parser = get_base_parser("Bias Injection Telemetry Simulator")
    parser.add_argument("--bias-offset", type=float, default=35.0, help="Constant offset added to ECG (default: 35.0)")
    args = parser.parse_args()

    run_bias_injection(
        device_id=args.device_id,
        count=args.count,
        interval=args.interval,
        start_seq=args.start_seq,
        bias_offset=args.bias_offset,
        broker_host=args.broker,
        broker_port=args.port,
        dry_run=args.dry_run,
    )


if __name__ == "__main__":
    main()
