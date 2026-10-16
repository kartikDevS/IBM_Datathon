"""Spike Injection Attack Simulation.

Injects an abrupt, abnormal physiological or cyber-induced spike into the ECG stream.
Tests downstream clinical alarms vs. cybersecurity witness correlation.
"""

import time
from attack_simulator.common import BaseSimulator, generate_synthetic_ecg, get_base_parser


def run_spike_injection(
    device_id: str = "bed7",
    count: int = 20,
    interval: float = 0.5,
    start_seq: int = 100,
    spike_at: int = 8,
    spike_magnitude: float = 120.0,
    broker_host: str = "localhost",
    broker_port: int = 1883,
    dry_run: bool = False,
):
    sim = BaseSimulator(
        scenario_name="attack_spike",
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

    sim.logger.info("Starting Spike Injection: device=%s, spike_at_step=%d, magnitude=+%.1f", device_id, spike_at, spike_magnitude)
    try:
        for i in range(count):
            seq = start_seq + i
            ts = time.time()
            val = generate_synthetic_ecg(i)

            is_spike = (i == spike_at or i == spike_at + 1)
            if is_spike:
                val = round(val + spike_magnitude, 2)
                sim.logger.warning("[SIMULATION ATTACK] Injected anomalous spike: %.2f bpm at seq=%d", val, seq)

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
    parser = get_base_parser("Spike Injection Telemetry Simulator")
    parser.add_argument("--spike-at", type=int, default=8, help="Step index at which spike occurs (default: 8)")
    parser.add_argument("--spike-magnitude", type=float, default=120.0, help="Magnitude added during spike (default: 120.0)")
    args = parser.parse_args()

    run_spike_injection(
        device_id=args.device_id,
        count=args.count,
        interval=args.interval,
        start_seq=args.start_seq,
        spike_at=args.spike_at,
        spike_magnitude=args.spike_magnitude,
        broker_host=args.broker,
        broker_port=args.port,
        dry_run=args.dry_run,
    )


if __name__ == "__main__":
    main()
