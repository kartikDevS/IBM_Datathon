"""Bounded Flooding / Denial-of-Service Simulator.

Publishes messages at a rapid, strictly bounded rate to test broker rate-limiting,
M5 burst/jitter features, and ingestion buffer stability.

SAFETY RESTRICTIONS:
1. Requires explicit opt-in flag `--enable-flood-test`.
2. Strictly bounded maximum message count (hard limit 500) and maximum rate (hard limit 50 msgs/sec).
3. Restricted by default to loopback/local test broker only (`localhost` or `127.0.0.1`).
4. NEVER targeted against production, hospital, or third-party infrastructure.
"""

import sys
import time
from attack_simulator.common import BaseSimulator, generate_synthetic_ecg, get_base_parser


def run_flood_simulation(
    device_id: str = "bed7",
    count: int = 100,
    rate_per_sec: float = 20.0,
    start_seq: int = 1000,
    broker_host: str = "localhost",
    broker_port: int = 1883,
    dry_run: bool = False,
    enable_flood_test: bool = False,
):
    if not enable_flood_test:
        print("\n[SAFETY BLOCKER] Flooding simulation aborted.")
        print("To run bounded stress testing in an authorized local lab, you MUST supply the flag:")
        print("  --enable-flood-test\n")
        sys.exit(2)

    # Restrict to local targets only
    if broker_host.lower() not in ["localhost", "127.0.0.1", "::1"] and not dry_run:
        print(f"[SAFETY ERROR] Bounded flood test prohibited against non-loopback host '{broker_host}'!")
        sys.exit(3)

    # Hard safety bounds
    count = min(count, 500)
    rate_per_sec = min(max(1.0, rate_per_sec), 50.0)
    delay = 1.0 / rate_per_sec

    sim = BaseSimulator(
        scenario_name="attack_flood",
        device_id=device_id,
        broker_host=broker_host,
        broker_port=broker_port,
        count=count,
        interval=delay,
        start_seq=start_seq,
        dry_run=dry_run,
    )

    if not sim.connect():
        return

    sim.logger.warning(
        "[BOUNDED FLOOD SIMULATION] Rate: %.1f msgs/sec (delay: %.3fs), Max count: %d, Target: %s",
        rate_per_sec,
        delay,
        count,
        broker_host,
    )

    start_time = time.time()
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
            time.sleep(delay)
    finally:
        sim.close()
        elapsed = time.time() - start_time
        sim.logger.info("Flood test concluded. Published %d messages in %.2f seconds (effective rate: %.1f msg/s)", count, elapsed, count / max(0.001, elapsed))


def main():
    parser = get_base_parser("Bounded Flooding Telemetry Simulator")
    parser.add_argument("--rate", type=float, default=20.0, help="Messages per second (bounded max 50.0; default: 20.0)")
    parser.add_argument(
        "--enable-flood-test",
        action="store_true",
        help="MANDATORY opt-in safety flag to authorize local test flood",
    )
    args = parser.parse_args()

    run_flood_simulation(
        device_id=args.device_id,
        count=args.count,
        rate_per_sec=args.rate,
        start_seq=args.start_seq,
        broker_host=args.broker,
        broker_port=args.port,
        dry_run=args.dry_run,
        enable_flood_test=args.enable_flood_test,
    )


if __name__ == "__main__":
    main()
