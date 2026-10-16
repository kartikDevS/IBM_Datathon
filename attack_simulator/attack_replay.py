"""Replay Attack Simulator.

Simulates capturing a series of legitimate bedside telemetry packets and re-transmitting
them to the MQTT broker. Exercises M4 replay detection on:
1. Verbatim replay (duplicate seq + stale timestamp).
2. Duplicate sequence replay (duplicate seq + updated timestamp).
3. Stale timestamp injection.
"""

import time
from attack_simulator.common import BaseSimulator, generate_synthetic_ecg, get_base_parser


def run_replay_attack(
    device_id: str = "bed7",
    count: int = 15,
    interval: float = 0.5,
    start_seq: int = 200,
    replay_mode: str = "verbatim",
    broker_host: str = "localhost",
    broker_port: int = 1883,
    dry_run: bool = False,
):
    sim = BaseSimulator(
        scenario_name="attack_replay",
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

    sim.logger.info("Starting Replay Attack Simulation: device=%s, mode=%s", device_id, replay_mode)
    captured_messages = []

    try:
        # Phase 1: Legitimate transmission and capture
        phase1_count = min(5, count // 2)
        sim.logger.info("[PHASE 1] Publishing and capturing %d baseline messages...", phase1_count)
        for i in range(phase1_count):
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
            captured_messages.append(payload)
            sim.publish_message(payload)
            time.sleep(interval)

        # Pause between transmission and attack
        time.sleep(1.0)

        # Phase 2: Replay Transmission
        sim.logger.warning("[PHASE 2 - ATTACK] Replaying captured messages under mode '%s'...", replay_mode)
        for original in captured_messages:
            replay_payload = dict(original)
            if replay_mode == "verbatim":
                # Stale timestamp AND duplicate seq
                pass
            elif replay_mode == "dup_seq":
                # Fresh timestamp but duplicate sequence number
                replay_payload["timestamp"] = round(time.time(), 3)
            elif replay_mode == "stale_ts":
                # Advanced sequence number but stale timestamp
                replay_payload["seq"] = start_seq + 50
                replay_payload["timestamp"] = round(time.time() - 30.0, 3)

            sim.logger.warning(
                "[SIMULATION ATTACK] Replaying seq=%d, ts=%.3f, ecg=%.2f",
                replay_payload["seq"],
                replay_payload["timestamp"],
                replay_payload["ecg"],
            )
            sim.publish_message(replay_payload)
            time.sleep(interval)

    finally:
        sim.close()


def main():
    parser = get_base_parser("Replay Attack Telemetry Simulator")
    parser.add_argument(
        "--mode",
        choices=["verbatim", "dup_seq", "stale_ts"],
        default="verbatim",
        help="Replay mode (verbatim, dup_seq, stale_ts; default: verbatim)",
    )
    args = parser.parse_args()

    run_replay_attack(
        device_id=args.device_id,
        count=args.count,
        interval=args.interval,
        start_seq=args.start_seq,
        replay_mode=args.mode,
        broker_host=args.broker,
        broker_port=args.port,
        dry_run=args.dry_run,
    )


if __name__ == "__main__":
    main()
