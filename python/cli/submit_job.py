"""
Submit a job to the Neuron Network.

Usage:
  python3 cli/submit_job.py --target HOST:PORT --type inference --prompt "explain gravity"
  python3 cli/submit_job.py --target HOST:PORT --type benchmark
  python3 cli/submit_job.py --target HOST:PORT --type echo --message "hello neuron"
"""
from __future__ import annotations

import asyncio
import argparse
import json
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.identity import get_or_create_identity


async def send_and_receive(host: str, port: int, message: dict) -> dict | None:
    """Connect, send a message, receive response."""
    reader, writer = await asyncio.open_connection(host, port)

    identity = get_or_create_identity()

    # Handshake
    handshake = {
        "type": "handshake",
        "node_id": identity.node_id,
        "public_key": identity.public_key.hex(),
        "timestamp": time.time(),
    }
    payload = json.dumps(handshake).encode()
    writer.write(struct.pack("!I", len(payload)) + payload)
    await writer.drain()

    # Read handshake ack
    header = await reader.readexactly(4)
    length = struct.unpack("!I", header)[0]
    data = await reader.readexactly(length)
    ack = json.loads(data.decode())

    if ack.get("type") != "handshake_ack":
        print("Handshake failed!")
        writer.close()
        return None

    print(f"Connected to node {ack['node_id'][:16]}...")

    # Send job request (with 0x00 plaintext flag byte for _recv_encrypted)
    payload = json.dumps(message).encode()
    frame = b"\x00" + payload
    writer.write(struct.pack("!I", len(frame)) + frame)
    await writer.drain()

    # Read responses until we get a job_result
    # (may receive peer_list_request or heartbeats first)
    response = None
    for _ in range(20):  # max 20 messages to wait through
        try:
            header = await asyncio.wait_for(reader.readexactly(4), timeout=60)
            length = struct.unpack("!I", header)[0]
            data = await reader.readexactly(length)
            # Strip flag byte (0x00 plaintext or 0x01 encrypted)
            if len(data) > 0 and data[0] in (0x00, 0x01):
                data = data[1:]
            msg = json.loads(data.decode())

            if msg.get("type") == "job_result":
                response = msg
                break
            # Skip non-result messages (peer_list_request, heartbeats, etc.)
        except asyncio.TimeoutError:
            print("Timeout waiting for result.")
            break
        except Exception:
            break

    writer.close()
    await writer.wait_closed()
    return response


async def main():
    parser = argparse.ArgumentParser(description="Submit a job to Neuron Network")
    parser.add_argument("--target", required=True, help="Target node (host:port)")
    parser.add_argument("--type", default="echo", help="Job type: echo, benchmark, inference")
    parser.add_argument("--prompt", default="", help="Prompt for inference jobs")
    parser.add_argument("--model", default="", help="Model name for inference")
    parser.add_argument("--message", default="hello neuron", help="Message for echo jobs")
    parser.add_argument("--direct", action="store_true", help="Bypass scheduler, send directly to target")
    args = parser.parse_args()

    host, port = args.target.rsplit(":", 1)

    # Build payload
    payload = {}
    if args.type == "echo":
        payload = {"message": args.message}
    elif args.type == "benchmark":
        payload = {}
    elif args.type == "inference":
        payload = {"prompt": args.prompt, "model": args.model, "max_tokens": 256}

    # Use scheduler by default — let the network pick the best node
    if args.direct:
        job_request = {"type": "job_request", "job_type": args.type, "payload": payload}
    else:
        job_request = {
            "type": "schedule_job",
            "job_type": args.type,
            "model": args.model or "",
            "payload": payload,
        }

    print(f"\nSubmitting {args.type} job to {host}:{port}...")
    start = time.time()

    response = await send_and_receive(host, int(port), job_request)

    elapsed = time.time() - start

    if response:
        print(f"\n{'=' * 60}")
        print(f"  JOB RESULT")
        print(f"{'=' * 60}")
        print(f"  Status:   {response.get('status', 'unknown')}")
        print(f"  Worker:   {response.get('worker_node', 'unknown')[:16]}...")
        print(f"  Duration: {response.get('duration_s', 0):.3f}s")
        print(f"  Round-trip: {elapsed:.3f}s")

        result = response.get("result", {})
        if isinstance(result, dict):
            print(f"\n  Result:")
            for k, v in result.items():
                print(f"    {k}: {v}")
        elif result:
            print(f"\n  Result: {result}")

        error = response.get("error")
        if error:
            print(f"\n  Error: {error}")

        print(f"{'=' * 60}\n")
    else:
        print("No response received.")


if __name__ == "__main__":
    asyncio.run(main())
