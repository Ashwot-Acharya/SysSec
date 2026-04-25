"""
Test WebSocket client — connects to the anomaly detection server
and pretty-prints incoming messages.

Usage:
    python test_client.py
"""

import asyncio
import json
import websockets

SERVER_URI = "ws://localhost:8000/ws"

COLORS = {
    "welcome": "\033[96m",   # cyan
    "syscall": "\033[0m",    # default
    "anomaly": "\033[91m",   # bright red
    "stats":   "\033[93m",   # yellow
    "ping":    "\033[90m",   # grey
    "reset":   "\033[0m",
}


async def listen() -> None:
    print(f"Connecting to {SERVER_URI} …\n")
    async with websockets.connect(SERVER_URI) as ws:
        async for raw in ws:
            msg = json.loads(raw)
            t = msg.get("type", "?")
            color = COLORS.get(t, "")
            reset = COLORS["reset"]

            if t == "anomaly":
                print(f"{color}{'─'*60}")
                print(f"  ⚠  ANOMALY DETECTED")
                print(f"  Score      : {msg['anomaly_score']}")
                print(f"  Reason     : {msg['failure_reason']}")
                print(f"  Window     : {msg['window_sequence']}")
                print(f"  Expected   : {msg['expected_tokens']}")
                print(f"{'─'*60}{reset}")
            elif t == "syscall":
                print(f"{color}[{msg['timestamp']}] {msg['thread']}({msg['pid']}) "
                      f"{msg['syscall']}({msg['args']}) = {msg['return_value']}{reset}")
            elif t == "stats":
                print(f"{color}[STATS] total={msg['total_syscalls']} "
                      f"anomalies={msg['total_anomalies']} "
                      f"rate={msg['anomaly_rate']:.5f} "
                      f"rps={msg['recent_syscalls_per_second']}{reset}")
            elif t == "welcome":
                print(f"{color}[SERVER] {msg['message']}{reset}\n")
            elif t == "ping":
                await ws.send(json.dumps({"type": "pong"}))
            else:
                print(f"[?] {msg}")


if __name__ == "__main__":
    try:
        asyncio.run(listen())
    except KeyboardInterrupt:
        print("\nDisconnected.")