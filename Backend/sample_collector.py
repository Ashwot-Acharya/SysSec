"""
Sample Syscall Collector — feeds syscall data into the server via WebSocket.

This demonstrates how an external collector (perf trace, strace, etc.)
would send real syscall data to the server. Replace the SAMPLE_DATA
loop with actual perf trace / strace output parsing.

Usage:
    python sample_collector.py
"""

import asyncio
import json
import websockets

INGEST_URI = "ws://localhost:8000/ws/ingest"

# Sample data simulating real syscalls
SAMPLE_DATA = [
    {"timestamp": "6425.801", "thread": "Thread-1", "pid": 14298, "syscall": "recvfrom", "args": "fd: 4", "return_value": 438},
    {"timestamp": "6425.808", "thread": "Thread-1", "pid": 14298, "syscall": "openat", "args": "filename: config.conf", "return_value": 5},
    {"timestamp": "6425.816", "thread": "Thread-1", "pid": 14298, "syscall": "read", "args": "fd: 5", "return_value": 8192},
    {"timestamp": "6425.824", "thread": "Thread-1", "pid": 14298, "syscall": "read", "args": "fd: 5", "return_value": 8192},
    {"timestamp": "6425.832", "thread": "Thread-1", "pid": 14298, "syscall": "close", "args": "fd: 5", "return_value": 0},
    {"timestamp": "6425.839", "thread": "Thread-1", "pid": 14298, "syscall": "sendto", "args": "fd: 4", "return_value": 155},
    {"timestamp": "6425.847", "thread": "Thread-1", "pid": 14298, "syscall": "close", "args": "fd: 4", "return_value": 0},
    {"timestamp": "12793.663", "thread": "Thread-2", "pid": 167630, "syscall": "recvfrom", "args": "fd: 4", "return_value": 494},
    {"timestamp": "12794.042", "thread": "Thread-2", "pid": 167630, "syscall": "openat", "args": "filename: users.db", "return_value": 5},
    {"timestamp": "12794.107", "thread": "Thread-2", "pid": 167630, "syscall": "read", "args": "fd: 5", "return_value": 8192},
    {"timestamp": "12794.378", "thread": "Thread-2", "pid": 167630, "syscall": "read", "args": "fd: 5", "return_value": 8192},
    {"timestamp": "12794.654", "thread": "Thread-2", "pid": 167630, "syscall": "close", "args": "fd: 5", "return_value": 0},
    {"timestamp": "12794.887", "thread": "Thread-2", "pid": 167630, "syscall": "sendto", "args": "fd: 4", "return_value": 185},
    {"timestamp": "12794.963", "thread": "Thread-2", "pid": 167630, "syscall": "close", "args": "fd: 4", "return_value": 0},
]


async def collect():
    print(f"Connecting to ingest endpoint: {INGEST_URI}")
    async with websockets.connect(INGEST_URI) as ws:
        print("Connected! Sending syscall data…\n")
        cycle = 0
        while True:
            cycle += 1
            for sc in SAMPLE_DATA:
                await ws.send(json.dumps(sc))
                print(f"  → {sc['syscall']}({sc['args']})")
                await asyncio.sleep(0.1)
            print(f"\n  [Cycle {cycle} complete — looping]\n")


if __name__ == "__main__":
    try:
        asyncio.run(collect())
    except KeyboardInterrupt:
        print("\nCollector stopped.")
