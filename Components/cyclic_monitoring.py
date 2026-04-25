#!/usr/bin/env python3
import sys
import re
import subprocess
from sequitur import SequiturSimple   

# Syscalls that indicate the server is idle (waiting for new events)
IDLE_SYSCALLS = {'epoll_pwait', 'epoll_wait', 'poll', 'ppoll', 'select', 'pselect6'}

# Regex to extract syscall name
SYSCALL_PATTERN = re.compile(r'\b([a-zA-Z_]+)\s*\(')

def extract_syscall(line: str) -> str | None:
    match = SYSCALL_PATTERN.search(line)
    return match.group(1) if match else None

def process_batch(batch, cycle_num):
    if not batch:
        return
    print(f"\n{'='*60}")
    print(f"Cycle {cycle_num} – {len(batch)} syscalls")
    print(f"{'='*60}")
    sq = SequiturSimple()
    sq.learn(batch)
    sq.print_grammar()
    # Optional: verify expansion
    expanded = sq.expand()
    print(f"Expansion matches: {expanded == batch}")

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <PID>")
        sys.exit(1)

    pid = sys.argv[1]
    cmd = ["sudo", "perf", "trace", "-p", pid]

    print(f"Monitoring PID {pid} – will batch syscalls until an idle syscall ({', '.join(IDLE_SYSCALLS)})")
    print("Press Ctrl+C to stop.\n")

    batch = []
    cycle = 0

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue

            syscall = extract_syscall(line)
            if syscall is None:
                # Unparsable line – skip or print to stderr for debugging
                continue

            batch.append(syscall)

            # If this syscall indicates idling, finalise the batch
            if syscall in IDLE_SYSCALLS:
                cycle += 1
                process_batch(batch, cycle)
                batch = []   # start fresh for next cycle

    except KeyboardInterrupt:
        print("\n\nInterrupted.")
        # If there's a partial batch, process it too
        if batch:
            cycle += 1
            process_batch(batch, cycle)
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
            proc.wait()

if __name__ == "__main__":
    main()