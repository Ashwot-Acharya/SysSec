"""
collect_traces.py — Phase 1: Data Collection
=============================================
Attaches to a running process and collects normal syscall traces.
Saves them as a .pkl file (list of lists of syscall name strings).

Usage:
  # Start your server first, then:
  python collect_traces.py <PID> normal_traces.pkl

  # Or use strace (more reliable on some systems):
  python collect_traces.py <PID> normal_traces.pkl --strace

  # Collect for exactly N seconds then stop automatically:
  python collect_traces.py <PID> normal_traces.pkl --timeout 60

  # See every raw line from perf (debug):
  python collect_traces.py <PID> normal_traces.pkl --debug

Workflow:
  1. python -m http.server 8080 &        # start a test server
  2. echo $!                             # note its PID
  3. python collect_traces.py <PID> normal_traces.pkl &   # start collecting
  4. curl http://localhost:8080/ (x many times)           # generate traffic
  5. Ctrl+C                              # stop collector
  6. python train.py normal_traces.pkl model.pkl          # train model

Output format (normal_traces.pkl):
  A pickle file containing:
  {
    "traces":   [ ["open","read","close"], ["open","write","close"], ... ],
    "pid":      1234,
    "count":    847,
    "duration": 32.4,   # seconds
    "created":  "2026-04-25T14:23:11"
  }
"""

from __future__ import annotations
import sys
import os
import re
import time
import pickle
import signal
import argparse
import subprocess
import threading
import datetime
from typing import Optional


# ── Syscalls that signal end of a request/task cycle ─────────────────────────
IDLE_SYSCALLS = {
    'epoll_pwait', 'epoll_wait',
    'poll', 'ppoll',
    'select', 'pselect6',
    'nanosleep', 'clock_nanosleep',
    'futex',
}

# ── Syscalls to IGNORE — too noisy, not behaviorally meaningful ───────────────
SKIP_SYSCALLS = {
    'mprotect', 'brk', 'munmap', 'arch_prctl',
    'set_tid_address', 'set_robust_list', 'rseq',
    'sched_getaffinity', 'getpid', 'getppid',
    'gettid', 'getuid', 'getgid', 'geteuid', 'getegid',
    'rt_sigaction', 'rt_sigprocmask', 'rt_sigreturn',
    'sigaltstack',
}

MIN_TRACE_LEN = 3     # discard traces shorter than this
MAX_TRACE_LEN = 200   # cap very long traces (prevent memory blowup)

# ── Regex: handles both perf trace and strace output ─────────────────────────
SYSCALL_RE = re.compile(
    r'(?:'
    r':\s+(?:\S+/\d+\s+)?'   # perf trace: after "): [proc/pid ]"
    r'|'
    r'^\s*'                   # strace: start of line
    r')'
    r'([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
)


def extract_syscall(line: str) -> Optional[str]:
    m = SYSCALL_RE.search(line)
    if not m:
        return None
    name = m.group(1)
    if name in SKIP_SYSCALLS:
        return None
    return name


# ═════════════════════════════════════════════════════════════════════════════
# COLLECTOR
# ═════════════════════════════════════════════════════════════════════════════

class TraceCollector:
    """
    Reads a live syscall stream and accumulates batches.
    A batch = syscalls between two idle syscalls = one "request cycle".
    """

    def __init__(self, debug: bool = False):
        self.traces:   list[list[str]] = []
        self.debug:    bool            = debug
        self._batch:   list[str]       = []
        self._total_syscalls = 0
        self._start = time.time()

    def push(self, syscall: str) -> None:
        self._total_syscalls += 1
        self._batch.append(syscall)

        if syscall in IDLE_SYSCALLS:
            self._flush()

    def _flush(self) -> None:
        # Strip idle markers from the batch content
        trace = [s for s in self._batch if s not in IDLE_SYSCALLS]
        self._batch = []

        if len(trace) < MIN_TRACE_LEN:
            return
        if len(trace) > MAX_TRACE_LEN:
            trace = trace[:MAX_TRACE_LEN]

        self.traces.append(trace)
        n = len(self.traces)

        # Print progress every 5 traces
        if n % 5 == 0 or n <= 3:
            elapsed = time.time() - self._start
            preview = " ".join(trace[:6]) + ("..." if len(trace) > 6 else "")
            print(f"  [trace {n:>4}]  len={len(trace):>4}  ({preview})")

    def flush_final(self) -> None:
        """Force-flush any partial batch on shutdown."""
        if self._batch:
            trace = [s for s in self._batch if s not in IDLE_SYSCALLS]
            if len(trace) >= MIN_TRACE_LEN:
                self.traces.append(trace[:MAX_TRACE_LEN])
        self._batch = []

    def stats(self) -> dict:
        elapsed = time.time() - self._start
        return {
            "traces":   len(self.traces),
            "syscalls": self._total_syscalls,
            "duration": round(elapsed, 2),
            "rate":     round(self._total_syscalls / elapsed, 1) if elapsed > 0 else 0,
        }


# ═════════════════════════════════════════════════════════════════════════════
# SUBPROCESS READERS
# ═════════════════════════════════════════════════════════════════════════════

def _start_reader_threads(proc: subprocess.Popen,
                           queue: list,
                           lock: threading.Lock) -> None:
    """Read stdout and stderr from proc in background threads."""
    def reader(stream):
        for raw in stream:
            try:
                line = raw.decode("utf-8", errors="replace").rstrip()
            except Exception:
                continue
            with lock:
                queue.append(line)

    for stream in (proc.stdout, proc.stderr):
        if stream:
            t = threading.Thread(target=reader, args=(stream,), daemon=True)
            t.start()


def collect_perf(collector: TraceCollector, pid: int, timeout: Optional[float]) -> None:
    cmd = ["sudo", "stdbuf", "-oL", "-eL", "perf", "trace", "-p", str(pid)]
    print(f"  Command : {' '.join(cmd)}")
    _run_collector(collector, cmd, pid, timeout)


def collect_strace(collector: TraceCollector, pid: int, timeout: Optional[float]) -> None:
    cmd = ["sudo", "strace", "-f", "-e", "trace=all", "-p", str(pid)]
    print(f"  Command : {' '.join(cmd)}")
    _run_collector(collector, cmd, pid, timeout)


def _run_collector(collector: TraceCollector, cmd: list,
                   pid: int, timeout: Optional[float]) -> None:
    queue: list[str] = []
    lock  = threading.Lock()
    proc  = None

    deadline = time.time() + timeout if timeout else None

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )
        _start_reader_threads(proc, queue, lock)

        lines_seen    = 0
        syscalls_seen = 0

        print(f"  Attached. Generating traffic now. Press Ctrl+C to stop.\n")

        while True:
            time.sleep(0.02)

            with lock:
                current = queue[:]
                queue.clear()

            for line in current:
                lines_seen += 1

                if collector.debug:
                    print(f"  [raw] {line}")

                syscall = extract_syscall(line)
                if syscall is None:
                    continue

                syscalls_seen += 1
                if syscalls_seen == 1:
                    print(f"  ✓ First syscall captured: {syscall}")

                collector.push(syscall)

            # Timeout check
            if deadline and time.time() > deadline:
                print(f"\n  Timeout reached.")
                break

            if proc.poll() is not None:
                print(f"\n  Process exited.")
                if lines_seen == 0:
                    print("  ✗ No output received. Try --strace or run manually:")
                    print(f"    sudo perf trace -p {pid} 2>&1 | head -5")
                elif syscalls_seen == 0:
                    print(f"  ✗ Got {lines_seen} lines but 0 syscalls matched.")
                    print("  Run with --debug to see raw output.")
                break

    except KeyboardInterrupt:
        print(f"\n  Ctrl+C — stopping collection.")
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
            proc.wait()


# ═════════════════════════════════════════════════════════════════════════════
# SAVE / LOAD
# ═════════════════════════════════════════════════════════════════════════════

def save_traces(traces: list[list[str]], pid: int,
                duration: float, output_path: str) -> None:
    payload = {
        "traces":   traces,
        "pid":      pid,
        "count":    len(traces),
        "duration": duration,
        "created":  datetime.datetime.now().isoformat(timespec="seconds"),
    }
    with open(output_path, "wb") as f:
        pickle.dump(payload, f)
    print(f"\n  Saved {len(traces)} traces → {output_path}")


def load_traces(path: str) -> list[list[str]]:
    with open(path, "rb") as f:
        payload = pickle.load(f)
    if isinstance(payload, dict):
        return payload["traces"]
    # Legacy: plain list of lists
    return payload


# ═════════════════════════════════════════════════════════════════════════════
# CLI
# ═════════════════════════════════════════════════════════════════════════════

def main():
    p = argparse.ArgumentParser(
        description="Collect normal syscall traces from a running process.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("pid",    type=int, help="PID to monitor")
    p.add_argument("output", type=str, help="Output .pkl file path")
    p.add_argument("--strace",   action="store_true",
                   help="Use strace instead of perf trace")
    p.add_argument("--timeout",  type=float, default=None,
                   help="Stop after N seconds (default: run until Ctrl+C)")
    p.add_argument("--debug",    action="store_true",
                   help="Print every raw line from the tracer")
    args = p.parse_args()

    print(f"\n{'═'*55}")
    print(f"  TRACE COLLECTOR  —  PID {args.pid}")
    print(f"{'═'*55}")
    print(f"  Output  : {args.output}")
    print(f"  Tracer  : {'strace' if args.strace else 'perf trace'}")
    if args.timeout:
        print(f"  Timeout : {args.timeout}s")
    print()

    collector = TraceCollector(debug=args.debug)

    if args.strace:
        collect_strace(collector, args.pid, args.timeout)
    else:
        collect_perf(collector, args.pid, args.timeout)

    collector.flush_final()

    s = collector.stats()
    print(f"\n{'─'*55}")
    print(f"  Traces collected : {s['traces']}")
    print(f"  Total syscalls   : {s['syscalls']}")
    print(f"  Duration         : {s['duration']}s")
    print(f"  Rate             : {s['rate']} syscalls/s")
    print(f"{'─'*55}")

    if s['traces'] == 0:
        print("\n  ✗ No traces collected. Cannot save.")
        print("  Make sure the target process is generating syscalls")
        print("  and that idle syscalls (epoll_wait, poll, etc.) are firing.")
        sys.exit(1)

    save_traces(collector.traces, args.pid, s['duration'], args.output)
    print(f"\n  Next step:  python train.py {args.output} model.pkl")


if __name__ == "__main__":
    main()