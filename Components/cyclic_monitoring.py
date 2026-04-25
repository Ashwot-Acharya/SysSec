"""
cyclic_monitor.py  — Connected to pcfg_inside.AnomalyDetector
==============================================================

Two detection modes (auto-selected):

  MODE A — BATCH MODE (default)
    Collects syscalls until an idle syscall fires (epoll_wait, poll, etc.)
    Each batch = one "request/task cycle" of the process.
    Good for: web servers, request-response programs.

  MODE B — SLIDING WINDOW MODE
    Scores every W syscalls using a rolling window, stepping S syscalls.
    Fires regardless of idle signals.
    Good for: continuous processes (DB, file copy, long computations)
              that never produce idle syscalls.

  Both modes run simultaneously — batch mode when idle fires,
  sliding window as a safety net for long stretches between idles.

Training:
  Phase 1 — WARM-UP: collect the first WARMUP_CYCLES batches silently.
             These are assumed normal. AnomalyDetector trains on them.
  Phase 2 — DETECT: every subsequent batch/window is scored live.

Usage:
  # Monitor a running process (by PID):
  python cyclic_monitor.py --pid 1234

  # Train from a file of normal traces, then monitor:
  python cyclic_monitor.py --pid 1234 --train normal_traces.txt

  # Replay a recorded trace file (for testing):
  python cyclic_monitor.py --replay trace.txt

File format for --train  (one trace per line, syscalls space-separated):
  open read write close
  open read read close
  connect send recv close
"""

from __future__ import annotations
import sys
import re
import os
import time
import argparse
import subprocess
from collections import deque
from typing import Optional

# ── import from our ML pipeline ──────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pcgf_inside import AnomalyDetector
from sequitur import SequiturSimple


# ═════════════════════════════════════════════════════════════════════════════
# CONFIGURATION — tune these for your use case
# ═════════════════════════════════════════════════════════════════════════════

# Syscalls that signal the process is idle (end of a request/task cycle)
IDLE_SYSCALLS = {
    'epoll_pwait', 'epoll_wait',
    'poll', 'ppoll',
    'select', 'pselect6',
    'nanosleep', 'clock_nanosleep',
    'futex',          # thread waiting — often signals idle
}

# How many warmup CYCLES to collect before training
# (only used when no --train file is provided)
WARMUP_CYCLES = 10

# Sliding window config (MODE B)
WINDOW_SIZE = 30        # score every window of this many syscalls
WINDOW_STEP = 10        # advance the window by this many syscalls each time
MIN_SEQ_LEN = 3         # don't score sequences shorter than this

# Anomaly detector config
Z_THRESHOLD = 2.5       # stddevs above mean → anomaly

# Regex to extract syscall name from perf trace / strace output
# Matches lines like:  "    0.123 read(3, ...) = 5"  or  "read(...)"
SYSCALL_RE = re.compile(r'^\s*[\d.]*\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\(')

# Colour codes (disable if terminal doesn't support)
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"


# ═════════════════════════════════════════════════════════════════════════════
# SYSCALL EXTRACTOR
# ═════════════════════════════════════════════════════════════════════════════

def extract_syscall(line: str) -> Optional[str]:
    """
    Parse one line of perf trace / strace output and return the syscall name.
    Returns None if the line doesn't look like a syscall.
    """
    m = SYSCALL_RE.match(line)
    return m.group(1) if m else None


# ═════════════════════════════════════════════════════════════════════════════
# SLIDING WINDOW BUFFER
# ═════════════════════════════════════════════════════════════════════════════

class SlidingWindowBuffer:
    """
    Maintains a rolling buffer of the last WINDOW_SIZE syscalls.
    Every WINDOW_STEP new syscalls it fires a callback with the current window.

    This is the answer to the "continuously running process" problem:
    we don't need the process to finish — we score whatever we have.
    """

    def __init__(self, window_size: int, step: int,
                 callback):  # callback(window: list[str]) -> None
        self.window_size = window_size
        self.step        = step
        self.callback    = callback
        self._buf: deque[str] = deque(maxlen=window_size)
        self._since_last_step = 0

    def push(self, syscall: str) -> None:
        self._buf.append(syscall)
        self._since_last_step += 1

        # Fire when we have a full window AND enough new data since last fire
        if (len(self._buf) >= self.window_size and
                self._since_last_step >= self.step):
            self.callback(list(self._buf))
            self._since_last_step = 0

    def flush(self) -> None:
        """Force-fire on whatever is in the buffer (called at shutdown)."""
        if len(self._buf) >= MIN_SEQ_LEN:
            self.callback(list(self._buf))


# ═════════════════════════════════════════════════════════════════════════════
# STATS TRACKER
# ═════════════════════════════════════════════════════════════════════════════

class Stats:
    def __init__(self):
        self.total_syscalls  = 0
        self.total_batches   = 0
        self.total_windows   = 0
        self.anomaly_batches = 0
        self.anomaly_windows = 0
        self.start_time      = time.time()

    def print_summary(self) -> None:
        elapsed = time.time() - self.start_time
        rate = self.total_syscalls / elapsed if elapsed > 0 else 0
        print(f"\n{'═'*55}")
        print(f"  SUMMARY")
        print(f"{'═'*55}")
        print(f"  Runtime          : {elapsed:.1f}s")
        print(f"  Total syscalls   : {self.total_syscalls}  ({rate:.0f}/s)")
        print(f"  Batches scored   : {self.total_batches}")
        print(f"  Windows scored   : {self.total_windows}")
        if self.total_batches > 0:
            br = self.anomaly_batches / self.total_batches * 100
            print(f"  Batch anomalies  : {self.anomaly_batches} ({br:.1f}%)")
        if self.total_windows > 0:
            wr = self.anomaly_windows / self.total_windows * 100
            print(f"  Window anomalies : {self.anomaly_windows} ({wr:.1f}%)")
        print(f"{'═'*55}")


# ═════════════════════════════════════════════════════════════════════════════
# MAIN MONITOR CLASS
# ═════════════════════════════════════════════════════════════════════════════

class CyclicMonitor:
    """
    Connects perf trace → AnomalyDetector in real time.

    State machine:
      WARMUP  → collecting first WARMUP_CYCLES batches as normal training data
      TRAINED → AnomalyDetector is trained, scoring every batch/window
    """

    def __init__(self, z_threshold: float = Z_THRESHOLD,
                 warmup_cycles: int = WARMUP_CYCLES):
        self.detector      = AnomalyDetector(z_threshold=z_threshold)
        self.warmup_cycles = warmup_cycles
        self._trained      = False
        self._warmup_data: list[list[str]] = []   # accumulate during warmup
        self.stats         = Stats()

        # Sliding window buffer — fires _on_window() every WINDOW_STEP syscalls
        self.window_buf = SlidingWindowBuffer(
            window_size = WINDOW_SIZE,
            step        = WINDOW_STEP,
            callback    = self._on_window
        )

    # ── Training ──────────────────────────────────────────────────────────────

    def train_from_file(self, path: str) -> None:
        """
        Load pre-collected normal traces from a text file.
        File format: one trace per line, syscalls space-separated.
        """
        traces = []
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    traces.append(line.split())

        if not traces:
            raise ValueError(f"No traces found in {path}")

        print(f"{CYAN}[Monitor] Loading {len(traces)} normal traces from {path}{RESET}")
        self._do_train(traces)

    def _do_train(self, traces: list[list[str]]) -> None:
        """Run the full ML pipeline: SEQUITUR → PCFG → CNF → InsideAlgorithm."""
        print(f"{CYAN}[Monitor] Training AnomalyDetector on {len(traces)} traces...{RESET}")
        self.detector.train(traces, holdout_fraction=0.2)
        self._trained = True
        print(f"{GREEN}[Monitor] Training complete. "
              f"Threshold = {self.detector.threshold:.4f}{RESET}")

        # Print the learned grammar for interpretability
        self._print_grammar_summary()

    def _print_grammar_summary(self) -> None:
        """Show the human-readable grammar rules on the terminal."""
        if not self.detector.pcfg:
            return
        print(f"\n{CYAN}{'─'*50}")
        print(f"  Learned Grammar (top rules):")
        print(f"{'─'*50}{RESET}")
        for lhs, prods in list(self.detector.pcfg.rules.items())[:8]:
            for body, prob in prods[:3]:
                body_str = " ".join(body)
                print(f"  {lhs:<6} →  {body_str:<30}  [{prob:.3f}]")
        print(f"{CYAN}{'─'*50}{RESET}\n")

    # ── Batch processing (MODE A) ─────────────────────────────────────────────

    def process_batch(self, batch: list[str], source: str = "batch") -> None:
        """
        Score one batch of syscalls.
        During warmup: accumulate for training.
        After training: score with AnomalyDetector.
        """
        if len(batch) < MIN_SEQ_LEN:
            return

        self.stats.total_batches += 1

        # Strip idle syscalls — they're boundary markers, not behavioral content
        batch = [s for s in batch if s not in IDLE_SYSCALLS]
        if len(batch) < MIN_SEQ_LEN:
            return

        if not self._trained:
            # ── WARMUP PHASE ──────────────────────────────────────────────
            self._warmup_data.append(batch[:])
            n = len(self._warmup_data)
            print(f"  [{YELLOW}WARMUP{RESET}] Cycle {n}/{self.warmup_cycles} — "
                  f"{len(batch)} syscalls  ({', '.join(batch[:5])}{'...' if len(batch)>5 else ''})")

            if n >= self.warmup_cycles:
                self._do_train(self._warmup_data)
            return

        # ── DETECTION PHASE ───────────────────────────────────────────────
        self._score_and_report(batch, source)

    def _on_window(self, window: list[str]) -> None:
        """Called by SlidingWindowBuffer every WINDOW_STEP syscalls."""
        self.stats.total_windows += 1

        if not self._trained:
            return   # don't score windows during warmup

        self._score_and_report(window, source="window")
        if self.stats.total_windows % 10 == 0:
            self._update_stats_line()

    # ── Scoring ───────────────────────────────────────────────────────────────

    def _score_and_report(self, sequence: list[str], source: str) -> None:
        """Run AnomalyDetector.predict() and print the result."""
        is_anomaly, score, explanation = self.detector.predict(sequence)

        # Update counters
        if source.startswith("batch") or source.startswith("replay"):
            if is_anomaly:
                self.stats.anomaly_batches += 1
        else:
            if is_anomaly:
                self.stats.anomaly_windows += 1

        # Print result
        score_str = f"{score:.3f}" if score < 999 else "∞"
        seq_preview = " ".join(sequence[:8]) + ("..." if len(sequence) > 8 else "")
        threshold   = self.detector.threshold

        if is_anomaly:
            print(
                f"  {RED}{BOLD}⚠  ANOMALY{RESET}  "
                f"[{source}] score={score_str} (thresh={threshold:.2f})  "
                f"{RED}{seq_preview}{RESET}"
            )
            if explanation:
                print(f"  {YELLOW}   └─ {explanation}{RESET}")
        else:
            # Only print normal confirmations every 5th batch to reduce noise
            if self.stats.total_batches % 5 == 0:
                print(
                    f"  {GREEN}✓ normal{RESET}  "
                    f"[{source}] score={score_str}  {seq_preview}"
                )

    def _update_stats_line(self) -> None:
        elapsed = time.time() - self.stats.start_time
        rate    = self.stats.total_syscalls / elapsed if elapsed > 0 else 0
        print(
            f"  {CYAN}[stats]{RESET} "
            f"{self.stats.total_syscalls} syscalls  "
            f"{self.stats.anomaly_batches} batch-anomalies  "
            f"{self.stats.anomaly_windows} window-anomalies  "
            f"({rate:.0f} syscalls/s)"
        )

    # ── Push one syscall (called per line from perf) ───────────────────────────

    def push(self, syscall: str) -> None:
        """
        Accept one syscall from the live stream.
        Updates the sliding window and batch accumulator.
        """
        self.stats.total_syscalls += 1
        self.window_buf.push(syscall)   # MODE B: always


# ═════════════════════════════════════════════════════════════════════════════
# LIVE PERF TRACE READER
# ═════════════════════════════════════════════════════════════════════════════

def run_live(monitor: CyclicMonitor, pid: int) -> None:
    """
    Attach perf trace to PID and feed syscalls into the monitor in real time.
    Batches are flushed when an idle syscall is observed (MODE A).
    Sliding window fires automatically (MODE B).
    """
    cmd = ["sudo", "perf", "trace", "-p", str(pid)]
    print(f"{CYAN}[Monitor] Attaching to PID {pid}...{RESET}")
    print(f"  Batch mode  : flush on {{{', '.join(sorted(IDLE_SYSCALLS)[:4])}...}}")
    print(f"  Window mode : score every {WINDOW_STEP} syscalls (window={WINDOW_SIZE})")
    print(f"  Press Ctrl+C to stop.\n")

    batch: list[str] = []
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
                continue

            # Push to sliding window (MODE B — always)
            monitor.push(syscall)

            # Accumulate for batch (MODE A)
            batch.append(syscall)

            # Flush batch when idle syscall detected (MODE A)
            if syscall in IDLE_SYSCALLS:
                cycle += 1
                monitor.process_batch(batch, source=f"batch-{cycle}")
                batch = []

    except KeyboardInterrupt:
        print(f"\n{YELLOW}[Monitor] Interrupted.{RESET}")

    finally:
        # Flush partial batch
        if batch:
            cycle += 1
            monitor.process_batch(batch, source=f"batch-{cycle}-final")

        # Flush partial window
        monitor.window_buf.flush()

        # Kill perf
        if proc and proc.poll() is None:
            proc.terminate()
            proc.wait()

        monitor.stats.print_summary()


# ═════════════════════════════════════════════════════════════════════════════
# REPLAY MODE (for testing without a live process)
# ═════════════════════════════════════════════════════════════════════════════

def run_replay(monitor: CyclicMonitor, path: str) -> None:
    """
    Replay a recorded trace file as if it were live.
    File format: one syscall per line, OR one trace per line (space-separated).
    """
    print(f"{CYAN}[Monitor] Replaying {path}...{RESET}\n")

    batch: list[str] = []
    cycle = 0

    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            # Support two formats:
            # 1. One syscall per line (from perf trace output)
            # 2. One trace per line, space-separated  →  treat as one batch
            parts = line.split()
            if len(parts) == 1:
                # Single syscall
                syscall = parts[0]
                monitor.push(syscall)
                batch.append(syscall)
                if syscall in IDLE_SYSCALLS:
                    cycle += 1
                    monitor.process_batch(batch, source=f"replay-batch-{cycle}")
                    batch = []
            else:
                # Whole trace on one line
                monitor.process_batch(parts, source=f"replay-trace-{cycle}")
                for s in parts:
                    monitor.push(s)
                cycle += 1

    if batch:
        monitor.process_batch(batch, source="replay-final")
    monitor.window_buf.flush()
    monitor.stats.print_summary()


# ═════════════════════════════════════════════════════════════════════════════
# DEMO / SELF-TEST (no perf required)
# ═════════════════════════════════════════════════════════════════════════════

def run_demo() -> None:
    """
    Self-contained demo that trains on synthetic data and tests detection.
    No perf or sudo required. Run this to verify the full pipeline works.
    """
    print(f"\n{CYAN}{'═'*55}")
    print(f"  DEMO MODE — synthetic syscall stream")
    print(f"{'═'*55}{RESET}\n")

    # ── Step 1: build a monitor and train it ─────────────────────────────────
    monitor = CyclicMonitor(z_threshold=2.0, warmup_cycles=0)

    normal_traces = [
        ['open', 'read', 'close'],
        ['open', 'read', 'read', 'close'],
        ['open', 'write', 'close'],
        ['open', 'read', 'write', 'close'],
        ['open', 'read', 'close'],
        ['open', 'write', 'write', 'close'],
        ['open', 'read', 'write', 'close'],
        ['open', 'read', 'read', 'write', 'close'],
        ['open', 'read', 'close'],
        ['open', 'write', 'close'],
        ['open', 'read', 'close'],
        ['open', 'read', 'read', 'close'],
    ] * 2   # 24 traces

    monitor._do_train(normal_traces)

    # ── Step 2: simulate a live syscall stream ────────────────────────────────
    print(f"\n{CYAN}[Demo] Simulating live syscall stream...{RESET}\n")

    # Interleaved normal and attack syscalls
    # IDLE_SYSCALL at the end of each "request" flushes the batch
    stream = [
        # Normal file read
        'open', 'read', 'close',
        'epoll_wait',   # ← idle: batch 1 flushed here

        # Normal file write
        'open', 'write', 'close',
        'epoll_wait',   # ← batch 2

        # Long read loop (continuous — no idle fires for a while)
        'open', 'read', 'read', 'read', 'read', 'read',
        'read', 'read', 'read', 'read', 'read', 'read',
        'epoll_wait',   # ← batch 3 (long but normal)

        # ATTACK: shellcode pattern
        'open', 'mmap', 'execve', 'connect', 'send',
        'epoll_wait',   # ← batch 4 — should fire anomaly

        # ATTACK: network without open
        'connect', 'send', 'recv', 'send',
        'epoll_wait',   # ← batch 5 — should fire anomaly

        # Back to normal
        'open', 'read', 'close',
        'epoll_wait',   # ← batch 6
    ]

    batch: list[str] = []
    cycle = 0

    for syscall in stream:
        monitor.push(syscall)
        batch.append(syscall)
        if syscall in IDLE_SYSCALLS:
            cycle += 1
            monitor.process_batch(batch, source=f"batch-{cycle}")
            batch = []

    # Flush any leftovers
    if batch:
        monitor.process_batch(batch, source="final")
    monitor.window_buf.flush()

    monitor.stats.print_summary()


# ═════════════════════════════════════════════════════════════════════════════
# CLI
# ═════════════════════════════════════════════════════════════════════════════

def parse_args():
    p = argparse.ArgumentParser(
        description="CFG-IDS cyclic monitor — connects perf trace to AnomalyDetector"
    )
    p.add_argument('--pid',    type=int,  help="PID to monitor with perf trace")
    p.add_argument('--train',  type=str,  help="Path to normal traces file for pre-training")
    p.add_argument('--replay', type=str,  help="Path to recorded trace file to replay")
    p.add_argument('--demo',   action='store_true', help="Run self-contained demo (no perf)")
    p.add_argument('--warmup', type=int,  default=WARMUP_CYCLES,
                   help=f"Warmup cycles before training (default {WARMUP_CYCLES})")
    p.add_argument('--z',      type=float, default=Z_THRESHOLD,
                   help=f"Z-score threshold (default {Z_THRESHOLD})")
    p.add_argument('--window', type=int,  default=WINDOW_SIZE,
                   help=f"Sliding window size (default {WINDOW_SIZE})")
    p.add_argument('--step',   type=int,  default=WINDOW_STEP,
                   help=f"Sliding window step (default {WINDOW_STEP})")
    return p.parse_args()


def main():
    args = parse_args()

    # Override globals from CLI
    global WINDOW_SIZE, WINDOW_STEP
    WINDOW_SIZE = args.window
    WINDOW_STEP = args.step

    if args.demo:
        run_demo()
        return

    if not args.pid and not args.replay:
        print("Specify --pid <PID>, --replay <file>, or --demo")
        print("Example: python cyclic_monitor.py --demo")
        sys.exit(1)

    monitor = CyclicMonitor(z_threshold=args.z, warmup_cycles=args.warmup)

    # Pre-train from file if provided
    if args.train:
        monitor.train_from_file(args.train)

    if args.replay:
        run_replay(monitor, args.replay)
    elif args.pid:
        run_live(monitor, args.pid)


if __name__ == "__main__":
    main()