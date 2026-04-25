"""
cyclic_monitor.py — Phase 3: Live Monitoring
=============================================
Loads a trained model.pkl and monitors a running process in real time.

Usage:
  python cyclic_monitor.py --pid <PID> --model model.pkl
  python cyclic_monitor.py --pid <PID> --model model.pkl --strace
  python cyclic_monitor.py --pid <PID> --model model.pkl --send-api http://localhost:5000/anomalies
  python cyclic_monitor.py --pid <PID> --model model.pkl --debug

What it does:
  1. Loads model.pkl  (saved by train.py — contains detector, threshold, grammar, stats)
  2. Attaches to the target PID via perf trace (or strace)
  3. Accumulates syscalls into "cycles" — one cycle = syscalls between two idle syscalls
  4. Scores each cycle with the Inside algorithm: score = -log P(cycle | grammar)
  5. Flags cycles where score > threshold as anomalies
  6. Optionally POSTs anomaly events to a backend API
"""

from __future__ import annotations
import sys
import os
import re
import time
import pickle
import signal
import argparse
import threading
import datetime
import json
from collections import defaultdict
from typing import Optional

# Optional: uncomment when backend is ready
# import requests


# ── Idle syscalls (same set as collect_traces.py) ────────────────────────────
IDLE_SYSCALLS = {
    'epoll_pwait', 'epoll_wait',
    'poll', 'ppoll',
    'select', 'pselect6',
    'nanosleep', 'clock_nanosleep',
    'futex',
}

# ── Noisy syscalls to skip (same set as collect_traces.py) ───────────────────
SKIP_SYSCALLS = {
    'mprotect', 'brk', 'munmap', 'arch_prctl',
    'set_tid_address', 'set_robust_list', 'rseq',
    'sched_getaffinity', 'getpid', 'getppid',
    'gettid', 'getuid', 'getgid', 'geteuid', 'getegid',
    'rt_sigaction', 'rt_sigprocmask', 'rt_sigreturn',
    'sigaltstack',
}

MIN_BATCH_LEN = 3    # discard cycles shorter than this (noise)

# ── Regex: handles both perf trace and strace output ─────────────────────────
SYSCALL_RE = re.compile(
    r'(?:'
    r':\s+(?:\S+/\d+\s+)?'   # perf trace: "): [proc/pid ]syscall("
    r'|'
    r'^\s*'                   # strace: start of line
    r')'
    r'([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
)


def extract_syscall(line: str) -> Optional[str]:
    """Extract syscall name from a perf trace or strace output line."""
    m = SYSCALL_RE.search(line)
    if not m:
        return None
    name = m.group(1)
    if name in SKIP_SYSCALLS:
        return None
    return name


# ═════════════════════════════════════════════════════════════════════════════
# MODEL LOADING
# ═════════════════════════════════════════════════════════════════════════════

def load_model(path: str) -> dict:
    """
    Load model.pkl saved by train.py.

    train.py saves a dict:
      {
        "detector":   AnomalyDetector,
        "threshold":  float,
        "grammar":    dict,
        "stats":      dict,
        "created":    str,
        "version":    str,
      }

    This function handles both the new dict format and the legacy format
    where the raw AnomalyDetector was pickled directly.
    """
    with open(path, "rb") as f:
        payload = pickle.load(f)

    # New format: train.py saves a dict with "detector" key
    if isinstance(payload, dict) and "detector" in payload:
        return payload

    # Legacy format: raw AnomalyDetector object pickled directly
    # Wrap it so the rest of the code works uniformly
    print("  [Warning] Legacy model format detected — wrapping for compatibility.")
    return {
        "detector":  payload,
        "threshold": payload.threshold,
        "grammar":   {},
        "stats":     {},
        "created":   "unknown",
    }


def print_model_info(payload: dict) -> None:
    s = payload.get("stats", {})
    print(f"  Created   : {payload.get('created', 'unknown')}")
    print(f"  Threshold : {payload['threshold']:.4f}")
    if s:
        print(f"  Trained on: {s.get('n_traces', '?')} traces")
        print(f"  Vocabulary: {s.get('n_terminals', '?')} syscalls  "
              f"({', '.join(s.get('vocabulary', [])[:8])}"
              f"{'...' if len(s.get('vocabulary', [])) > 8 else ''})")
        print(f"  Grammar   : {s.get('n_rules', '?')} rules, "
              f"z={s.get('z_threshold', '?')}")


# ═════════════════════════════════════════════════════════════════════════════
# SUBPROCESS READER (non-blocking, background threads)
# ═════════════════════════════════════════════════════════════════════════════

def _start_reader_threads(proc: "subprocess.Popen",
                           line_queue: list,
                           lock: threading.Lock) -> None:
    """Read stdout AND stderr in background threads (perf writes to stderr)."""
    def reader(stream):
        for raw in stream:
            try:
                line = raw.decode("utf-8", errors="replace").rstrip()
            except Exception:
                continue
            with lock:
                line_queue.append(line)

    for stream in (proc.stdout, proc.stderr):
        if stream:
            t = threading.Thread(target=reader, args=(stream,), daemon=True)
            t.start()


# ═════════════════════════════════════════════════════════════════════════════
# ANOMALY REPORTER
# ═════════════════════════════════════════════════════════════════════════════

def report_anomaly(cycle: int, pid: str, batch: list[str],
                   score: float, explanation: str,
                   api_url: Optional[str]) -> None:
    """Print anomaly details and optionally POST to backend API."""
    print(f"  ╔══ ANOMALY DETAILS ══════════════════════════════╗")
    print(f"  ║ Score      : {score:.4f}")
    print(f"  ║ Syscalls   : {' '.join(batch[:12])}{'...' if len(batch) > 12 else ''}")
    print(f"  ║ Explanation: {explanation[:80]}")
    print(f"  ╚════════════════════════════════════════════════╝")

    if api_url:
        event = {
            "cycle":       cycle,
            "timestamp":   time.time(),
            "pid":         pid,
            "sequence":    batch,
            "score":       score,
            "explanation": explanation,
        }
        try:
            # Uncomment when backend is ready:
            # import requests
            # requests.post(api_url, json=event, timeout=0.5)
            print(f"  [API] Would POST to {api_url}:")
            print(f"        {json.dumps(event, indent=4)[:200]}...")
        except Exception as e:
            print(f"  [API] Error: {e}")


# ═════════════════════════════════════════════════════════════════════════════
# MONITOR LOOP
# ═════════════════════════════════════════════════════════════════════════════

def monitor(pid: str, detector, threshold: float,
            use_strace: bool, api_url: Optional[str],
            debug: bool) -> None:
    """
    Main monitoring loop.

    Attaches to PID, reads syscall stream, batches into cycles on idle
    syscalls, scores each cycle, and flags anomalies.
    """
    import subprocess

    if use_strace:
        cmd = ["sudo", "strace", "-f", "-e", "trace=all", "-p", pid]
    else:
        cmd = ["sudo", "stdbuf", "-oL", "-eL", "perf", "trace", "-p", pid]

    print(f"  Command : {' '.join(cmd)}")
    print(f"  Batching on idle syscalls: {', '.join(sorted(IDLE_SYSCALLS))}")
    print(f"  Anomaly threshold: {threshold:.4f}")
    print(f"\n  Attached. Generate traffic now. Press Ctrl+C to stop.\n")
    print(f"  {'─'*60}")

    batch:   list[str] = []
    cycle    = 0
    total_anomalies = 0
    line_queue: list[str] = []
    lock    = threading.Lock()
    proc    = None

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,   # separate stderr — perf uses stderr
            bufsize=0,
        )
        _start_reader_threads(proc, line_queue, lock)

        syscalls_seen = 0

        while True:
            time.sleep(0.02)

            with lock:
                current = line_queue[:]
                line_queue.clear()

            for line in current:
                if debug:
                    print(f"  [raw] {line}")

                syscall = extract_syscall(line)
                if syscall is None:
                    continue

                syscalls_seen += 1
                if syscalls_seen == 1:
                    print(f"  ✓ First syscall captured: {syscall!r}")

                batch.append(syscall)

                # ── Cycle boundary: idle syscall seen ─────────────────────
                if syscall in IDLE_SYSCALLS:
                    # Strip idle markers from the cycle content
                    cycle_syscalls = [s for s in batch if s not in IDLE_SYSCALLS]
                    batch = []

                    if len(cycle_syscalls) < MIN_BATCH_LEN:
                        continue   # too short — noise, skip

                    cycle += 1
                    is_anom, score, explanation = detector.predict(cycle_syscalls)

                    ts = datetime.datetime.now().strftime("%H:%M:%S")
                    score_str = f"{score:.4f}" if score < 999 else "∞"
                    flag = "⚠️  ANOMALY" if is_anom else "✓  normal "

                    print(f"  [{ts}] Cycle {cycle:>4} | "
                          f"{len(cycle_syscalls):>3} syscalls | "
                          f"score={score_str:>9} | {flag}")

                    if is_anom:
                        total_anomalies += 1
                        report_anomaly(cycle, pid, cycle_syscalls,
                                       score, explanation, api_url)

            if proc.poll() is not None:
                print(f"\n  Process exited (code {proc.returncode}).")
                if syscalls_seen == 0:
                    print("  ✗ No syscalls captured. Possible causes:")
                    print("    • perf_event_paranoid is too restrictive:")
                    print("        sudo sysctl -w kernel.perf_event_paranoid=-1")
                    print("    • Try --strace for strace-based monitoring")
                    print("    • Run with --debug to see raw output")
                break

    except KeyboardInterrupt:
        print(f"\n\n  Ctrl+C — stopping monitor.")

        # Score any partial cycle
        if batch:
            cycle_syscalls = [s for s in batch if s not in IDLE_SYSCALLS]
            if len(cycle_syscalls) >= MIN_BATCH_LEN:
                cycle += 1
                is_anom, score, explanation = detector.predict(cycle_syscalls)
                score_str = f"{score:.4f}" if score < 999 else "∞"
                flag = "⚠️  ANOMALY" if is_anom else "✓  normal"
                print(f"\n  [Final cycle] {len(cycle_syscalls)} syscalls | "
                      f"score={score_str} | {flag}")
                if is_anom:
                    total_anomalies += 1
                    report_anomaly(cycle, pid, cycle_syscalls,
                                   score, explanation, api_url)

    finally:
        if proc and proc.poll() is None:
            proc.terminate()
            proc.wait()

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"\n  {'═'*60}")
    print(f"  MONITORING SUMMARY")
    print(f"  {'═'*60}")
    print(f"  Total cycles  : {cycle}")
    print(f"  Anomalies     : {total_anomalies}  "
          f"({'%.1f' % (total_anomalies/cycle*100 if cycle else 0)}%)")
    print(f"  {'═'*60}")


# ═════════════════════════════════════════════════════════════════════════════
# CLI
# ═════════════════════════════════════════════════════════════════════════════

def main():
    p = argparse.ArgumentParser(
        description="Phase 3: Live syscall anomaly monitoring using a trained model.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--pid",      type=str, required=True,
                   help="PID of the process to monitor")
    p.add_argument("--model",    type=str, required=True,
                   help="Path to model.pkl (from train.py)")
    p.add_argument("--strace",   action="store_true",
                   help="Use strace instead of perf trace")
    p.add_argument("--send-api", type=str, default=None, metavar="URL",
                   help="POST anomaly events to this URL")
    p.add_argument("--debug",    action="store_true",
                   help="Print every raw line from the tracer")
    args = p.parse_args()

    print(f"\n{'═'*60}")
    print(f"  CFG-IDS LIVE MONITOR")
    print(f"{'═'*60}")
    print(f"  PID   : {args.pid}")
    print(f"  Model : {args.model}")
    print(f"  Tracer: {'strace' if args.strace else 'perf trace'}")
    if args.send_api:
        print(f"  API   : {args.send_api}")
    print()

    # ── Load model ────────────────────────────────────────────────────────────
    try:
        payload  = load_model(args.model)
        detector = payload["detector"]
        threshold = payload["threshold"]
    except FileNotFoundError:
        print(f"  ✗ Model file not found: {args.model}")
        print(f"  Run:  python train.py normal_traces.pkl {args.model}")
        sys.exit(1)
    except Exception as e:
        print(f"  ✗ Failed to load model: {e}")
        sys.exit(1)

    print(f"  Model loaded successfully:")
    print_model_info(payload)
    print()

    # ── Start monitoring ──────────────────────────────────────────────────────
    monitor(
        pid       = args.pid,
        detector  = detector,
        threshold = threshold,
        use_strace= args.strace,
        api_url   = args.send_api,
        debug     = args.debug,
    )


if __name__ == "__main__":
    main()