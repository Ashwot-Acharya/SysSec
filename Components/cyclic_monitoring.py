"""
cyclic_monitor.py — Phase 3: Live Monitoring
=============================================
Loads a trained model.pkl and monitors a running process in real time.

Usage:
  python cyclic_monitor.py --pid <PID> --model model.pkl
  python cyclic_monitor.py --pid <PID> --model model.pkl --strace
  python cyclic_monitor.py --pid <PID> --model model.pkl --send-api http://localhost:5000/anomalies
  python cyclic_monitor.py --pid <PID> --model model.pkl --debug
  python cyclic_monitor.py --pid <PID> --model model.pkl --warmup 18

What it does:
  1. Loads model.pkl  (saved by train.py — contains detector, threshold, grammar, stats)
  2. Attaches to the target PID via perf trace (or strace)
  3. Accumulates syscalls into "cycles" — one cycle = syscalls between two idle syscalls
  4. Silently discards the first WARMUP_CYCLES cycles (startup burst — execve, capget, etc.)
  5. Scores each cycle with NGramScorer: score = mean( -log P(wi+1|wi) ) across bigrams
  6. Flags cycles where score > threshold as anomalies
  7. Optionally POSTs anomaly events to a backend API via WebSocket

Threshold:
  Loaded from model.pkl — computed dynamically at train time as μ + z·σ
  over holdout traces.  It is NEVER hardcoded here.

Compatibility:
  Handles legacy model.pkl files trained before NGramScorer was introduced.
  If the loaded AnomalyDetector has no .scorer attribute, it is reconstructed
  from the embedded .pcfg automatically — no retraining needed.
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
import websockets
import asyncio
import requests
import websockets
import asyncio
from collections import defaultdict
from typing import Optional


# ── Idle syscalls (same set as collect_traces.py) ────────────────────────────
IDLE_SYSCALLS = {
    'epoll_pwait', 'epoll_wait',
    'poll', 'ppoll',
    'select', 'pselect6',
    'nanosleep', 'clock_nanosleep',
    'futex',
}

# ── Noisy syscalls to skip — must match SKIP_SYSCALLS in collect_traces.py ───
SKIP_SYSCALLS = {
    'mprotect', 'brk', 'munmap', 'arch_prctl',
    'set_tid_address', 'set_robust_list', 'rseq',
    'sched_getaffinity', 'getpid', 'getppid',
    'gettid', 'getuid', 'getgid', 'geteuid', 'getegid',
    'rt_sigaction', 'rt_sigprocmask', 'rt_sigreturn',
    'sigaltstack',
}

MIN_BATCH_LEN = 3    # discard cycles shorter than this (noise)

# Default warmup cycles to discard after attaching.
# Matches STARTUP_SKIP_CYCLES in collect_traces.py so the monitor
# sees the same steady-state syscall distribution the model was trained on.
DEFAULT_WARMUP_CYCLES = 18

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

def _ensure_scorer(detector) -> None:
    """
    Compatibility shim for models pickled before NGramScorer was introduced.

    Old AnomalyDetector objects won't have a .scorer attribute. If pcfg is
    present we can reconstruct NGramScorer from it without retraining.
    Raises RuntimeError if the model is too old to recover.
    """
    if hasattr(detector, 'scorer') and detector.scorer is not None:
        return  # already fine

    # Try to import NGramScorer from pcfg_inside (must be on PYTHONPATH)
    try:
        from pcfg_inside import NGramScorer
    except ImportError:
        raise ImportError(
            "pcfg_inside.py not found on PYTHONPATH. "
            "Place it in the same directory as cyclic_monitor.py."
        )

    if detector.pcfg is None:
        raise RuntimeError(
            "Legacy model has no .scorer AND no .pcfg — cannot recover. "
            "Please retrain:  python train.py normal_traces.pkl model.pkl"
        )

    smoothing       = getattr(detector, 'smoothing',       0.1)
    unknown_penalty = getattr(detector, 'unknown_penalty', 5.0)
    detector.scorer = NGramScorer(detector.pcfg, smoothing, unknown_penalty)
    print("  [Compat] Reconstructed NGramScorer from legacy model's PCFG.")
    print("           Consider retraining for a properly calibrated threshold.")


def load_model(path: str) -> dict:
    """
    Load model.pkl saved by train.py.

    Expected format:
      {
        "detector":   AnomalyDetector,
        "threshold":  float,   ← dynamic, computed at train time
        "grammar":    dict,
        "stats":      dict,
        "created":    str,
        "version":    str,
      }

    Also handles the legacy format where the raw AnomalyDetector was
    pickled directly.
    """
    with open(path, "rb") as f:
        payload = pickle.load(f)

    if isinstance(payload, dict) and "detector" in payload:
        _ensure_scorer(payload["detector"])
        return payload

    # Legacy format: raw AnomalyDetector pickled directly
    print("  [Warning] Legacy model format detected — wrapping for compatibility.")
    _ensure_scorer(payload)
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
    print(f"  Threshold : {payload['threshold']:.4f}  (dynamic — μ + z·σ from holdout)")
    if s:
        print(f"  Trained on: {s.get('n_traces', '?')} traces")
        print(f"  Score mean: {s.get('score_mean', '?')}  std: {s.get('score_std', '?')}")
        print(f"  Vocabulary: {s.get('n_terminals', '?')} syscalls  "
              f"({', '.join(s.get('vocabulary', [])[:8])}"
              f"{'...' if len(s.get('vocabulary', [])) > 8 else ''})")
        print(f"  Grammar   : {s.get('n_rules', '?')} rules, "
              f"z={s.get('z_threshold', '?')}")

        # Health warning if model was saved with a bad threshold
        n = s.get('n_traces', 0)
        if isinstance(n, int) and n < 30:
            print(f"  ⚠ WARNING : Only {n} training traces — grammar may be too narrow.")
            print(f"             Collect 50+ traces for reliable detection.")


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

def report_anomaly(cycle: int, pid: str, batch: list, score: float,
                   explanation: dict, threshold: float,
                   send_queue: list, send_lock: threading.Lock) -> None:

    verdict         = explanation.get("verdict", str(explanation)) if isinstance(explanation, dict) else explanation
    breakdown       = explanation.get("breakdown") if isinstance(explanation, dict) else None
    unknown         = explanation.get("unknown_syscalls", []) if isinstance(explanation, dict) else []
    parse_spans     = explanation.get("parse_spans", []) if isinstance(explanation, dict) else []
    token_parseable = explanation.get("token_parseable", []) if isinstance(explanation, dict) else []

    print(f"  ╔══ ANOMALY DETAILS ══════════════════════════════╗")
    print(f"  ║ Score    : {score:.4f}  (threshold={threshold:.4f})")
    print(f"  ║ Syscalls : {' '.join(batch[:12])}{'...' if len(batch) > 12 else ''}")
    print(f"  ║ Verdict  : {verdict[:80]}")
    if breakdown:
        print(f"  ║ Broke at : pos {breakdown['position']} — '{breakdown['syscall']}'")
        print(f"  ║ Reason   : {breakdown['reason'][:80]}")
    if unknown:
        print(f"  ║ Unknown  : {unknown}")
    print(f"  ╚════════════════════════════════════════════════╝")

    # Send anomaly alert through the WebSocket to the backend for broadcasting
    if send_queue is not None:
        failed_pos = breakdown.get("position", len(batch) - 1) if breakdown else len(batch) - 1
        anomaly_msg = json.dumps({
            "type":              "anomaly",
            "timestamp":         datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "anomaly_score":     score if score < 999 else 999.99,
            "threshold":         threshold,   # dynamic — from model.pkl
            "window_sequence":   batch,
            "failure_reason":    verdict,
            "failed_at_position": failed_pos,
            "expected_tokens":   [],
            "parse_tree": {
                "token_parseable": token_parseable or [True] * len(batch),
                "breakdown":       breakdown,
                "verdict":         verdict,
                "unknown_syscalls": unknown,
                "parse_spans":     parse_spans,
            },
        })
        with send_lock:
            send_queue.append(anomaly_msg)


def _ws_sender_thread(api_url: str, send_queue: list, send_lock: threading.Lock):
    """Background thread: maintains a persistent WebSocket to the backend ingest endpoint."""
    base = api_url.rstrip('/')
    if base.startswith('http://'):
        ws_url = 'ws://' + base[len('http://'):] + '/ws/ingest'
    elif base.startswith('https://'):
        ws_url = 'wss://' + base[len('https://'):] + '/ws/ingest'
    elif base.startswith('ws://') or base.startswith('wss://'):
        ws_url = base + '/ws/ingest'
    else:
        ws_url = 'ws://' + base + '/ws/ingest'

    async def _run():
        while True:
            try:
                async with websockets.connect(ws_url) as ws:
                    print(f"  [WS] Connected to {ws_url}")
                    while True:
                        with send_lock:
                            items = send_queue[:]
                            send_queue.clear()
                        if items:
                            for msg in items:
                                await ws.send(msg)
                        else:
                            await asyncio.sleep(0.05)
            except Exception as e:
                print(f"  [WS] Connection lost ({e}), reconnecting in 2s...")
                await asyncio.sleep(2)

    asyncio.run(_run())


def post_raw_syscalls(syscall: str, pid: str,
                      send_queue: list, send_lock: threading.Lock) -> None:
    """Queue a single raw syscall to be sent to the backend via WebSocket."""
    ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    msg = json.dumps({
        "timestamp":    ts,
        "thread":       "T1",
        "pid":          int(pid) if pid.isdigit() else 0,
        "syscall":      syscall,
        "args":         "",
        "return_value": 0,
    })
    with send_lock:
        send_queue.append(msg)


# ═════════════════════════════════════════════════════════════════════════════
# MONITOR LOOP
# ═════════════════════════════════════════════════════════════════════════════

def monitor(pid: str, cmd_to_run: str, detector, threshold: float,
            use_strace: bool, api_url: Optional[str],
            debug: bool, warmup_cycles: int) -> None:
    """
    Main monitoring loop.

    Attaches to PID, reads syscall stream, batches into cycles on idle
    syscalls, silently discards the first `warmup_cycles` cycles, then
    scores each subsequent cycle and flags anomalies.

    The threshold is the value loaded from model.pkl — never hardcoded.
    """
    import subprocess

    # Guard: ensure scorer exists before the loop (handles legacy pickles)
    _ensure_scorer(detector)

    if cmd_to_run:
        if use_strace:
            cmd = ["sudo", "strace", "-f", "-e", "trace=all"] + cmd_to_run.split()
        else:
            cmd = ["sudo", "stdbuf", "-oL", "-eL", "perf", "trace"] + cmd_to_run.split()
    else:
        if use_strace:
            cmd = ["sudo", "strace", "-f", "-e", "trace=all", "-p", pid]
        else:
            cmd = ["sudo", "stdbuf", "-oL", "-eL", "perf", "trace", "-p", pid]

    print(f"  Command   : {' '.join(cmd)}")
    print(f"  Idle on   : {', '.join(sorted(IDLE_SYSCALLS))}")
    print(f"  Threshold : {threshold:.4f}  (dynamic — from model.pkl)")
    print(f"  Warmup    : discarding first {warmup_cycles} cycles (startup burst)")
    print(f"\n  Attached. Generate traffic now. Press Ctrl+C to stop.\n")
    print(f"  {'─'*60}")

    batch:            list[str] = []
    raw_cycle_count:  int       = 0   # every flush attempt, including warmup
    scored_cycles:    int       = 0   # cycles actually scored (post-warmup)
    total_anomalies:  int       = 0
    line_queue:       list[str] = []
    lock              = threading.Lock()
    proc              = None

    # WebSocket sender
    send_queue: list[str] = []
    send_lock   = threading.Lock()
    if api_url:
        ws_thread = threading.Thread(
            target=_ws_sender_thread, args=(api_url, send_queue, send_lock), daemon=True
        )
        ws_thread.start()

    # Start persistent WebSocket sender thread
    send_queue: list[str] = []
    send_lock = threading.Lock()
    if api_url:
        ws_thread = threading.Thread(
            target=_ws_sender_thread, args=(api_url, send_queue, send_lock), daemon=True
        )
        ws_thread.start()

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
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
                
                # Instantly queue this raw syscall for the live dashboard
                if api_url:
                    post_raw_syscalls([syscall], pid, send_queue, send_lock)

                # Stream raw syscalls to dashboard (per-cycle batch sent after boundary)
                if api_url:
                    post_raw_syscalls(syscall, pid, send_queue, send_lock)

                # ── Cycle boundary: idle syscall seen ─────────────────────────
                if syscall in IDLE_SYSCALLS:
                    cycle_syscalls = [s for s in batch if s not in IDLE_SYSCALLS]
                    batch = []

                    if len(cycle_syscalls) < MIN_BATCH_LEN:
                        continue   # too short — noise, skip

                    raw_cycle_count += 1

                    # ── Warmup: silently discard startup burst ─────────────────
                    if raw_cycle_count <= warmup_cycles:
                        ts = datetime.datetime.now().strftime("%H:%M:%S")
                        print(f"  [{ts}] Warmup  {raw_cycle_count:>4}/{warmup_cycles}  "
                              f"| {len(cycle_syscalls):>3} syscalls | (startup — not scored)")
                        continue

                    # ── Steady-state: score the cycle ──────────────────────────
                    scored_cycles += 1
                    is_anom, score, explanation = detector.predict(cycle_syscalls)

                    ts        = datetime.datetime.now().strftime("%H:%M:%S")
                    score_str = f"{score:.4f}" if score < 999 else "∞"
                    flag      = "⚠ ANOMALY" if is_anom else "✓ normal "

                    print(f"  [{ts}] Cycle {scored_cycles:>4} | "
                          f"{len(cycle_syscalls):>3} syscalls | "
                          f"score={score_str:>9} | {flag}")

                    if is_anom:
                        total_anomalies += 1
                        report_anomaly(cycle, pid, cycle_syscalls,
                                       score, explanation,
                                       send_queue, send_lock)

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

        # Score any partial cycle if we're past warmup
        if batch and raw_cycle_count >= warmup_cycles:
            cycle_syscalls = [s for s in batch if s not in IDLE_SYSCALLS]
            if len(cycle_syscalls) >= MIN_BATCH_LEN:
                scored_cycles += 1
                is_anom, score, explanation = detector.predict(cycle_syscalls)
                score_str = f"{score:.4f}" if score < 999 else "∞"
                flag = "ANOMALY" if is_anom else "✓  normal"
                print(f"\n  [Final cycle] {len(cycle_syscalls)} syscalls | "
                      f"score={score_str} | {flag}")
                if is_anom:
                    total_anomalies += 1
                    report_anomaly(cycle, pid, cycle_syscalls,
                                   score, explanation,
                                   send_queue, send_lock)

    finally:
        if proc and proc.poll() is None:
            proc.terminate()
            proc.wait()

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"\n  {'═'*60}")
    print(f"  MONITORING SUMMARY")
    print(f"  {'═'*60}")
    print(f"  Warmup cycles : {min(raw_cycle_count, warmup_cycles)} discarded")
    print(f"  Scored cycles : {scored_cycles}")
    print(f"  Threshold     : {threshold:.4f}")
    print(f"  Anomalies     : {total_anomalies}  "
          f"({'%.1f' % (total_anomalies / scored_cycles * 100 if scored_cycles else 0)}%)")
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
    p.add_argument("--pid",      type=str, default="",
                   help="PID of the process to monitor")
    p.add_argument("--cmd",      type=str, default="",
                   help="Command to run and monitor")
    p.add_argument("--model",    type=str, required=True,
                   help="Path to model.pkl (from train.py)")
    p.add_argument("--strace",   action="store_true",
                   help="Use strace instead of perf trace")
    p.add_argument("--send-api", type=str, default=None, metavar="URL",
                   help="POST anomaly events to this URL (WebSocket)")
    p.add_argument("--debug",    action="store_true",
                   help="Print every raw line from the tracer")
    p.add_argument("--warmup",   type=int, default=DEFAULT_WARMUP_CYCLES,
                   metavar="N",
                   help=f"Discard first N cycles after attaching (default: {DEFAULT_WARMUP_CYCLES}). "
                        f"Covers startup burst syscalls (execve, capget, prlimit64, etc.).")
    args = p.parse_args()

    if not args.pid and not args.cmd:
        print("Error: Must provide either --pid or --cmd")
        sys.exit(1)

    print(f"\n{'═'*60}")
    print(f"  CFG-IDS LIVE MONITOR")
    print(f"{'═'*60}")
    print(f"  PID   : {args.pid or 'N/A'}")
    print(f"  CMD   : {args.cmd or 'N/A'}")
    print(f"  Model : {args.model}")
    print(f"  Tracer: {'strace' if args.strace else 'perf trace'}")
    print(f"  Warmup: {args.warmup} cycles")
    if args.send_api:
        print(f"  API   : {args.send_api}")
    print()

    # ── Load model ────────────────────────────────────────────────────────────
    try:
        payload   = load_model(args.model)
        detector  = payload["detector"]
        threshold = payload["threshold"]   # dynamic — computed at train time
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

    # Sanity-check the threshold — warn if it looks like a hardcoded fallback
    if threshold == 50.0:
        print(f"  ⚠ WARNING: Threshold is exactly 50.0 — this is the hardcoded fallback.")
        print(f"             The model's holdout traces were all unparseable at train time.")
        print(f"             Retrain with more/better data before deploying.")
        print()

    # ── Start monitoring ──────────────────────────────────────────────────────
    monitor(
        pid           = args.pid,
        cmd_to_run    = args.cmd,
        detector      = detector,
        threshold     = threshold,
        use_strace    = args.strace,
        api_url       = args.send_api,
        debug         = args.debug,
        warmup_cycles = args.warmup,
    )


if __name__ == "__main__":
    main()