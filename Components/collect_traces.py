"""
collect_traces.py — Phase 1: Data Collection
=============================================
Attaches to a running process OR launches a new one, collects normal
syscall traces, and saves them as a .pkl file.

Usage:
  # Attach to an already-running process by PID:
  python collect_traces.py --pid 1234 normal_traces.pkl

  # Launch a command and trace it from the start:
  python collect_traces.py --cmd "node server.js" normal_traces.pkl
  python collect_traces.py --cmd "python -m http.server 8080" normal_traces.pkl

  # Use strace instead of perf trace (more reliable on most systems):
  python collect_traces.py --pid 1234 normal_traces.pkl --strace
  python collect_traces.py --cmd "node server.js" normal_traces.pkl --strace

  # Stop automatically after N seconds:
  python collect_traces.py --cmd "node server.js" normal_traces.pkl --timeout 60

  # Print every raw tracer line (debug):
  python collect_traces.py --pid 1234 normal_traces.pkl --debug

  # Skip the first N cycles (startup burst — execve, capget, prlimit64, etc.):
  python collect_traces.py --cmd "node server.js" normal_traces.pkl --skip-startup 10

Workflow (--cmd mode):
  1. python collect_traces.py --cmd "node server.js" normal_traces.pkl --strace &
  2. # generate traffic: curl, wrk, browser, etc.
  3. Ctrl+C to stop (or wait for --timeout)
  4. python train.py normal_traces.pkl model.pkl

Workflow (--pid mode):
  1. node server.js &          # start process separately
  2. python collect_traces.py --pid $! normal_traces.pkl --strace &
  3. # generate traffic
  4. Ctrl+C
  5. python train.py normal_traces.pkl model.pkl

Output format (normal_traces.pkl):
  {
    "traces":   [ ["open","read","close"], ["openat","read","close"], ... ],
    "pid":      1234,
    "cmd":      "node server.js",   # or None for --pid mode
    "count":    847,
    "duration": 32.4,
    "created":  "2026-04-25T14:23:11"
  }
"""

from __future__ import annotations
import sys
import os
import re
import time
import pickle
import shlex
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

# ── Syscalls to skip — too noisy, not behaviorally meaningful ─────────────────
SKIP_SYSCALLS = {
    'mprotect', 'brk', 'munmap', 'arch_prctl',
    'set_tid_address', 'set_robust_list', 'rseq',
    'sched_getaffinity', 'getpid', 'getppid',
    'gettid', 'getuid', 'getgid', 'geteuid', 'getegid',
    'rt_sigaction', 'rt_sigprocmask', 'rt_sigreturn',
    'sigaltstack',
}

MIN_TRACE_LEN  = 3    # discard traces shorter than this
MAX_TRACE_LEN  = 200  # cap very long traces

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
    """Accumulates syscall batches. A batch = syscalls between two idle syscalls."""

    def __init__(self, debug: bool = False, skip_startup: int = 0):
        self.traces:         list[list[str]] = []
        self.debug:          bool            = debug
        self.skip_startup:   int             = skip_startup  # skip first N cycles
        self._batch:         list[str]       = []
        self._total_syscalls = 0
        self._cycle_count    = 0            # includes skipped cycles
        self._start          = time.time()

    def push(self, syscall: str) -> None:
        self._total_syscalls += 1
        self._batch.append(syscall)
        if syscall in IDLE_SYSCALLS:
            self._flush()

    def _flush(self) -> None:
        trace = [s for s in self._batch if s not in IDLE_SYSCALLS]
        self._batch = []
        self._cycle_count += 1

        # Skip startup cycles (execve, capget, prlimit64 burst)
        if self._cycle_count <= self.skip_startup:
            if self.debug:
                print(f"  [skip startup cycle {self._cycle_count}/{self.skip_startup}]"
                      f"  {' '.join(trace[:6])}")
            return

        if len(trace) < MIN_TRACE_LEN:
            return
        if len(trace) > MAX_TRACE_LEN:
            trace = trace[:MAX_TRACE_LEN]

        self.traces.append(trace)
        n = len(self.traces)
        if n % 5 == 0 or n <= 3:
            elapsed = time.time() - self._start
            preview = " ".join(trace[:6]) + ("..." if len(trace) > 6 else "")
            print(f"  [trace {n:>4}]  len={len(trace):>4}  ({preview})")

    def flush_final(self) -> None:
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
            "cycles":   self._cycle_count,
            "skipped":  self.skip_startup,
            "duration": round(elapsed, 2),
            "rate":     round(self._total_syscalls / elapsed, 1) if elapsed > 0 else 0,
        }


# ═════════════════════════════════════════════════════════════════════════════
# COMMAND BUILDERS
# ═════════════════════════════════════════════════════════════════════════════

def _build_cmd(use_strace: bool, pid: Optional[int], cmd_str: Optional[str]) -> list[str]:
    """
    Build the tracer command for either attach (--pid) or launch (--cmd) mode.

    Attach mode  (pid given, cmd_str=None):
      strace:  sudo strace -f -e trace=all -p <pid>
      perf:    sudo stdbuf -oL -eL perf trace -p <pid>

    Launch mode  (cmd_str given, pid=None):
      strace:  sudo strace -f -e trace=all -- <cmd_str tokens>
      perf:    sudo stdbuf -oL -eL perf trace -- <cmd_str tokens>

    The "--" separator is important for perf/strace so they don't try to
    interpret flags from the user's command as their own flags.
    """
    if use_strace:
        base = ["sudo", "strace", "-f", "-e", "trace=all"]
        if pid is not None:
            return base + ["-p", str(pid)]
        else:
            return base + ["--"] + shlex.split(cmd_str)
    else:
        base = ["sudo", "stdbuf", "-oL", "-eL", "perf", "trace"]
        if pid is not None:
            return base + ["-p", str(pid)]
        else:
            return base + ["--"] + shlex.split(cmd_str)


# ═════════════════════════════════════════════════════════════════════════════
# RUNNER
# ═════════════════════════════════════════════════════════════════════════════

def run_collector(collector: TraceCollector,
                  cmd: list[str],
                  timeout: Optional[float],
                  mode_label: str) -> Optional[int]:
    """
    Start the tracer subprocess, feed lines into collector.
    Returns the PID of the traced process (extracted from strace output if
    launched via --cmd, or the PID we were given).

    strace --cmd mode prints the PID on the first line:
      "strace: Process 12345 attached"   (attach)
      "execve(...)  = 0"                  (launch — PID is proc.pid of strace itself,
                                           but strace -f tracks children so we use proc.pid)
    """
    queue: list[str] = []
    lock   = threading.Lock()
    proc   = None
    traced_pid: Optional[int] = None
    deadline = time.time() + timeout if timeout else None

    def reader(stream):
        for raw in stream:
            try:
                line = raw.decode("utf-8", errors="replace").rstrip()
            except Exception:
                continue
            with lock:
                queue.append(line)

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )

        # In --cmd mode the strace child PID ≈ proc.pid + 1 but that's
        # unreliable.  We extract it from strace's stderr header instead.
        pid_re = re.compile(r'(?:Process\s+(\d+)\s+attached|execve.*=\s*0)')

        for stream in (proc.stdout, proc.stderr):
            t = threading.Thread(target=reader, args=(stream,), daemon=True)
            t.start()

        lines_seen    = 0
        syscalls_seen = 0

        print(f"  {mode_label}")
        print(f"  Command : {' '.join(cmd)}")
        print(f"  Generate traffic now. Press Ctrl+C to stop.\n")

        while True:
            time.sleep(0.02)

            with lock:
                current = queue[:]
                queue.clear()

            for line in current:
                lines_seen += 1

                if collector.debug:
                    print(f"  [raw] {line}")

                # Try to extract traced PID from strace header
                if traced_pid is None:
                    m = pid_re.search(line)
                    if m and m.group(1):
                        traced_pid = int(m.group(1))
                        print(f"  ✓ Traced process PID: {traced_pid}")

                syscall = extract_syscall(line)
                if syscall is None:
                    continue

                syscalls_seen += 1
                if syscalls_seen == 1:
                    print(f"  ✓ First syscall captured: {syscall!r}")

                collector.push(syscall)

            if deadline and time.time() > deadline:
                print(f"\n  Timeout reached ({timeout}s).")
                break

            if proc.poll() is not None:
                print(f"\n  Tracer exited (code {proc.returncode}).")
                if lines_seen == 0:
                    _print_no_output_help(cmd)
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

    return traced_pid or (proc.pid if proc else None)


def _print_no_output_help(cmd: list[str]) -> None:
    print("  ✗ No output received from tracer. Possible causes:")
    if "perf" in cmd:
        print("    • perf_event_paranoid too restrictive:")
        print("        sudo sysctl -w kernel.perf_event_paranoid=-1")
        print("    • Try --strace for a more reliable alternative")
    else:
        print("    • Process may have exited before strace attached")
        print("    • Try: sudo strace -e trace=all -p <pid>  manually")
    print("    • Run with --debug to see all raw lines")


# ═════════════════════════════════════════════════════════════════════════════
# SAVE / LOAD
# ═════════════════════════════════════════════════════════════════════════════

def save_traces(traces: list[list[str]],
                output_path: str,
                pid: Optional[int] = None,
                cmd: Optional[str] = None,
                duration: float = 0.0) -> None:
    payload = {
        "traces":   traces,
        "pid":      pid,
        "cmd":      cmd,
        "count":    len(traces),
        "duration": round(duration, 2),
        "created":  datetime.datetime.now().isoformat(timespec="seconds"),
    }
    with open(output_path, "wb") as f:
        pickle.dump(payload, f)
    size_kb = os.path.getsize(output_path) / 1024
    print(f"\n  Saved {len(traces)} traces → {output_path}  ({size_kb:.1f} KB)")


def load_traces(path: str) -> list[list[str]]:
    with open(path, "rb") as f:
        payload = pickle.load(f)
    if isinstance(payload, dict):
        return payload["traces"]
    return payload   # legacy plain list


# ═════════════════════════════════════════════════════════════════════════════
# CLI
# ═════════════════════════════════════════════════════════════════════════════

def main():
    p = argparse.ArgumentParser(
        description="Collect normal syscall traces from a process.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # ── Source: exactly one of --pid or --cmd ────────────────────────────────
    source = p.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--pid", type=int, metavar="PID",
        help="Attach to an already-running process by PID",
    )
    source.add_argument(
        "--cmd", type=str, metavar="COMMAND",
        help='Launch and trace a new process  (e.g. --cmd "node server.js")',
    )

    # ── Output ───────────────────────────────────────────────────────────────
    p.add_argument(
        "output", type=str,
        help="Output .pkl file path  (e.g. normal_traces.pkl)",
    )

    # ── Options ──────────────────────────────────────────────────────────────
    p.add_argument("--strace",        action="store_true",
                   help="Use strace instead of perf trace (recommended)")
    p.add_argument("--timeout",       type=float, default=None, metavar="SECONDS",
                   help="Stop automatically after N seconds")
    p.add_argument("--skip-startup",  type=int,   default=0,   metavar="N",
                   help="Skip the first N cycles (startup burst).  "
                        "Useful with --cmd to ignore execve / loader syscalls. "
                        "(default: 0)")
    p.add_argument("--debug",         action="store_true",
                   help="Print every raw line from the tracer")

    args = p.parse_args()

    # ── Build tracer command ─────────────────────────────────────────────────
    cmd = _build_cmd(
        use_strace = args.strace,
        pid        = args.pid,
        cmd_str    = args.cmd,
    )

    mode_label = (
        f"ATTACH mode  — PID {args.pid}"
        if args.pid
        else f"LAUNCH mode  — $ {args.cmd}"
    )

    print(f"\n{'═'*60}")
    print(f"  TRACE COLLECTOR")
    print(f"{'═'*60}")
    print(f"  Mode    : {mode_label}")
    print(f"  Output  : {args.output}")
    print(f"  Tracer  : {'strace' if args.strace else 'perf trace'}")
    if args.timeout:
        print(f"  Timeout : {args.timeout}s")
    if args.skip_startup:
        print(f"  Skip    : first {args.skip_startup} startup cycles")
    print()

    # ── Collect ──────────────────────────────────────────────────────────────
    collector = TraceCollector(debug=args.debug, skip_startup=args.skip_startup)

    traced_pid = run_collector(
        collector  = collector,
        cmd        = cmd,
        timeout    = args.timeout,
        mode_label = mode_label,
    )

    collector.flush_final()

    # ── Summary ──────────────────────────────────────────────────────────────
    s = collector.stats()
    print(f"\n{'─'*60}")
    print(f"  Traces collected : {s['traces']}")
    if s['skipped']:
        print(f"  Startup skipped  : {s['skipped']} cycles")
    print(f"  Total syscalls   : {s['syscalls']}")
    print(f"  Total cycles     : {s['cycles']}")
    print(f"  Duration         : {s['duration']}s")
    print(f"  Rate             : {s['rate']} syscalls/s")
    print(f"{'─'*60}")

    if s['traces'] == 0:
        print("\n  ✗ No traces collected. Cannot save.")
        print("  Possible fixes:")
        print("    • With --cmd: add --skip-startup 5 to skip the loader burst")
        print("    • Try --strace (more reliable than perf on most systems)")
        print("    • Make sure idle syscalls fire: epoll_wait, poll, futex, etc.")
        print("    • Generate more traffic (curl, wrk, browser requests)")
        sys.exit(1)

    save_traces(
        collector.traces,
        output_path = args.output,
        pid         = traced_pid or args.pid,
        cmd         = args.cmd,
        duration    = s['duration'],
    )

    print(f"\n  Next step:")
    print(f"    python train.py {args.output} model.pkl")


if __name__ == "__main__":
    main()