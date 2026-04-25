import sys
import re
import signal
import subprocess
from sequitur import SequiturSimple   # make sure sequitur.py is in same folder


SYSCALL_PATTERN = re.compile(r'\b([a-zA-Z_]+)\s*\(')

def extract_syscall_from_line(line: str) -> str | None:
    """Return syscall name or None if not found."""
    match = SYSCALL_PATTERN.search(line)
    return match.group(1) if match else None

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <PID>")
        sys.exit(1)

    pid = sys.argv[1]
    cmd = ["sudo", "perf", "trace", "-p", pid]

    print(f"Monitoring PID {pid} with: {' '.join(cmd)}")
    print("Press Ctrl+C to stop and see the grammar.\n")

    syscalls = []
    try:
        # Start perf trace, pipe stdout and stderr
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,   # merge stderr into stdout
            text=True,
            bufsize=1                    # line buffered
        )

        # Read line by line
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            syscall = extract_syscall_from_line(line)
            if syscall:
                syscalls.append(syscall)
                # Optional: print live syscalls
                print(f"[{len(syscalls)}] {syscall}")
            else:
                # Print lines we couldn't parse (for debugging)
                print(f"[?] {line[:80]}", file=sys.stderr)

    except KeyboardInterrupt:
        print("\n\nInterrupted. Processing collected syscalls...")
    finally:
        if proc.poll() is None:
            proc.terminate()
            proc.wait()

    # Now run Sequitur on the collected sequence
    if not syscalls:
        print("No syscalls captured.")
        return

    print(f"\nCollected {len(syscalls)} syscalls. First 20: {syscalls[:20]}\n")
    sq = SequiturSimple()
    sq.learn(syscalls)
    sq.print_grammar()

    # Optional: verify expansion
    expanded = sq.expand()
    print(f"\nExpansion matches original: {expanded == syscalls}")

if __name__ == "__main__":
    main()