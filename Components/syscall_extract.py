import re
import numpy as np 

def extract_syscalls(text: str) -> list[str]:
    """
    Extract syscall names from a multi‑line strace output.
    Works on both regular lines and continuation lines like:
    "         ? (         ): python/167682  ... [continued]: openat())"
    """
    syscalls = []
    # Regex explanation:
    #   \b            word boundary
    #   [a-zA-Z_]+    syscall name (letters + optional underscore, though syscalls don't have underscores)
    #   \s*           optional whitespace
    #   \(            literal '('
    pattern = re.compile(r'\b([a-zA-Z_]+)\s*\(')
    
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        match = pattern.search(line)
        if match:
            syscalls.append(match.group(1))
    return syscalls



