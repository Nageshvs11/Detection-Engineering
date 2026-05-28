#!/usr/bin/env python3
"""
Return the next 3-digit sequence number for a detection rule directory.

Usage:
    python3 next-seq.py /opt/DetectionEngineering/kql/windows
    # → 001   (no files yet)
    # → 004   (after 001, 002, 003 exist)
"""

import re
import sys
from pathlib import Path

SEQ_RE = re.compile(r"^(\d{3})_")


def next_seq(directory: str) -> str:
    d = Path(directory)
    if not d.exists():
        print(f"Directory does not exist: {d}", file=sys.stderr)
        sys.exit(1)

    highest = 0
    for f in d.iterdir():
        m = SEQ_RE.match(f.name)
        if m:
            highest = max(highest, int(m.group(1)))

    return f"{highest + 1:03d}"


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: next-seq.py <directory>", file=sys.stderr)
        sys.exit(1)
    print(next_seq(sys.argv[1]))
