#!/usr/bin/env python3
import math, collections, sys, os

def print_entropy():
    """Compute and print Shannon entropy for a file given as a CLI argument."""
    if len(sys.argv) < 2:
        print(f"Usage: {os.path.basename(sys.argv[0])} <file>")
        return

    path = sys.argv[1]
    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception as e:
        print(f"[ERROR] Cannot read {path}: {e}")
        return

    if not data:
        print(f"{path}: empty file (entropy = 0.0)")
        return

    counts = collections.Counter(data)
    length = len(data)
    ent = 0.0
    for count in counts.values():
        p = count / length
        ent -= p * math.log2(p)

    print(f"{path}: Entropy = {ent:.3f} bits/byte, Size = {length} bytes")

if __name__ == "__main__":
    print_entropy()
