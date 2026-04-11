#!/usr/bin/env python
"""Run tests and generate summary report."""

import subprocess
import sys
from pathlib import Path


def run_tests():
    """Run tests and print summary."""
    print("=" * 70)
    print("🧪 AI Bug Hunter - Test Suite")
    print("=" * 70)
    
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/", "-v", "--tb=short"],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent,
    )
    
    # Print full output
    print(result.stdout)
    if result.stderr:
        print(result.stderr)
    
    # Parse summary
    lines = result.stdout.split("\n")
    for line in lines:
        if "passed" in line or "failed" in line:
            print(f"\n{'=' * 70}")
            print(f"📊 {line.strip()}")
            print(f"{'=' * 70}")
            break
    
    return result.returncode


if __name__ == "__main__":
    sys.exit(run_tests())
