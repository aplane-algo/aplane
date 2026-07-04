#!/usr/bin/env python3
"""Run TLC over the formal models and verify recorded metrics.

docs/formal/metrics.json is the authority for WHICH (spec, cfg) pairs run
and what shape their state spaces have. Each entry records the distinct
state count and search depth of the last accepted run; a mismatch fails
the build with instructions, so a spec edit that changes the state space
must consciously update the recorded metrics (and the roadmap table that
mirrors them). This also catches accidental state-space explosions.

Usage:
  scripts/run-formal-tests.py            # docs/formal/metrics.json
  scripts/run-formal-tests.py --deep     # docs/formal/metrics_deep.json

The TLC jar is found via $TLA2TOOLS_JAR, then .tools/tla2tools.jar,
tla2tools.jar, ~/tla/tla2tools.jar (same lookup the Makefile used).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FORMAL_DIR = ROOT / "docs" / "formal"

# Parsed against comma-stripped output, anchored on the final summary line
# ("N states generated, M distinct states found, 0 states left on queue") —
# TLC's intermediate Progress lines print the same phrase with
# comma-grouped digits.
DISTINCT_RE = re.compile(r"(\d+) distinct states found 0 states left on queue")
DEPTH_RE = re.compile(r"depth of the complete state graph search is (\d+)")
SUCCESS = "Model checking completed. No error has been found."


def find_jar() -> Path:
    env = os.environ.get("TLA2TOOLS_JAR", "")
    candidates = [env] if env else []
    candidates += [
        str(ROOT / ".tools" / "tla2tools.jar"),
        "tla2tools.jar",
        str(Path.home() / "tla" / "tla2tools.jar"),
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return Path(candidate)
    sys.exit(
        "Error: tla2tools.jar not found. "
        "Set TLA2TOOLS_JAR=/path/to/tla2tools.jar."
    )


def run_entry(jar: Path, entry: dict) -> list[str]:
    spec = entry["spec"]
    cfg = entry.get("cfg", spec)
    label = spec if cfg == spec else f"{spec} ({cfg}.cfg)"
    print(f"Running TLC for {label}")
    proc = subprocess.run(
        [
            "java",
            "-XX:+UseParallelGC",
            "-cp",
            str(jar),
            "tlc2.TLC",
            "-cleanup",
            "-config",
            str(FORMAL_DIR / f"{cfg}.cfg"),
            str(FORMAL_DIR / f"{spec}.tla"),
        ],
        capture_output=True,
        text=True,
    )
    output = (proc.stdout + proc.stderr).replace(",", "")
    problems: list[str] = []
    if SUCCESS not in output:
        sys.stdout.write(output)
        problems.append(f"{label}: TLC did not complete cleanly (see output above)")
        return problems

    distinct = DISTINCT_RE.search(output)
    depth = DEPTH_RE.search(output)
    if not distinct or not depth:
        problems.append(f"{label}: could not parse state count/depth from TLC output")
        return problems

    got = {"distinct_states": int(distinct.group(1)), "depth": int(depth.group(1))}
    for key in ("distinct_states", "depth"):
        if got[key] != entry[key]:
            problems.append(
                f"{label}: {key} = {got[key]}, recorded {entry[key]} — the spec "
                f"changed shape. If intentional, update the entry in "
                f"docs/formal/{metrics_name} and the roadmap's module table."
            )
    return problems


if __name__ == "__main__":
    metrics_name = "metrics_deep.json" if "--deep" in sys.argv[1:] else "metrics.json"
    metrics_path = FORMAL_DIR / metrics_name
    entries = json.loads(metrics_path.read_text())
    jar = find_jar()
    failures: list[str] = []
    for entry in entries:
        failures.extend(run_entry(jar, entry))
    if failures:
        print("\nFormal metrics check FAILED:")
        for failure in failures:
            print(f"  - {failure}")
        sys.exit(1)
    print(f"All {len(entries)} TLC runs passed with recorded metrics ({metrics_name}).")
