#!/usr/bin/env python3
"""Run TLC over the formal models and verify recorded outcomes and metrics.

docs/formal/metrics.json is the authority for WHICH (spec, cfg) pairs run
and what outcome and state-space shape each check must have. Normal entries
must complete without an error. An entry with ``expected_invariant_violation``
is a negative control and must produce that exact counterexample. Every entry
records the distinct state count and search depth of the last accepted run; a
mismatch fails the build with instructions, so a spec edit that changes the
state space must consciously update the recorded metrics (and the roadmap
table that mirrors them). This also catches accidental state-space explosions.

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

# Parsed against comma-stripped output. TLC's intermediate Progress lines use
# comma-grouped digits, while the final summary has no parenthesized rate.
SUMMARY_RE = re.compile(
    r"^(\d+) states generated (\d+) distinct states found "
    r"(\d+) states left on queue\.$",
    re.MULTILINE,
)
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
    expected_violation = entry.get("expected_invariant_violation")
    if expected_violation:
        label += f" [expects {expected_violation} violation]"
    print(f"Running TLC for {label}")
    proc = subprocess.run(
        [
            "java",
            "-XX:+UseParallelGC",
            "-cp",
            str(jar),
            "tlc2.TLC",
            "-cleanup",
            "-noGenerateSpecTE",
            "-config",
            str(FORMAL_DIR / f"{cfg}.cfg"),
            str(FORMAL_DIR / f"{spec}.tla"),
        ],
        capture_output=True,
        text=True,
    )
    output = (proc.stdout + proc.stderr).replace(",", "")
    problems: list[str] = []
    if expected_violation:
        violation_text = f"Invariant {expected_violation} is violated."
        if violation_text not in output:
            sys.stdout.write(output)
            problems.append(
                f"{label}: TLC did not produce the expected invariant violation "
                f"(see output above)"
            )
            return problems
        if SUCCESS in output or proc.returncode == 0:
            sys.stdout.write(output)
            problems.append(
                f"{label}: TLC reported success while an invariant violation "
                f"was expected"
            )
            return problems
    elif SUCCESS not in output or proc.returncode != 0:
        sys.stdout.write(output)
        problems.append(f"{label}: TLC did not complete cleanly (see output above)")
        return problems

    summary = SUMMARY_RE.search(output)
    depth = DEPTH_RE.search(output)
    if not summary or not depth:
        problems.append(f"{label}: could not parse state count/depth from TLC output")
        return problems

    got = {"distinct_states": int(summary.group(2)), "depth": int(depth.group(1))}
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
        print("\nFormal outcome/metrics check FAILED:")
        for failure in failures:
            print(f"  - {failure}")
        sys.exit(1)
    print(
        f"All {len(entries)} TLC runs matched recorded outcomes and metrics "
        f"({metrics_name})."
    )
