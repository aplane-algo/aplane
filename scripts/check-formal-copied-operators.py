#!/usr/bin/env python3
"""Check copied TLA+ operators in composed formal specs.

The composed specs intentionally copy small pure operators instead of importing
them because the source modules declare colliding variables. This check keeps
those copies honest without changing the TLA module structure.
"""

from __future__ import annotations

import difflib
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FORMAL_DIR = ROOT / "docs" / "formal"


OPERATOR_RE = re.compile(r"^([A-Za-z][A-Za-z0-9_]*)\s*(?:\([^)]*\))?\s*==")
SECTION_RE = re.compile(r"^(?:-{5,}|={5,})")
UNCHANGED_RE = re.compile(r"UNCHANGED\s*<<(?P<vars>.*?)>>", re.DOTALL)


class CheckFailure(Exception):
    pass


def strip_comments(text: str) -> str:
    text = re.sub(r"\(\*.*?\*\)", "", text, flags=re.DOTALL)
    return "\n".join(line.split(r"\*", 1)[0] for line in text.splitlines())


def module_operators(module_name: str) -> dict[str, str]:
    path = FORMAL_DIR / f"{module_name}.tla"
    lines = strip_comments(path.read_text()).splitlines()
    starts: list[tuple[int, str]] = []
    for idx, line in enumerate(lines):
        match = OPERATOR_RE.match(line)
        if match:
            starts.append((idx, match.group(1)))

    operators: dict[str, str] = {}
    for pos, (start, name) in enumerate(starts):
        next_start = starts[pos + 1][0] if pos + 1 < len(starts) else len(lines)
        end = next_start
        for idx in range(start + 1, next_start):
            if SECTION_RE.match(lines[idx]):
                end = idx
                break
        operators[name] = "\n".join(lines[start:end]).strip()
    return operators


def parse_unchanged_vars(vector: str) -> list[str]:
    return [part.strip() for part in vector.replace("\n", " ").split(",") if part.strip()]


def replace_spans(text: str, replacements: list[tuple[tuple[int, int], str]]) -> str:
    for (start, end), replacement in sorted(replacements, reverse=True):
        text = text[:start] + replacement + text[end:]
    return text


def normalize_allowed_unchanged(
    source: str,
    target: str,
    allowed_target_extras: set[str],
    label: str,
) -> tuple[str, str]:
    source_matches = list(UNCHANGED_RE.finditer(source))
    target_matches = list(UNCHANGED_RE.finditer(target))
    if len(source_matches) != len(target_matches):
        raise CheckFailure(
            f"{label}: source has {len(source_matches)} UNCHANGED clauses, "
            f"target has {len(target_matches)}"
        )

    source_replacements: list[tuple[tuple[int, int], str]] = []
    target_replacements: list[tuple[tuple[int, int], str]] = []
    for source_match, target_match in zip(source_matches, target_matches):
        source_vars = parse_unchanged_vars(source_match.group("vars"))
        target_vars = parse_unchanged_vars(target_match.group("vars"))
        source_set = set(source_vars)
        target_set = set(target_vars)
        missing = source_set - target_set
        extras = target_set - source_set
        if missing:
            raise CheckFailure(f"{label}: target UNCHANGED clause is missing {sorted(missing)}")
        if extras - allowed_target_extras:
            raise CheckFailure(
                f"{label}: target UNCHANGED clause has unexpected extras "
                f"{sorted(extras - allowed_target_extras)}"
            )
        canonical = "UNCHANGED <<" + ", ".join(source_vars) + ">>"
        source_replacements.append((source_match.span(), canonical))
        target_replacements.append((target_match.span(), canonical))

    return (
        replace_spans(source, source_replacements),
        replace_spans(target, target_replacements),
    )


def compact_definition(definition: str, canonical_name: str) -> str:
    definition = OPERATOR_RE.sub(
        lambda match: match.group(0).replace(match.group(1), canonical_name, 1),
        definition,
        count=1,
    )
    return re.sub(r"\s+", "", definition)


def pretty_definition(definition: str, canonical_name: str) -> list[str]:
    definition = OPERATOR_RE.sub(
        lambda match: match.group(0).replace(match.group(1), canonical_name, 1),
        definition,
        count=1,
    )
    return [line.rstrip() for line in definition.splitlines()]


def compare_operator(
    source_module: str,
    source_name: str,
    target_module: str,
    target_name: str | None = None,
    canonical_name: str | None = None,
    allow_unchanged_extras: set[str] | None = None,
) -> None:
    target_name = target_name or source_name
    canonical_name = canonical_name or target_name
    source_ops = module_operators(source_module)
    target_ops = module_operators(target_module)
    if source_name not in source_ops:
        raise CheckFailure(f"{source_module}.{source_name}: source operator not found")
    if target_name not in target_ops:
        raise CheckFailure(f"{target_module}.{target_name}: target operator not found")

    source = source_ops[source_name]
    target = target_ops[target_name]
    label = f"{target_module}.{target_name} copied from {source_module}.{source_name}"
    if allow_unchanged_extras is not None:
        source, target = normalize_allowed_unchanged(source, target, allow_unchanged_extras, label)

    if compact_definition(source, canonical_name) == compact_definition(target, canonical_name):
        return

    diff = "\n".join(
        difflib.unified_diff(
            pretty_definition(source, canonical_name),
            pretty_definition(target, canonical_name),
            fromfile=f"{source_module}.{source_name}",
            tofile=f"{target_module}.{target_name}",
            lineterm="",
        )
    )
    raise CheckFailure(f"{label} drifted:\n{diff}")


SIGN_BOUNDARY_COPIES = [
    "RequestMode",
    "SlotClass",
    "RequestEntry",
    "ValidRequest",
    "PlannedSlot",
    "Plan",
    "SignOutput",
    "BoundedRequests",
]

POLICY_PRECEDENCE_COPIES = [
    ("RuleMatches", None),
    ("Verdict", "PolicyVerdict"),
    ("Approval", None),
    ("Outcome", None),
    ("Decide", None),
    ("ApplyApproval", None),
]

LIFECYCLE_LOCK_COPIES = [
    "AdminState",
    "WriterPending",
    "SignerAcquire",
    "AdminBeginDecommission",
    "AdminAcquireWrite",
    "AdminMarkDecommissioned",
    "AdminReleaseWrite",
]


def main() -> int:
    try:
        for target_module in ("composition", "approval_composition"):
            for operator in SIGN_BOUNDARY_COPIES:
                compare_operator("sign_boundary", operator, target_module)
            for source_name, target_name in POLICY_PRECEDENCE_COPIES:
                compare_operator(
                    "policy_precedence",
                    source_name,
                    target_module,
                    target_name=target_name,
                )

        for operator in LIFECYCLE_LOCK_COPIES:
            compare_operator(
                "lifecycle",
                operator,
                "lifecycle_composition",
                allow_unchanged_extras={"policySigned", "signerOutput"},
            )
    except CheckFailure as exc:
        print(f"formal copied-operator sync check failed: {exc}", file=sys.stderr)
        return 1

    print("formal copied-operator sync check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
