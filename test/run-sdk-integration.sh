#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${APLANE_SDKS_REPO:-}" ]]; then
  echo "Skipping SDK integration tests (APLANE_SDKS_REPO not set)"
  exit 0
fi

if [[ ! -d "$APLANE_SDKS_REPO" ]]; then
  echo "APLANE_SDKS_REPO does not exist or is not a directory: $APLANE_SDKS_REPO" >&2
  exit 1
fi

check_sdk_test_requirements() {
  local python_dir="$APLANE_SDKS_REPO/python"
  local typescript_dir="$APLANE_SDKS_REPO/typescript"

  if [[ -d "$python_dir" ]] && ! pytest --version >/dev/null 2>&1; then
    cat >&2 <<EOF
Python SDK integration prerequisite unavailable: pytest

Install the Python SDK development dependencies, then rerun integration tests:
  cd "$python_dir"
  python3 -m pip install -e '.[dev]'
EOF
    exit 1
  fi

  if [[ -d "$typescript_dir" ]]; then
    if ! command -v node >/dev/null 2>&1; then
      echo "TypeScript SDK integration prerequisite missing: node" >&2
      exit 1
    fi
    if ! command -v npm >/dev/null 2>&1; then
      echo "TypeScript SDK integration prerequisite missing: npm" >&2
      exit 1
    fi
    warn_typescript_node_engines "$typescript_dir"
    if ! (cd "$typescript_dir" && node --import tsx --eval "" >/dev/null 2>&1); then
      cat >&2 <<EOF
TypeScript SDK integration prerequisite missing: local tsx dependency

Install the TypeScript SDK dependencies, then rerun integration tests:
  cd "$typescript_dir"
  npm ci
EOF
      exit 1
    fi
  fi
}

warn_typescript_node_engines() {
  local typescript_dir="$1"
  local package_lock="$typescript_dir/package-lock.json"

  if [[ ! -f "$package_lock" ]]; then
    return 0
  fi

  node - "$package_lock" <<'NODE' || true
const fs = require("node:fs");

const packageLockPath = process.argv[2];
const lock = JSON.parse(fs.readFileSync(packageLockPath, "utf8"));
const current = parseVersion(process.versions.node);

function parseVersion(value) {
  const match = String(value).trim().match(/^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?/);
  if (!match) {
    return null;
  }
  return [
    Number(match[1]),
    Number(match[2] || 0),
    Number(match[3] || 0),
  ];
}

function compareVersions(left, right) {
  for (let i = 0; i < 3; i++) {
    if (left[i] !== right[i]) {
      return left[i] < right[i] ? -1 : 1;
    }
  }
  return 0;
}

function satisfiesComparator(version, operator, target) {
  const cmp = compareVersions(version, target);
  switch (operator || "=") {
    case ">":
      return cmp > 0;
    case ">=":
      return cmp >= 0;
    case "<":
      return cmp < 0;
    case "<=":
      return cmp <= 0;
    case "=":
      return cmp === 0;
    case "^":
      if (cmp < 0) {
        return false;
      }
      return target[0] > 0
        ? version[0] === target[0]
        : version[0] === 0 && version[1] === target[1];
    case "~":
      return cmp >= 0 && version[0] === target[0] && version[1] === target[1];
    default:
      return true;
  }
}

function satisfiesRange(version, range) {
  const text = String(range).trim();
  if (!text || text === "*" || text.toLowerCase() === "latest") {
    return true;
  }
  return text.split("||").some((alternative) => {
    const comparators = [...alternative.matchAll(/(>=|<=|>|<|\^|~|=)?\s*v?(\d+(?:\.\d+){0,2})/g)];
    if (comparators.length === 0) {
      return true;
    }
    return comparators.every((match) =>
      satisfiesComparator(version, match[1], parseVersion(match[2]))
    );
  });
}

function packageName(path, pkg) {
  if (pkg && pkg.name) {
    return pkg.name;
  }
  const parts = path.split("node_modules/");
  return parts[parts.length - 1] || path || "(root)";
}

const packages = lock.packages || {};
const mismatches = [];
for (const [path, pkg] of Object.entries(packages)) {
  const required = pkg && pkg.engines && pkg.engines.node;
  if (!required || satisfiesRange(current, required)) {
    continue;
  }
  mismatches.push({
    name: packageName(path, pkg),
    version: pkg.version || "unknown",
    required,
  });
}

if (mismatches.length > 0) {
  console.error(
    `TypeScript SDK integration warning: current Node ${process.version} does not satisfy package engine requirements:`
  );
  for (const item of mismatches) {
    console.error(`  ${item.name}@${item.version} requires node ${item.required}`);
  }
  console.error("Tests will still run because npm treats these as warnings by default.");
}
NODE
}

check_sdk_test_requirements

if [[ ! -f .env.test ]]; then
  echo ".env.test not found; run test/setup-test-env.sh first" >&2
  exit 1
fi

set -a
. ./.env.test
set +a

: "${APSIGNER_DATA:?APSIGNER_DATA not set by .env.test}"
: "${APCLIENT_DATA:?APCLIENT_DATA not set by .env.test}"

runtime_dir="$APSIGNER_DATA/run"
mkdir -p "$runtime_dir"
chmod 700 "$runtime_dir"

project_root="$(pwd)"
binary="temp/apsigner-sdk-integration"
go build -o "$binary" ./cmd/apsigner
binary_abs="$project_root/$binary"

port="$(python3 - <<'PY'
import os
from pathlib import Path

config = Path(os.environ["APSIGNER_DATA"]) / "config.yaml"
in_endpoint = False
for raw in config.read_text().splitlines():
    stripped = raw.strip()
    if not stripped or stripped.startswith("#"):
        continue
    indent = len(raw) - len(raw.lstrip(" "))
    if indent == 0:
        in_endpoint = stripped == "endpoint:"
        continue
    if in_endpoint and indent == 2 and stripped.startswith("signer_port:"):
        value = stripped.split(":", 1)[1].split("#", 1)[0].strip()
        if not value.isdigit():
            raise SystemExit(f"endpoint.signer_port is not numeric in {config}")
        print(value)
        break
else:
    raise SystemExit("endpoint.signer_port not found in APSIGNER_DATA/config.yaml")
PY
)"

log_file="${TMPDIR:-/tmp}/aplane-sdk-integration-apsigner.log"

pushd "$APSIGNER_DATA" >/dev/null
"$binary_abs" >"$log_file" 2>&1 &
signer_pid=$!
popd >/dev/null

cleanup() {
  kill "$signer_pid" 2>/dev/null || true
  wait "$signer_pid" 2>/dev/null || true
  rm -f "$binary_abs"
}
trap cleanup EXIT

ready=0
for _ in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:$port/health" >/dev/null 2>&1; then
    ready=1
    break
  fi
  if ! kill -0 "$signer_pid" 2>/dev/null; then
    echo "apsigner exited before becoming ready" >&2
    tail -80 "$log_file" >&2 || true
    exit 1
  fi
  sleep 1
done

if [[ "$ready" != 1 ]]; then
  echo "apsigner did not become ready for SDK integration tests" >&2
  tail -80 "$log_file" >&2 || true
  exit 1
fi

echo "Running SDK integration tests from $APLANE_SDKS_REPO"
(
  cd "$APLANE_SDKS_REPO"
  APLANE_SDK_INTEGRATION=1 \
    APSIGNER_DATA="$APSIGNER_DATA" \
    APCLIENT_DATA="$APCLIENT_DATA" \
    make --no-print-directory integration-test
)
