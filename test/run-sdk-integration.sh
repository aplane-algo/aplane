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
import re
from pathlib import Path

config = Path(os.environ["APSIGNER_DATA"]) / "config.yaml"
match = re.search(r"(?m)^signer_port:\s*(\d+)\s*$", config.read_text())
if not match:
    raise SystemExit("signer_port not found in APSIGNER_DATA/config.yaml")
print(match.group(1))
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
