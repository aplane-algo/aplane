#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 APlane Project LLC
#
# Proves that binaries running without a logging handler cannot emit a slog record.
#
# appolicy, aplocalnet, and applugin-checksum link logging sources but install no
# handler. Two of them are TUIs, so a record would be written across the screen.
# They are exempt only while ordinary logging is unreachable from their main. A new
# reachable call invalidates the exemption even if no dependency changed, which is
# why this analyzes reachability and not imports.
#
# Each binary is analyzed separately, as built for production: no test code and no
# testmode tag, unlike deadcode-check. The result holds for the GOOS, GOARCH, and CGO
# setting printed below, and only for ordinary logging: Logger.log and
# Logger.logAttrs are not the only way to reach a handler. test/arch forbids the
# others in our code.
#
# A missing or unexpected result fails. Nothing here treats silence as safe: dead
# functions must be listed by name, so a Go release that renames them fails this
# check rather than passing it.
#
# Usage: check-logging-reach.sh <path-to-deadcode>
set -euo pipefail

deadcode=${1:?usage: check-logging-reach.sh <path-to-deadcode>}

exempt=(./cmd/appolicy ./cmd/aplocalnet ./cmd/applugin-checksum)
# Programs that log, to show the analysis can see it and that this check can fail.
controls=(./cmd/apshell ./test/arch/testdata/logreach)

fail() {
	echo "✗ $*" >&2
	exit 1
}

links_slog() {
	go list -deps "$1" | grep -qx 'log/slog'
}

# slog_state <package> prints "dead" when both functions are listed as unreachable
# and "live" when one isn't. It fails if the analysis can't be trusted.
slog_state() {
	local package=$1 output
	if ! output=$("$deadcode" -filter='^log/slog$' "$package" 2>&1); then
		fail "deadcode failed on $package:"$'\n'"$output"
	fi
	if ! grep -q 'unreachable func: ' <<<"$output"; then
		fail "deadcode reported nothing for log/slog in $package, so its output can't be trusted:"$'\n'"$output"
	fi
	if grep -q 'unreachable func: Logger\.log$' <<<"$output" &&
		grep -q 'unreachable func: Logger\.logAttrs$' <<<"$output"; then
		echo dead
	else
		echo live
	fi
}

echo "Checking logging reachability for $(go env GOOS)/$(go env GOARCH), CGO_ENABLED=$(go env CGO_ENABLED), no build tags"

for package in "${controls[@]}"; do
	[ "$(slog_state "$package")" = live ] ||
		fail "$package logs, but the analysis found no way for it to: this check can't be trusted"
	echo "  control $package: logging detected"
done

for package in "${exempt[@]}"; do
	if ! links_slog "$package"; then
		echo "  $package: log/slog not linked"
		continue
	fi
	if [ "$(slog_state "$package")" != dead ]; then
		fail "$package can now emit a log record but has no handler. Install one with clientlog.Install, or remove the call."
	fi
	echo "  $package: no reachable logging"
done

echo "✓ binaries without a handler can't log"
