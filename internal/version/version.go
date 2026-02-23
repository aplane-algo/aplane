// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

// Package version provides build version information for aPlane binaries.
// Values are injected at build time via -ldflags.
package version

import (
	"fmt"
	"runtime"
)

// These variables are set at build time via -ldflags.
// Example: go build -ldflags "-X aplane/internal/version.Version=1.0.0"
var (
	// Version is the semantic version (e.g., "0.38.0" or "0.38.0-dev")
	Version = "dev"

	// GitCommit is the git commit hash (short form)
	GitCommit = "unknown"

	// BuildTime is the build timestamp in RFC3339 format
	BuildTime = "unknown"
)

// String returns a formatted version string suitable for --version output.
func String() string {
	return fmt.Sprintf("%s (commit: %s, built: %s, %s/%s)",
		Version, GitCommit, BuildTime, runtime.GOOS, runtime.GOARCH)
}
