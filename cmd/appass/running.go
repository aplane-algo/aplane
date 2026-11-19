// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"fmt"
	"net"
	"time"

	"github.com/aplane-algo/aplane/internal/signerprobe"
)

const signerCheckTimeout = 300 * time.Millisecond

// signerProbeDial replaces signerprobe's default dial in tests. Production
// leaves it nil.
var signerProbeDial func(socketPath string, timeout time.Duration) (net.Conn, error)

// requireSignerStopped fails closed when apsigner is reachable for the same data dir.
func requireSignerStopped(dataDir string) error {
	running, socketPath, err := signerRunning(dataDir)
	if err != nil {
		return err
	}
	if running {
		return fmt.Errorf("WARNING: appass cannot run while apsigner is running.\n\nStop apsigner for data dir %s, then run appass again.\nActive IPC socket: %s", dataDir, socketPath)
	}
	return nil
}

func signerRunning(dataDir string) (bool, string, error) {
	result, err := signerprobe.Check(dataDir, signerprobe.Options{
		Timeout:         signerCheckTimeout,
		DataDirExplicit: true,
		Dial:            signerProbeDial,
	})
	if err != nil {
		if result.IPCPath != "" {
			return false, result.IPCPath, fmt.Errorf("check signer IPC socket %s: %w", result.IPCPath, err)
		}
		return false, "", err
	}
	return result.Running(), result.IPCPath, nil
}
