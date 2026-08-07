// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

//go:build storetest

package testcheckpoint

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	checkpointNameEnv = "APLANE_STORE_TEST_CHECKPOINT"
	checkpointDirEnv  = "APLANE_STORE_TEST_CHECKPOINT_DIR"
	checkpointModeEnv = "APLANE_STORE_TEST_CHECKPOINT_MODE"
)

// Reach announces a semantic store-lifecycle boundary to the external test
// harness. In block mode it waits to be killed or released; in error mode it
// returns a deterministic failure. This implementation is unavailable to
// production builds.
func Reach(name string) error {
	if strings.TrimSpace(os.Getenv(checkpointNameEnv)) != name {
		return nil
	}
	dir := strings.TrimSpace(os.Getenv(checkpointDirEnv))
	if dir == "" {
		return fmt.Errorf("%s requires %s", checkpointNameEnv, checkpointDirEnv)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create store-test checkpoint directory: %w", err)
	}
	reached := filepath.Join(dir, "reached")
	if err := os.WriteFile(reached, []byte(name+"\n"), 0o600); err != nil {
		return fmt.Errorf("publish store-test checkpoint: %w", err)
	}

	switch strings.TrimSpace(os.Getenv(checkpointModeEnv)) {
	case "error":
		return errors.New("injected store-test checkpoint failure: " + name)
	case "", "block":
		release := filepath.Join(dir, "release")
		for {
			if _, err := os.Stat(release); err == nil {
				return nil
			} else if !os.IsNotExist(err) {
				return fmt.Errorf("inspect store-test checkpoint release: %w", err)
			}
			time.Sleep(10 * time.Millisecond)
		}
	default:
		return fmt.Errorf("invalid %s value", checkpointModeEnv)
	}
}
