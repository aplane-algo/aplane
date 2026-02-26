// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const defaultServiceFile = "/lib/systemd/system/aplane.service"

type serviceInfo struct {
	BinDir      string
	User        string
	Group       string
	HasLoadCred bool
}

// parseServiceFile extracts configuration from the installed systemd service file.
func parseServiceFile(path string) (*serviceInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("could not open service file %s: %w", path, err)
	}
	defer f.Close()

	info := &serviceInfo{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		switch {
		case strings.HasPrefix(line, "ExecStart="):
			// ExecStart=/usr/local/bin/apsignerd ... → extract directory
			execPath := strings.TrimPrefix(line, "ExecStart=")
			// Strip arguments (space-separated)
			if idx := strings.IndexByte(execPath, ' '); idx != -1 {
				execPath = execPath[:idx]
			}
			info.BinDir = filepath.Dir(execPath)

		case strings.HasPrefix(line, "User="):
			info.User = strings.TrimPrefix(line, "User=")

		case strings.HasPrefix(line, "Group="):
			info.Group = strings.TrimPrefix(line, "Group=")

		case strings.HasPrefix(line, "LoadCredentialEncrypted"):
			info.HasLoadCred = true
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading service file: %w", err)
	}

	if info.BinDir == "" {
		return nil, fmt.Errorf("could not extract binary directory from %s (no ExecStart= line)", path)
	}
	if info.User == "" {
		return nil, fmt.Errorf("could not extract User= from %s", path)
	}
	if info.Group == "" {
		return nil, fmt.Errorf("could not extract Group= from %s", path)
	}

	return info, nil
}
