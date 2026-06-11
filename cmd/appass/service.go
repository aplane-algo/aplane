// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"bufio"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
)

const defaultServiceFile = "/etc/systemd/system/apsigner.service"

// serviceFilePath is written by the async status load and read by action
// commands; both run in bubbletea command goroutines, so access goes through
// the mutex-guarded accessors below.
var serviceFileMu sync.Mutex
var serviceFilePath = defaultServiceFile

func currentServiceFile() string {
	serviceFileMu.Lock()
	defer serviceFileMu.Unlock()
	return serviceFilePath
}

func setServiceFile(path string) {
	serviceFileMu.Lock()
	defer serviceFileMu.Unlock()
	serviceFilePath = path
}

var serviceFileCandidates = []string{
	defaultServiceFile,
	"/lib/systemd/system/apsigner.service",
	"/usr/lib/systemd/system/apsigner.service",
}

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
	defer func() { _ = f.Close() }()

	info := &serviceInfo{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		switch {
		case strings.HasPrefix(line, "ExecStart="):
			// ExecStart=/usr/local/bin/apsigner ... → extract directory
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

// resolveServiceInfo tries to parse the systemd service file.
// If that fails, it falls back to local mode using the current process info.
// The boolean return value is true when running in local mode.
func resolveServiceInfo() (*serviceInfo, bool) {
	for _, path := range candidateServiceFiles() {
		svc, err := parseServiceFile(path)
		if err == nil {
			setServiceFile(path)
			return svc, false
		}
	}
	return localServiceInfo(), true
}

func localServiceInfo() *serviceInfo {
	execPath, _ := os.Executable()
	return &serviceInfo{
		BinDir: filepath.Dir(execPath),
		User:   currentUsername(),
		Group:  currentGroupname(),
	}
}

func candidateServiceFiles() []string {
	if path := currentServiceFile(); path != defaultServiceFile {
		return []string{path}
	}
	return serviceFileCandidates
}

func currentUsername() string {
	u, err := user.Current()
	if err != nil {
		return "unknown"
	}
	return u.Username
}

func currentGroupname() string {
	u, err := user.Current()
	if err != nil {
		return "unknown"
	}
	g, err := user.LookupGroupId(u.Gid)
	if err != nil {
		return u.Gid
	}
	return g.Name
}
