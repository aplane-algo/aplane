// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package signerprobe provides installer-facing signer liveness checks.
package signerprobe

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

const DefaultTimeout = 300 * time.Millisecond

type State string

const (
	StateRunning State = "running"
	StateStopped State = "stopped"
)

type Result struct {
	State   State
	IPCPath string
}

func (r Result) Running() bool {
	return r.State == StateRunning
}

type Options struct {
	Timeout time.Duration
	Dial    func(socketPath string, timeout time.Duration) (net.Conn, error)
}

func Check(dataDir string, opts Options) (Result, error) {
	ipcPath, err := ResolveIPCPath(dataDir)
	if err != nil {
		return Result{}, err
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	dial := opts.Dial
	if dial == nil {
		dial = func(socketPath string, timeout time.Duration) (net.Conn, error) {
			return net.DialTimeout("unix", socketPath, timeout)
		}
	}

	conn, err := dial(ipcPath, timeout)
	if err == nil {
		_ = conn.Close()
		return Result{State: StateRunning, IPCPath: ipcPath}, nil
	}
	if errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ECONNREFUSED) {
		return Result{State: StateStopped, IPCPath: ipcPath}, nil
	}
	return Result{IPCPath: ipcPath}, fmt.Errorf("dial signer IPC: %w", err)
}

func ResolveIPCPath(dataDir string) (string, error) {
	if dataDir == "" {
		return "", errors.New("signer data directory is required")
	}

	configPath := filepath.Join(dataDir, "config.yaml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return filepath.Join(dataDir, "aplane.sock"), nil
		}
		return "", fmt.Errorf("read signer config %s: %w", configPath, err)
	}

	var cfg struct {
		IPCPath string `yaml:"ipc_path"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return "", fmt.Errorf("parse signer config %s: %w", configPath, err)
	}
	if cfg.IPCPath == "" {
		return filepath.Join(dataDir, "aplane.sock"), nil
	}
	return cfg.IPCPath, nil
}
