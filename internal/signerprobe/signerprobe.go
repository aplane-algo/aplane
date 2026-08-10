// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package signerprobe provides installer-facing signer liveness checks.
package signerprobe

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/aplane-algo/aplane/internal/adminipc"
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
	Timeout         time.Duration
	Dial            func(socketPath string, timeout time.Duration) (net.Conn, error)
	IPCPath         string
	DataDirExplicit bool
}

func Check(dataDir string, opts Options) (Result, error) {
	ipcPath, err := adminipc.ResolveClientPath(adminipc.ClientPathRequest{
		DataDir: dataDir, IPCPath: opts.IPCPath, DataDirExplicit: opts.DataDirExplicit,
	})
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
	return adminipc.ResolveClientPath(adminipc.ClientPathRequest{DataDir: dataDir})
}
