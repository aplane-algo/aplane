// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"context"
	"errors"
	"testing"
	"time"
)

type sshStopperFunc func(context.Context) error

func (f sshStopperFunc) StopContext(ctx context.Context) error {
	return f(ctx)
}

func TestStopSSHRuntimePropagatesLifecycleContextAndDetachesRuntime(t *testing.T) {
	t.Parallel()

	sshCtx, cancelSSH := context.WithCancel(context.Background())
	stopCtx, cancelStop := context.WithTimeout(context.Background(), time.Second)
	defer cancelStop()
	wantErr := errors.New("stop result")
	called := false
	rt := &sshRuntime{
		ctx:    sshCtx,
		cancel: cancelSSH,
		stopper: sshStopperFunc(func(ctx context.Context) error {
			called = true
			if ctx != stopCtx {
				t.Fatal("SSH stopper received a different context from lifecycle shutdown")
			}
			select {
			case <-sshCtx.Done():
			default:
				t.Fatal("SSH runtime context was not canceled before StopContext")
			}
			return wantErr
		}),
	}
	signer := &Signer{sshRuntime: rt}

	if err := signer.stopSSHRuntime(stopCtx); !errors.Is(err, wantErr) {
		t.Fatalf("stopSSHRuntime() error = %v, want %v", err, wantErr)
	}
	if !called {
		t.Fatal("stopSSHRuntime() did not call the SSH StopContext seam")
	}
	if signer.sshRuntime != nil || signer.sshServer != nil {
		t.Fatal("stopSSHRuntime() left the stopped SSH runtime published")
	}
}
