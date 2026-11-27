// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package connect

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	util "github.com/aplane-algo/aplane/internal/signerclient"
)

func TestBeginConnectRejectsConcurrentAttempt(t *testing.T) {
	state := NewState()

	alreadyConnected, currentTarget, inProgress := state.beginConnect("alpha")
	if alreadyConnected || currentTarget != "" || inProgress {
		t.Fatalf("first beginConnect() = (%v, %q, %v), want (false, \"\", false)", alreadyConnected, currentTarget, inProgress)
	}

	alreadyConnected, currentTarget, inProgress = state.beginConnect("beta")
	if alreadyConnected || currentTarget != "alpha" || !inProgress {
		t.Fatalf("second beginConnect() = (%v, %q, %v), want (false, \"alpha\", true)", alreadyConnected, currentTarget, inProgress)
	}
}

func TestSnapshotReportsConnectionAndTarget(t *testing.T) {
	state := NewState()
	if connected, target := state.Snapshot(); connected || target != "" {
		t.Fatalf("Snapshot() = (%v, %q), want (false, \"\")", connected, target)
	}
	state.SignerClient = util.NewSignerClient("http://localhost:1")
	state.ConnectionTarget = "remote"
	if connected, target := state.Snapshot(); !connected || target != "remote" {
		t.Fatalf("Snapshot() = (%v, %q), want (true, \"remote\")", connected, target)
	}
}

func TestDisconnectInvokesCallbackOutsideLock(t *testing.T) {
	state := NewState()
	state.SignerClient = util.NewSignerClient("http://localhost:1")
	state.ConnectionTarget = "remote"

	done := make(chan struct{})
	state.Disconnect(func() {
		_ = state.GetConnectionTarget()
		close(done)
	})

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Disconnect() callback appears to be blocked by the connection mutex")
	}
}

func TestBindSignerClientContextConcurrentClearIsRaceSafe(t *testing.T) {
	state := NewState()
	client := util.NewSignerClient("http://localhost:1")
	state.SignerClient = client
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				cleanup := state.BindSignerClientContext(ctx)
				cleanup()
			}
		}()
	}
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				state.Mu.Lock()
				state.clearLocked()
				state.SignerClient = client
				state.Mu.Unlock()
			}
		}()
	}
	wg.Wait()
}

func TestSetProgressOutputUpdatesStateAndActiveClient(t *testing.T) {
	state := NewState()
	var buf bytes.Buffer
	state.SetProgressOutput(&buf)
	if state.ProgressOutput() != &buf {
		t.Fatal("ProgressOutput() did not return configured writer")
	}

	client := util.NewSignerClient("http://localhost:1")
	state.SignerClient = client
	var second bytes.Buffer
	state.SetProgressOutput(&second)
	if client.ProgressOut != &second {
		t.Fatal("SetProgressOutput did not update active SignerClient.ProgressOut")
	}
}
