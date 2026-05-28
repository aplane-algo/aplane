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

func TestSetSignerProgressWriterPersistsAcrossClients(t *testing.T) {
	var progress bytes.Buffer

	state := NewState()
	state.SetSignerProgressWriter(&progress)

	first := util.NewSignerClientWithToken("http://localhost:1", "token")
	state.SignerClient = first
	state.SetSignerProgressWriter(&progress)

	if first.ProgressOut != &progress {
		t.Fatal("first signer client did not receive progress writer")
	}

	second := util.NewSignerClientWithToken("http://localhost:2", "token")
	state.SignerClient = second

	client, err := state.signerClient()
	if err != nil {
		t.Fatalf("signerClient() error = %v", err)
	}
	if client.ProgressOut != &progress {
		t.Fatal("replacement signer client did not inherit progress writer")
	}
}

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

func TestDisconnectInvokesCallbackOutsideLock(t *testing.T) {
	state := NewState()
	state.SignerClient = util.NewSignerClientWithToken("http://localhost:1", "token")
	state.ConnectionTarget = "remote"

	done := make(chan struct{})
	if err := state.Disconnect(func() {
		_ = state.GetConnectionTarget()
		close(done)
	}); err != nil {
		t.Fatalf("Disconnect() error = %v", err)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Disconnect() callback appears to be blocked by the connection mutex")
	}
}

func TestBindSignerClientContextConcurrentClearIsRaceSafe(t *testing.T) {
	state := NewState()
	client := util.NewSignerClientWithToken("http://localhost:1", "token")
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
