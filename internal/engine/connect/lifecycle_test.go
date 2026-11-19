// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package connect

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/internal/sshtunnel"
)

func TestConnectWithTunnelReportsAlreadyConnectedToTarget(t *testing.T) {
	state := NewState()
	state.SignerClient = signerclient.NewSignerClient("http://localhost:1")
	state.ConnectionTarget = "remote-a"

	result, err := state.ConnectWithTunnel(context.Background(), "remote-a", "host", 22, "", "", nil, nil, nil)
	if err != nil {
		t.Fatalf("ConnectWithTunnel() error = %v", err)
	}
	if !result.AlreadyConnected || result.Target != "remote-a" {
		t.Fatalf("result = %+v, want already connected to remote-a", result)
	}
}

func TestConnectWithTunnelRejectsConcurrentStates(t *testing.T) {
	t.Run("same target already in progress", func(t *testing.T) {
		state := NewState()
		state.connectingTarget = "remote-a"

		_, err := state.ConnectWithTunnel(context.Background(), "remote-a", "host", 22, "", "", nil, nil, nil)
		if err == nil || !strings.Contains(err.Error(), "connection to remote-a already in progress") {
			t.Fatalf("error = %v, want same-target in-progress error", err)
		}
	})

	t.Run("different target already in progress", func(t *testing.T) {
		state := NewState()
		state.connectingTarget = "remote-a"

		_, err := state.ConnectWithTunnel(context.Background(), "remote-b", "host", 22, "", "", nil, nil, nil)
		if err == nil || !strings.Contains(err.Error(), "already connecting to remote-a") {
			t.Fatalf("error = %v, want different-target in-progress error", err)
		}
	})

	t.Run("already connected to different target", func(t *testing.T) {
		state := NewState()
		state.SignerClient = signerclient.NewSignerClient("http://localhost:1")
		state.ConnectionTarget = "remote-a"

		_, err := state.ConnectWithTunnel(context.Background(), "remote-b", "host", 22, "", "", nil, nil, nil)
		if err == nil || !strings.Contains(err.Error(), "already connected to remote-a") {
			t.Fatalf("error = %v, want already-connected error", err)
		}
	})
}

func TestDisconnectClearsStateAndInvokesCallback(t *testing.T) {
	state := NewState()
	state.SignerClient = signerclient.NewSignerClient("http://localhost:1")
	state.SSHTunnelClient = sshtunnel.NewClient("host", 22, "", "")
	state.TunnelConnected = true
	cancelled := false
	state.TunnelCancel = func() { cancelled = true }
	state.ConnectionTarget = "remote-a"
	state.connectingTarget = "remote-b"

	callbackCalled := false
	state.Disconnect(func() { callbackCalled = true })

	if !cancelled {
		t.Fatal("TunnelCancel was not called")
	}
	if !callbackCalled {
		t.Fatal("disconnect callback was not called")
	}
	if state.SignerClient != nil || state.SSHTunnelClient != nil || state.TunnelConnected || state.ConnectionTarget != "" || state.connectingTarget != "" {
		t.Fatalf("state was not fully cleared: %+v", state)
	}
	if state.TunnelCancel != nil {
		t.Fatal("tunnel cancel should be cleared")
	}
}

func TestDisconnectIsANoOpWhenAlreadyDisconnected(t *testing.T) {
	state := NewState()
	callbackCalled := false
	state.Disconnect(func() { callbackCalled = true })
	if callbackCalled {
		t.Fatal("callback should not be called when already disconnected")
	}
}

func TestClearLockedResetsConnectionState(t *testing.T) {
	state := NewState()
	state.SignerClient = signerclient.NewSignerClient("http://localhost:1")
	state.SSHTunnelClient = sshtunnel.NewClient("host", 22, "", "")
	state.TunnelConnected = true
	state.ConnectionTarget = "remote-a"
	state.connectingTarget = "remote-b"

	state.clearLocked()

	if state.SignerClient != nil || state.SSHTunnelClient != nil || state.TunnelConnected || state.ConnectionTarget != "" || state.connectingTarget != "" {
		t.Fatalf("state was not fully cleared: %+v", state)
	}
}

var _ = errors.New
