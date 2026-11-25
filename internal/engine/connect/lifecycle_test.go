// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package connect

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/internal/sshtunnel"
	"github.com/aplane-algo/aplane/internal/sshtunnel/sshtest"
	"github.com/aplane-algo/aplane/pkg/signerapi"
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
	if state.SignerClient != nil || state.SSHTunnelClient != nil || state.ConnectionTarget != "" || state.connectingTarget != "" {
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
	state.ConnectionTarget = "remote-a"
	state.connectingTarget = "remote-b"

	state.clearLocked()

	if state.SignerClient != nil || state.SSHTunnelClient != nil || state.ConnectionTarget != "" || state.connectingTarget != "" {
		t.Fatalf("state was not fully cleared: %+v", state)
	}
}

type logMatchHandler struct {
	want    string
	matched chan struct{}
}

func (h *logMatchHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *logMatchHandler) Handle(_ context.Context, r slog.Record) error {
	if strings.Contains(r.Message, h.want) {
		select {
		case h.matched <- struct{}{}:
		default:
		}
	}
	return nil
}
func (h *logMatchHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *logMatchHandler) WithGroup(string) slog.Handler      { return h }

func TestConnectWithTunnelRefusesDeadTunnelDroppedBeforePublish(t *testing.T) {
	tests := []struct {
		name      string
		drop      func(node *sshtest.Node)
		logNeedle string
		wantErr   string
	}{
		{
			name: "revoked during onKeys",
			drop: func(node *sshtest.Node) {
				node.Server.CloseConnectionsForFingerprint(node.Fingerprint, sshtunnel.DisconnectReasonKeyRevoked)
			},
			logNeedle: "revoked by the signer",
			wantErr:   "client key was revoked by the signer",
		},
		{
			name: "server closed during onKeys",
			drop: func(node *sshtest.Node) {
				_ = node.Server.Stop()
			},
			logNeedle: "connection closed by remote server",
			wantErr:   "connection closed before setup completed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched := make(chan struct{}, 1)
			prev := slog.Default()
			slog.SetDefault(slog.New(&logMatchHandler{want: tt.logNeedle, matched: matched}))
			t.Cleanup(func() { slog.SetDefault(prev) })

			node := sshtest.Serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(signerapi.KeysResponse{Keys: []signerapi.KeyInfo{{Address: "A"}}})
			}))

			state := NewState()
			var disconnectCalls atomic.Int32
			res, err := state.ConnectWithTunnel(
				context.Background(),
				"node",
				node.Host,
				node.Port,
				node.IdentityFile,
				node.KnownHostsPath,
				nil,
				func([]signerapi.KeyInfo) error {
					tt.drop(node)
					select {
					case <-matched:
					case <-time.After(3 * time.Second):
						t.Fatal("timed out waiting for SSH client disconnect before publish")
					}
					return nil
				},
				func() { disconnectCalls.Add(1) },
			)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("ConnectWithTunnel() = (%+v, %v), want error containing %q", res, err, tt.wantErr)
			}
			if state.IsConnected() || state.SSHTunnelClient != nil || state.SignerClient != nil || state.ConnectionTarget != "" || state.connectingTarget != "" {
				t.Fatalf("ConnectWithTunnel installed a dead tunnel: connected=%v target=%q connecting=%q client=%v",
					state.IsConnected(), state.ConnectionTarget, state.connectingTarget, state.SSHTunnelClient)
			}
			if disconnectCalls.Load() != 0 {
				t.Fatalf("onDisconnect called %d times for a failed connect, want 0", disconnectCalls.Load())
			}
		})
	}
}

// A drop after the connection is published clears the state and tells the
// caller, once.
func TestConnectWithTunnelDropAfterPublishClearsStateAndNotifiesOnce(t *testing.T) {
	node := sshtest.Serve(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(signerapi.KeysResponse{Keys: []signerapi.KeyInfo{{Address: "A"}}})
	}))
	state := NewState()
	dropped := make(chan struct{}, 2)
	if _, err := state.ConnectWithTunnel(
		context.Background(), "node", node.Host, node.Port, node.IdentityFile, node.KnownHostsPath,
		nil, nil, func() { dropped <- struct{}{} },
	); err != nil {
		t.Fatalf("ConnectWithTunnel() error = %v", err)
	}
	if !state.IsConnected() {
		t.Fatal("not connected after ConnectWithTunnel")
	}

	node.Server.CloseConnectionsForFingerprint(node.Fingerprint, sshtunnel.DisconnectReasonKeyRevoked)
	select {
	case <-dropped:
	case <-time.After(3 * time.Second):
		t.Fatal("onDisconnect was not called for a dropped connection")
	}
	state.Mu.Lock()
	if state.SSHTunnelClient != nil || state.SignerClient != nil || state.ConnectionTarget != "" || state.TunnelCancel != nil {
		t.Errorf("a dropped connection was left installed: %+v", state)
	}
	state.Mu.Unlock()
	select {
	case <-dropped:
		t.Fatal("onDisconnect was called twice for one drop")
	case <-time.After(100 * time.Millisecond):
	}
}
