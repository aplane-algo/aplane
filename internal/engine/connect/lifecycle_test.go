// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package connect

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/internal/sshtunnel"
)

func TestConnectWithTunnelReturnsConnectedWhenAlreadyConnectedToTarget(t *testing.T) {
	state := NewState()
	state.SignerClient = signerclient.NewSignerClientWithToken("http://localhost:1", "token")
	state.ConnectionTarget = "remote-a"

	result, err := state.ConnectWithTunnel("remote-a", "host", 22, 12345, 8080, "token", "", "", nil, nil, nil)
	if err != nil {
		t.Fatalf("ConnectWithTunnel() error = %v", err)
	}
	if !result.Connected || result.Target != "remote-a" {
		t.Fatalf("result = %+v, want connected remote-a", result)
	}
}

func TestConnectWithTunnelRejectsConcurrentStates(t *testing.T) {
	t.Run("same target already in progress", func(t *testing.T) {
		state := NewState()
		state.connectingTarget = "remote-a"

		_, err := state.ConnectWithTunnel("remote-a", "host", 22, 12345, 8080, "token", "", "", nil, nil, nil)
		if err == nil || !strings.Contains(err.Error(), "connection to remote-a already in progress") {
			t.Fatalf("error = %v, want same-target in-progress error", err)
		}
	})

	t.Run("different target already in progress", func(t *testing.T) {
		state := NewState()
		state.connectingTarget = "remote-a"

		_, err := state.ConnectWithTunnel("remote-b", "host", 22, 12345, 8080, "token", "", "", nil, nil, nil)
		if err == nil || !strings.Contains(err.Error(), "already connecting to remote-a") {
			t.Fatalf("error = %v, want different-target in-progress error", err)
		}
	})

	t.Run("already connected to different target", func(t *testing.T) {
		state := NewState()
		state.SignerClient = signerclient.NewSignerClientWithToken("http://localhost:1", "token")
		state.ConnectionTarget = "remote-a"

		_, err := state.ConnectWithTunnel("remote-b", "host", 22, 12345, 8080, "token", "", "", nil, nil, nil)
		if err == nil || !strings.Contains(err.Error(), "already connected to remote-a") {
			t.Fatalf("error = %v, want already-connected error", err)
		}
	})
}

func TestConnectWithTunnelRejectsMissingToken(t *testing.T) {
	state := NewState()

	result, err := state.ConnectWithTunnel("remote-a", "host", 22, 12345, 8080, "", "", "", nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "no API token configured") {
		t.Fatalf("error = %v, want no token configured", err)
	}
	if result == nil || result.ErrorMessage != "no API token configured" || result.Target != "remote-a" {
		t.Fatalf("result = %+v, want target and error message populated", result)
	}
	if state.connectingTarget != "" {
		t.Fatalf("connectingTarget = %q, want cleared", state.connectingTarget)
	}
}

func TestConnectWithTunnelRejectsPortAlreadyInUse(t *testing.T) {
	state := NewState()
	state.portDialTimeout = func(network, address string, timeout time.Duration) (net.Conn, error) {
		if network != "tcp" {
			t.Fatalf("network = %q, want tcp", network)
		}
		if address != "localhost:14001" {
			t.Fatalf("address = %q, want localhost:14001", address)
		}
		return stubConn{}, nil
	}
	result, err := state.ConnectWithTunnel("remote-a", "host", 22, 14001, 8080, "token", "", "", nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "already in use locally") {
		t.Fatalf("error = %v, want port in use", err)
	}
	if result == nil || result.Target != "remote-a" {
		t.Fatalf("result = %+v, want target remote-a", result)
	}
	if state.connectingTarget != "" {
		t.Fatalf("connectingTarget = %q, want cleared", state.connectingTarget)
	}
}

type stubConn struct{}

func (stubConn) Read([]byte) (int, error)         { return 0, errors.New("unused") }
func (stubConn) Write([]byte) (int, error)        { return 0, errors.New("unused") }
func (stubConn) Close() error                     { return nil }
func (stubConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (stubConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (stubConn) SetDeadline(time.Time) error      { return nil }
func (stubConn) SetReadDeadline(time.Time) error  { return nil }
func (stubConn) SetWriteDeadline(time.Time) error { return nil }

func TestDisconnectClearsStateAndInvokesCallback(t *testing.T) {
	state := NewState()
	state.SignerClient = signerclient.NewSignerClientWithToken("http://localhost:1", "token")
	state.SSHTunnelClient = sshtunnel.NewClient("host", 22, 10001, 8080, "", "")
	state.TunnelConnected = true
	cancelled := false
	state.TunnelCancel = func() { cancelled = true }
	state.ConnectionTarget = "remote-a"
	state.connectingTarget = "remote-b"

	callbackCalled := false
	if err := state.Disconnect(func() { callbackCalled = true }); err != nil {
		t.Fatalf("Disconnect() error = %v", err)
	}

	if !cancelled {
		t.Fatal("TunnelCancel was not called")
	}
	if !callbackCalled {
		t.Fatal("disconnect callback was not called")
	}
	if state.SignerClient != nil || state.SSHTunnelClient != nil || state.TunnelConnected || state.ConnectionTarget != "" || state.connectingTarget != "" {
		t.Fatalf("state was not fully cleared: %+v", state)
	}
	if state.TunnelCtx != nil || state.TunnelCancel != nil {
		t.Fatal("tunnel context/cancel should be cleared")
	}
}

func TestDisconnectReturnsNilWhenAlreadyDisconnected(t *testing.T) {
	state := NewState()
	callbackCalled := false
	if err := state.Disconnect(func() { callbackCalled = true }); err != nil {
		t.Fatalf("Disconnect() error = %v", err)
	}
	if callbackCalled {
		t.Fatal("callback should not be called when already disconnected")
	}
}

func TestClearLockedResetsConnectionState(t *testing.T) {
	state := NewState()
	state.SignerClient = signerclient.NewSignerClientWithToken("http://localhost:1", "token")
	state.SSHTunnelClient = sshtunnel.NewClient("host", 22, 10001, 8080, "", "")
	state.TunnelConnected = true
	state.ConnectionTarget = "remote-a"
	state.connectingTarget = "remote-b"

	state.clearLocked()

	if state.SignerClient != nil || state.SSHTunnelClient != nil || state.TunnelConnected || state.ConnectionTarget != "" || state.connectingTarget != "" {
		t.Fatalf("state was not fully cleared: %+v", state)
	}
}

var _ = errors.New
