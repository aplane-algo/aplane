// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"

	engconnect "github.com/aplane-algo/aplane/internal/engine/connect"
	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/internal/sshtunnel"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

func TestEngineConnectWithTunnelMapsAlreadyConnectedError(t *testing.T) {
	eng := NewEngine("testnet")
	eng.Connection.SignerClient = signerclient.NewSignerClient("http://localhost:1")
	eng.Connection.ConnectionTarget = "remote-a"

	result, err := eng.ConnectWithTunnel(context.Background(), "remote-b", "host", 22, "", "", nil, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrAlreadyConnected) {
		t.Fatalf("error = %v, want ErrAlreadyConnected", err)
	}
	if !strings.Contains(err.Error(), "remote-a") {
		t.Fatalf("error = %q, want remote-a in error", err.Error())
	}
	if result != nil {
		t.Fatalf("result = %+v, want nil on ErrAlreadyConnected path", result)
	}
}

func TestHandleConnectionClosedResetsSignerCacheAndInvokesCallback(t *testing.T) {
	eng := NewEngine("testnet")
	if err := eng.PopulateSignerCache([]signerapi.KeyInfo{
		{Address: testAddr(1), KeyType: "ed25519", AuthorizationKind: "ed25519"},
	}); err != nil {
		t.Fatalf("PopulateSignerCache() error = %v", err)
	}
	called := false
	eng.handleConnectionClosed(func() { called = true })()

	if eng.SignerCacheCount() != 0 {
		t.Fatalf("SignerCacheCount() = %d, want 0", eng.SignerCacheCount())
	}
	if !called {
		t.Fatal("disconnect callback was not called")
	}
}

func TestEngineDisconnectDelegatesToConnectionState(t *testing.T) {
	eng := NewEngine("testnet")
	eng.Connection = engconnect.NewState()
	eng.Connection.SignerClient = signerclient.NewSignerClient("http://localhost:1")
	eng.Connection.ConnectionTarget = "remote-a"
	if err := eng.PopulateSignerCache([]signerapi.KeyInfo{
		{Address: testAddr(1), KeyType: "ed25519", AuthorizationKind: "ed25519"},
	}); err != nil {
		t.Fatalf("PopulateSignerCache() error = %v", err)
	}

	eng.Disconnect()
	if eng.Connection.IsConnected() {
		t.Fatal("engine should be disconnected")
	}
	if eng.SignerCacheCount() != 0 {
		t.Fatal("signer cache should be reset by disconnect callback")
	}
}

// An enrollment request is answered "pending" and nothing reconnects, so it
// must leave a live tunnel and the signer cache alone.
func TestEngineRequestEnrollmentLeavesTunnelConnected(t *testing.T) {
	eng := NewEngine("testnet")
	eng.Connection = engconnect.NewState()
	eng.Connection.SignerClient = signerclient.NewSignerClient("http://localhost:1")
	eng.Connection.SSHTunnelClient = sshtunnel.NewClient("host", 22, "", "")
	eng.Connection.ConnectionTarget = "remote-a"
	if err := eng.PopulateSignerCache([]signerapi.KeyInfo{
		{Address: testAddr(1), KeyType: "ed25519", AuthorizationKind: "ed25519"},
	}); err != nil {
		t.Fatalf("PopulateSignerCache() error = %v", err)
	}

	dir := t.TempDir()
	_, err := eng.RequestEnrollmentWithContext(context.Background(), "127.0.0.1", 1, dir+"/id_ed25519", dir+"/known_hosts", "", nil, nil)
	if err == nil {
		t.Fatal("expected enrollment request error, got nil")
	}
	if !eng.Connection.IsConnected() || eng.GetConnectionTarget() != "remote-a" {
		t.Fatal("an enrollment request must not disconnect the live tunnel")
	}
	if eng.SignerCacheCount() != 1 {
		t.Fatal("an enrollment request must not reset the signer cache")
	}
}

func TestHandleConnectionClosedWithoutCallbackStillResetsCache(t *testing.T) {
	eng := NewEngine("testnet")
	if err := eng.PopulateSignerCache([]signerapi.KeyInfo{
		{Address: testAddr(2), KeyType: "ed25519", AuthorizationKind: "ed25519"},
	}); err != nil {
		t.Fatalf("PopulateSignerCache() error = %v", err)
	}

	eng.handleConnectionClosed(nil)()

	if eng.SignerCacheCount() != 0 {
		t.Fatalf("SignerCacheCount() = %d, want 0", eng.SignerCacheCount())
	}
}

func TestSignerCacheConcurrentRefreshAndReadIsRaceSafe(t *testing.T) {
	eng := NewEngine("testnet")
	addr := testAddr(41)
	keys := []signerapi.KeyInfo{{Address: addr, KeyType: "ed25519"}}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if j%2 == 0 {
					_ = eng.PopulateSignerCache(keys)
				} else {
					eng.ResetSignerCache(false)
				}
			}
		}()
	}
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_ = eng.SignerKeyCount()
				_, _ = eng.CanSignForAddressWithKind(addr)
				_ = eng.GetStatus()
				_, _ = eng.ListAllAddresses()
				_ = eng.IsAccountSignable(addr)
				_ = eng.SignerCacheAlgorithm(addr)
			}
		}()
	}
	wg.Wait()
}

func TestEnsureSignerCacheWithContextPropagatesCancellation(t *testing.T) {
	eng := NewEngine("testnet")
	client := signerclient.NewSignerClient("http://signer.test")
	client.Client = &http.Client{Transport: keyMgmtRoundTripper{t: t, handler: func(req *http.Request) (*http.Response, error) {
		<-req.Context().Done()
		return nil, req.Context().Err()
	}}}
	eng.Connection.SignerClient = client

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := eng.EnsureSignerCache(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("EnsureSignerCache() error = %v, want context.Canceled", err)
	}
}
