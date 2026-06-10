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

	"github.com/aplane-algo/aplane/internal/cache"
	engconnect "github.com/aplane-algo/aplane/internal/engine/connect"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/internal/sshtunnel"
)

func TestEngineConnectWithTunnelMapsAlreadyConnectedError(t *testing.T) {
	eng, err := NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	eng.Connection.SignerClient = signerclient.NewSignerClientWithToken("http://localhost:1", "token")
	eng.Connection.ConnectionTarget = "remote-a"

	result, err := eng.ConnectWithTunnel("remote-b", "host", 22, 12345, 8080, "token", "", "", nil, nil)
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
	eng, err := NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	eng.SignerCache.AddAddress(testAddr(1), "ed25519")
	called := false
	eng.handleConnectionClosed(func() { called = true })()

	if eng.SignerCache.Count() != 0 {
		t.Fatalf("SignerCache.Count() = %d, want 0", eng.SignerCache.Count())
	}
	if !called {
		t.Fatal("disconnect callback was not called")
	}
}

func TestEngineDisconnectDelegatesToConnectionState(t *testing.T) {
	eng, err := NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	eng.Connection = engconnect.NewState()
	eng.Connection.SignerClient = signerclient.NewSignerClientWithToken("http://localhost:1", "token")
	eng.Connection.ConnectionTarget = "remote-a"
	eng.SignerCache = cache.NewSignerCache()
	eng.SignerCache.AddAddress(testAddr(1), "ed25519")

	if err := eng.Disconnect(); err != nil {
		t.Fatalf("Disconnect() error = %v", err)
	}
	if eng.Connection.IsConnected() {
		t.Fatal("engine should be disconnected")
	}
	if eng.SignerCache.Count() != 0 {
		t.Fatal("signer cache should be reset by disconnect callback")
	}
}

func TestEngineRequestTokenDisconnectsFirst(t *testing.T) {
	eng, err := NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	eng.Connection = engconnect.NewState()
	eng.Connection.SignerClient = signerclient.NewSignerClientWithToken("http://localhost:1", "token")
	eng.Connection.SSHTunnelClient = sshtunnel.NewClient("host", 22, 10001, 8080, "", "")
	eng.Connection.TunnelConnected = true
	eng.Connection.ConnectionTarget = "remote-a"
	eng.SignerCache.AddAddress(testAddr(1), "ed25519")

	_, err = eng.RequestTokenWithContext(context.Background(), "127.0.0.1", 1, "", "", nil, nil)
	if err == nil {
		t.Fatal("expected token request error, got nil")
	}
	if eng.Connection.IsConnected() {
		t.Fatal("engine should be disconnected before requesting token")
	}
	if eng.IsTunnelConnected() {
		t.Fatal("tunnel should be disconnected before requesting token")
	}
	if eng.SignerCache.Count() != 0 {
		t.Fatal("signer cache should be reset by disconnect-before-request flow")
	}
}

func TestHandleConnectionClosedWithoutCallbackStillResetsCache(t *testing.T) {
	eng, err := NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	eng.SignerCache.AddAddress(testAddr(2), "ed25519")

	eng.handleConnectionClosed(nil)()

	if eng.SignerCache.Count() != 0 {
		t.Fatalf("SignerCache.Count() = %d, want 0", eng.SignerCache.Count())
	}
}

func TestSignerCacheConcurrentRefreshAndReadIsRaceSafe(t *testing.T) {
	eng, err := NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	addr := testAddr(41)
	keys := []signerapi.KeyInfo{{Address: addr, KeyType: "ed25519"}}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if j%2 == 0 {
					eng.populateSignerCache(keys)
				} else {
					eng.resetSignerCache(false)
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
				_, _ = eng.CanSignForAddress(addr)
				_ = eng.GetStatus()
				_, _ = eng.ListAllAddresses()
				_ = eng.isSignable(addr)
				_ = eng.getAlgorithm(addr)
			}
		}()
	}
	wg.Wait()
}

func TestEnsureSignerCacheWithContextPropagatesCancellation(t *testing.T) {
	eng, err := NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	client := signerclient.NewSignerClientWithToken("http://signer.test", "token")
	client.Client = &http.Client{Transport: keyMgmtRoundTripper{t: t, handler: func(req *http.Request) (*http.Response, error) {
		<-req.Context().Done()
		return nil, req.Context().Err()
	}}}
	eng.Connection.SignerClient = client

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = eng.EnsureSignerCache(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("EnsureSignerCache() error = %v, want context.Canceled", err)
	}
}
