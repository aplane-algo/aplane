// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keyadmin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"

	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/serverconfig"
)

// hungAlgod is an algod that accepts every request and never answers it
// until the test ends.
func hungAlgod(t *testing.T) *httptest.Server {
	t.Helper()
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	// Cleanups run last first: the handlers return before Close waits for them.
	t.Cleanup(server.Close)
	t.Cleanup(func() { close(release) })
	return server
}

// Key generation compiles a LogicSig key type's TEAL on algod while it holds
// the store mutation lock, which admin mutations, watcher reloads and the
// unlock reconcile also take. A hung algod must not hold the lock for longer
// than the compile's bound.
func TestGenerationWithAHungAlgodReleasesTheMutationLock(t *testing.T) {
	setTEALCompileTimeout(t, 200*time.Millisecond)
	server := hungAlgod(t)

	for _, tc := range []struct {
		name    string
		keyType string
		params  map[string]string
		setup   func(t *testing.T, svc *Service)
	}{
		{
			name:    "DSA LogicSig",
			keyType: "aplane.falcon1024.v1",
			setup: func(t *testing.T, _ *Service) {
				client, err := algod.MakeClient(server.URL, "")
				if err != nil {
					t.Fatal(err)
				}
				lsigprovider.ConfigureAlgodClient(client)
				t.Cleanup(func() { lsigprovider.ConfigureAlgodClient(nil) })
			},
		},
		{
			name:    "generic LogicSig",
			keyType: serviceGenericKeyType,
			params:  map[string]string{"owner": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"},
			setup: func(t *testing.T, svc *Service) {
				registerServiceGenericTemplate(t)
				installServiceGenericTemplate(t, svc.Runtime)
				generator := GenericLSigGenerator{Config: &serverconfig.ServerConfig{
					TEALCompileNetwork: "testnet",
					Algod:              apconfig.AlgodConfig{"testnet": {Server: server.URL}},
				}}
				svc.GenerateGenericLSig = func(ctx context.Context, keyType string, params map[string]string) (string, error) {
					return generator.GenerateContext(ctx, svc.Runtime, keyType, params)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lock := &sync.Mutex{}
			svc := Service{Runtime: setupProductRuntime(t), MutationLock: lock}
			tc.setup(t, &svc)

			done := make(chan *Error, 1)
			go func() {
				_, err := svc.GenerateKey(context.Background(), tc.keyType, tc.params)
				done <- err
			}()
			var err *Error
			select {
			case err = <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("GenerateKey() still holds the mutation lock behind a hung algod")
			}
			const want = "key generation failed: algod did not answer the TEAL compile within 200ms"
			if err == nil || err.Kind != ErrorInternal || err.Message != want {
				t.Fatalf("GenerateKey() error = %#v, want %q", err, want)
			}
			if !lock.TryLock() {
				t.Fatal("the mutation lock is still held after GenerateKey() returned")
			}
			lock.Unlock()
			assertNoKeys(t, svc)
		})
	}
}

func setTEALCompileTimeout(t *testing.T, timeout time.Duration) {
	t.Helper()
	previous := tealCompileTimeout
	tealCompileTimeout = timeout
	t.Cleanup(func() { tealCompileTimeout = previous })
}
