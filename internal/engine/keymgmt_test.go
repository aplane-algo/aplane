// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/cache"
	engconnect "github.com/aplane-algo/aplane/internal/engine/connect"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signerclient"
)

type keyMgmtRoundTripper struct {
	t       *testing.T
	handler func(*http.Request) (*http.Response, error)
}

func (rt keyMgmtRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return rt.handler(req)
}

func TestEngineKeyMgmtRequiresConnection(t *testing.T) {
	eng, err := NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	if _, err := eng.ListKeyTypes(context.Background()); err != ErrNotConnected {
		t.Fatalf("ListKeyTypes() error = %v, want ErrNotConnected", err)
	}
	if _, err := eng.GenerateKey(context.Background(), "ed25519", nil); err != ErrNotConnected {
		t.Fatalf("GenerateKey() error = %v, want ErrNotConnected", err)
	}
	if err := eng.DeleteKey(context.Background(), "ADDR"); err != ErrNotConnected {
		t.Fatalf("DeleteKey() error = %v, want ErrNotConnected", err)
	}
}

func TestEngineListKeyTypesWrapsSignerResponse(t *testing.T) {
	eng := newConnectedEngineForKeyMgmtTest(t, func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodGet || req.URL.Path != "/keytypes" {
			t.Fatalf("unexpected request: %s %s", req.Method, req.URL.Path)
		}
		return keyMgmtJSONResponse(t, http.StatusOK, signerapi.KeyTypesResponse{
			KeyTypes: []signerapi.KeyTypeInfo{{KeyType: "ed25519", Family: "ed25519"}},
		}, req), nil
	})

	got, err := eng.ListKeyTypes(context.Background())
	if err != nil {
		t.Fatalf("ListKeyTypes() error = %v", err)
	}
	if len(got) != 1 || got[0].KeyType != "ed25519" {
		t.Fatalf("ListKeyTypes() = %#v, want one ed25519 key type", got)
	}
}

func TestEngineGenerateKeyRefreshesSignerCache(t *testing.T) {
	addr := testAddr(11)
	eng := newConnectedEngineForKeyMgmtTest(t, func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodPost && req.URL.Path == "/admin/generate":
			var body signerapi.AdminGenerateRequest
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
				t.Fatalf("Decode(generate request) error = %v", err)
			}
			if body.KeyType != "ed25519" {
				t.Fatalf("generate request key type = %q, want ed25519", body.KeyType)
			}
			if body.Parameters["label"] != "alice" {
				t.Fatalf("generate request parameters = %#v, want label=alice", body.Parameters)
			}
			return keyMgmtJSONResponse(t, http.StatusOK, signerapi.AdminGenerateResponse{
				Address: addr,
				KeyType: "ed25519",
			}, req), nil
		case req.Method == http.MethodGet && req.URL.Path == "/keys":
			return keyMgmtJSONResponse(t, http.StatusOK, signerapi.KeysResponse{
				Count: 1,
				Keys: []signerapi.KeyInfo{
					{Address: addr, KeyType: "ed25519", PublicKeyHex: "PUB"},
				},
			}, req), nil
		default:
			t.Fatalf("unexpected request: %s %s", req.Method, req.URL.Path)
			return nil, nil
		}
	})

	got, err := eng.GenerateKey(context.Background(), "ed25519", map[string]string{"label": "alice"})
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	if got.Address != addr || got.KeyType != "ed25519" {
		t.Fatalf("GenerateKey() = %#v, want address=%s keyType=ed25519", got, addr)
	}
	if eng.SignerCache.GetKeyType(addr) != "ed25519" {
		t.Fatalf("SignerCache key type = %q, want ed25519", eng.SignerCache.GetKeyType(addr))
	}
}

func TestEngineDeleteKeyRefreshesSignerCache(t *testing.T) {
	addr := testAddr(12)
	signerCache := cache.NewSignerCache()
	signerCache.AddAddress(addr, "ed25519")

	eng := newConnectedEngineForKeyMgmtTestWithSignerCache(t, signerCache, func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodDelete && req.URL.Path == "/admin/keys":
			if got := req.URL.Query().Get("address"); got != addr {
				t.Fatalf("delete request address = %q, want %q", got, addr)
			}
			return keyMgmtJSONResponse(t, http.StatusOK, signerapi.AdminDeleteResponse{Success: true}, req), nil
		case req.Method == http.MethodGet && req.URL.Path == "/keys":
			return keyMgmtJSONResponse(t, http.StatusOK, signerapi.KeysResponse{
				Count: 0,
				Keys:  []signerapi.KeyInfo{},
			}, req), nil
		default:
			t.Fatalf("unexpected request: %s %s", req.Method, req.URL.Path)
			return nil, nil
		}
	})

	if err := eng.DeleteKey(context.Background(), addr); err != nil {
		t.Fatalf("DeleteKey() error = %v", err)
	}
	if eng.SignerCache.Count() != 0 {
		t.Fatalf("SignerCache.Count() = %d, want 0 after refresh", eng.SignerCache.Count())
	}
}

func TestEngineGenerateKeyWrapsSignerErrors(t *testing.T) {
	eng := newConnectedEngineForKeyMgmtTest(t, func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodPost && req.URL.Path == "/admin/generate" {
			return keyMgmtTextResponse(http.StatusInternalServerError, "server blew up", req), nil
		}
		t.Fatalf("unexpected request: %s %s", req.Method, req.URL.Path)
		return nil, nil
	})

	_, err := eng.GenerateKey(context.Background(), "ed25519", nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to generate key: signer error (500): server blew up") {
		t.Fatalf("error = %q, want wrapped signer error", err.Error())
	}
}

func TestEngineGenerateKeyIgnoresRefreshFailure(t *testing.T) {
	addr := testAddr(21)
	eng := newConnectedEngineForKeyMgmtTest(t, func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodPost && req.URL.Path == "/admin/generate":
			return keyMgmtJSONResponse(t, http.StatusOK, signerapi.AdminGenerateResponse{
				Address: addr,
				KeyType: "ed25519",
			}, req), nil
		case req.Method == http.MethodGet && req.URL.Path == "/keys":
			return keyMgmtTextResponse(http.StatusInternalServerError, "refresh failed", req), nil
		default:
			t.Fatalf("unexpected request: %s %s", req.Method, req.URL.Path)
			return nil, nil
		}
	})

	got, err := eng.GenerateKey(context.Background(), "ed25519", nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v, want nil despite refresh failure", err)
	}
	if got.Address != addr || got.KeyType != "ed25519" {
		t.Fatalf("GenerateKey() = %#v, want address=%s keyType=ed25519", got, addr)
	}
	if eng.SignerCache.Count() != 0 {
		t.Fatalf("SignerCache.Count() = %d, want unchanged cache after ignored refresh failure", eng.SignerCache.Count())
	}
}

func TestEngineDeleteKeyIgnoresRefreshFailure(t *testing.T) {
	addr := testAddr(22)
	signerCache := cache.NewSignerCache()
	signerCache.AddAddress(addr, "ed25519")

	eng := newConnectedEngineForKeyMgmtTestWithSignerCache(t, signerCache, func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodDelete && req.URL.Path == "/admin/keys":
			return keyMgmtJSONResponse(t, http.StatusOK, signerapi.AdminDeleteResponse{Success: true}, req), nil
		case req.Method == http.MethodGet && req.URL.Path == "/keys":
			return keyMgmtTextResponse(http.StatusInternalServerError, "refresh failed", req), nil
		default:
			t.Fatalf("unexpected request: %s %s", req.Method, req.URL.Path)
			return nil, nil
		}
	})

	if err := eng.DeleteKey(context.Background(), addr); err != nil {
		t.Fatalf("DeleteKey() error = %v, want nil despite refresh failure", err)
	}
	if eng.SignerCache.GetKeyType(addr) != "ed25519" {
		t.Fatalf("SignerCache key type = %q, want original cache preserved", eng.SignerCache.GetKeyType(addr))
	}
}

func newConnectedEngineForKeyMgmtTest(t *testing.T, handler func(*http.Request) (*http.Response, error)) *Engine {
	t.Helper()
	return newConnectedEngineForKeyMgmtTestWithSignerCache(t, cache.NewSignerCache(), handler)
}

func newConnectedEngineForKeyMgmtTestWithSignerCache(t *testing.T, signerCache cache.SignerCache, handler func(*http.Request) (*http.Response, error)) *Engine {
	t.Helper()
	eng, err := NewEngine("testnet", WithSignerCache(signerCache), WithCacheStore(cache.NewStore(t.TempDir())))
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	client := signerclient.NewSignerClientWithToken("http://signer.test", "token")
	client.Client = &http.Client{Transport: keyMgmtRoundTripper{t: t, handler: handler}}
	eng.Connection = &engconnect.ConnectionState{SignerClient: client}
	return eng
}

func keyMgmtJSONResponse(t *testing.T, status int, body interface{}, req *http.Request) *http.Response {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(data)),
		Request:    req,
	}
}

func keyMgmtTextResponse(status int, body string, req *http.Request) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"text/plain"}},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}
}
