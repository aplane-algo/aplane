// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/cache"
	engconnect "github.com/aplane-algo/aplane/internal/engine/connect"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signerclient"
)

// TestEngineGenerateKeyExpandsAddressListParams locks in the fix for the JS/MCP
// generateKey divergence: address[] creation params (here an allowlist's
// "recipients") must be resolved alias->address and sorted by the engine before
// reaching the signer, which has no alias knowledge. Previously this lived only
// in the REPL/App layer, so JS/MCP callers passed raw alias strings and the
// signer rejected them.
func TestEngineGenerateKeyExpandsAddressListParams(t *testing.T) {
	friend := testAddr(31) // resolved address for alias "friend"
	addrB := testAddr(30)  // a raw address passed alongside the alias
	newKey := testAddr(32) // address the signer returns for the new key

	aliasCache := cache.AliasCache{Aliases: map[string]string{"friend": friend}}
	eng, err := NewEngine("testnet",
		WithSignerCache(cache.NewSignerCache()),
		WithCacheStore(cache.NewStore(t.TempDir())),
		WithAliasCache(aliasCache),
	)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	var captured map[string]string
	handler := func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodGet && req.URL.Path == "/keytypes":
			return keyMgmtJSONResponse(t, http.StatusOK, signerapi.KeyTypesResponse{
				KeyTypes: []signerapi.KeyTypeInfo{{
					KeyType:        "test.generic-policy.v1",
					CreationParams: []signerapi.CreationParamInfo{{Name: "recipients", Type: "address[]"}},
				}},
			}, req), nil
		case req.Method == http.MethodPost && req.URL.Path == "/admin/generate":
			var body signerapi.AdminGenerateRequest
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
				t.Fatalf("Decode(generate request) error = %v", err)
			}
			captured = body.Parameters
			return keyMgmtJSONResponse(t, http.StatusOK, signerapi.AdminGenerateResponse{
				Address: newKey,
				KeyType: "test.generic-policy.v1",
			}, req), nil
		case req.Method == http.MethodGet && req.URL.Path == "/keys":
			return keyMgmtJSONResponse(t, http.StatusOK, signerapi.KeysResponse{
				Count: 1,
				Keys:  []signerapi.KeyInfo{{Address: newKey, KeyType: "test.generic-policy.v1"}},
			}, req), nil
		default:
			t.Fatalf("unexpected request: %s %s", req.Method, req.URL.Path)
			return nil, nil
		}
	}
	client := signerclient.NewSignerClientWithToken("http://signer.test", "token")
	client.Client = &http.Client{Transport: keyMgmtRoundTripper{t: t, handler: handler}}
	eng.Connection = &engconnect.ConnectionState{SignerClient: client}

	// recipients given as a raw address + an alias, in unsorted order.
	_, err = eng.GenerateKey(context.Background(), "test.generic-policy.v1",
		map[string]string{"recipients": addrB + ",friend"})
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	wantParts := []string{addrB, friend}
	sort.Strings(wantParts)
	want := strings.Join(wantParts, ",")
	if captured["recipients"] != want {
		t.Fatalf("recipients sent to signer = %q, want %q (alias resolved + sorted)", captured["recipients"], want)
	}
}
