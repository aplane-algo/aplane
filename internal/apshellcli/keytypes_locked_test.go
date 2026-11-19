// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// keytypes on a locked signer says its list is the built-in key types only.
// The machine result stays the list.
func TestKeytypesNotesALockedSignersPartialList(t *testing.T) {
	signer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body any
		switch r.URL.Path {
		case "/keytypes":
			body = signerapi.KeyTypesResponse{KeyTypes: []signerapi.KeyTypeInfo{{KeyType: "ed25519", Description: "Native Algorand signing key"}}}
		case "/status":
			body = signerapi.StatusResponse{SignerLocked: true}
		default:
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(signer.Close)
	eng := newIsolatedTestEngine(t, "testnet")
	eng.Connection.SignerClient = signerclient.NewSignerClient(signer.URL)
	repl := &REPLState{App: apshellapp.New(eng, config.DefaultConfig(), t.TempDir()), DataDir: t.TempDir()}
	repl.SetOutput(&bytes.Buffer{})

	result, err := repl.cmdKeytypes(nil, nil)
	if err != nil {
		t.Fatalf("cmdKeytypes() error = %v", err)
	}
	var out bytes.Buffer
	if err := result.RenderText(&out); err != nil {
		t.Fatalf("RenderText() error = %v", err)
	}
	if !strings.HasPrefix(out.String(), "The signer is locked: only its built-in key types are listed.") ||
		!strings.Contains(out.String(), "ed25519") {
		t.Fatalf("keytypes output:\n%s", out.String())
	}
	machine, err := result.MarshalMachine()
	if err != nil {
		t.Fatalf("MarshalMachine() error = %v", err)
	}
	var list []signerapi.KeyTypeInfo
	if err := json.Unmarshal(machine, &list); err != nil || len(list) != 1 {
		t.Fatalf("machine result = %s (%v), want the key type list", machine, err)
	}
}
