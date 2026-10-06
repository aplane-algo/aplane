// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/witness"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// recordingEndpoint is a fake node that records every bearer token presented
// to it, whatever the path.
type recordingEndpoint struct {
	*httptest.Server
	mu        sync.Mutex
	presented []string
}

func (e *recordingEndpoint) tokens() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.presented...)
}

func newRecordingEndpoint(t *testing.T, token, nodeRole string, keys []signerapi.KeyInfo) *recordingEndpoint {
	t.Helper()
	endpoint := &recordingEndpoint{}
	endpoint.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		endpoint.mu.Lock()
		endpoint.presented = append(endpoint.presented, r.Header.Get("Authorization"))
		endpoint.mu.Unlock()
		if r.Header.Get("Authorization") != "aplane "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/status":
			_ = json.NewEncoder(w).Encode(signerapi.StatusResponse{NodeRole: nodeRole, State: "unlocked"})
		case "/keys":
			_ = json.NewEncoder(w).Encode(signerapi.KeysResponse{Count: len(keys), Keys: keys})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(endpoint.Close)
	return endpoint
}

func advertisedWitness(reference witness.PublicReference) signerapi.KeyInfo {
	return signerapi.KeyInfo{
		Address: reference.WitnessKeyID, PublicKeyHex: reference.PublicKeyHex,
		KeyType: reference.KeyType, IsWitnessKey: true,
	}
}

// runCosignerSetup drives prepare, apply, and complete the way the shell does.
func runCosignerSetup(t *testing.T, app *App, req CosignerSetupRequest) (CosignerSetupPlan, *CosignerSetupResult, error) {
	t.Helper()
	plan, err := app.PrepareCosignerSetup(req)
	if err != nil {
		t.Fatalf("PrepareCosignerSetup() error = %v", err)
	}
	endpoint, err := app.ApplyCosignerSetupEndpoint(plan, true)
	if err != nil {
		t.Fatalf("ApplyCosignerSetupEndpoint() error = %v", err)
	}
	result, err := app.CompleteCosignerSetup(context.Background(), plan, endpoint, nil, nil)
	return plan, result, err
}

func TestEndpointImportAndCreateRetireTokenWhenDestinationChanges(t *testing.T) {
	t.Run("import", func(t *testing.T) {
		dataDir := t.TempDir()
		writeLiveCosignerEndpoint(t, dataDir, "cosigner-local", "ssh://old.example:2223", "old-token")
		result, err := newEndpointTestApp(t, dataDir).EndpointImport(t.Context(), EndpointImportRequest{
			Alias: "cosigner-local", Role: config.ClientEndpointRoleCosigner, Path: writeEndpointEnvelope(t, dataDir),
		})
		if err != nil {
			t.Fatal(err)
		}
		if !result.TokenRetired || !strings.Contains(strings.Join(result.RenderLines, "\n"), "issued by the previous destination and was removed") {
			t.Fatalf("result = %#v, want the retired token reported", result)
		}
		if _, err := os.Stat(filepath.Join(dataDir, "tokens", "cosigner-local.token")); !os.IsNotExist(err) {
			t.Fatalf("token stat error = %v, want the previous destination's token removed", err)
		}
	})
	t.Run("import dry run keeps the token", func(t *testing.T) {
		dataDir := t.TempDir()
		writeLiveCosignerEndpoint(t, dataDir, "cosigner-local", "ssh://old.example:2223", "old-token")
		result, err := newEndpointTestApp(t, dataDir).EndpointImport(t.Context(), EndpointImportRequest{
			Alias: "cosigner-local", Role: config.ClientEndpointRoleCosigner, Path: writeEndpointEnvelope(t, dataDir), DryRun: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if !result.TokenRetired || !strings.Contains(strings.Join(result.RenderLines, "\n"), "would be removed") {
			t.Fatalf("result = %#v, want the pending retirement reported", result)
		}
		if _, err := os.Stat(filepath.Join(dataDir, "tokens", "cosigner-local.token")); err != nil {
			t.Fatalf("token stat error = %v, want a dry run to keep the token", err)
		}
	})
	t.Run("create over a leftover token", func(t *testing.T) {
		dataDir := t.TempDir()
		tokenPath := filepath.Join(dataDir, "tokens", "field.token")
		if err := os.MkdirAll(filepath.Dir(tokenPath), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(tokenPath, []byte("old-token\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		result, err := newEndpointTestApp(t, dataDir).EndpointCreateCosigner(t.Context(), EndpointCreateCosignerRequest{
			Alias: "field", URL: "ssh://new.example:2223", CosignerPort: 12270,
		})
		if err != nil {
			t.Fatal(err)
		}
		if !result.Created || !result.TokenRetired ||
			!strings.Contains(strings.Join(result.RenderLines, "\n"), "left over under this name predates the endpoint and was removed") {
			t.Fatalf("result = %#v, want the leftover token reported as removed", result)
		}
		if _, err := os.Stat(tokenPath); !os.IsNotExist(err) {
			t.Fatalf("token stat error = %v, want the leftover token removed", err)
		}
	})
	t.Run("create", func(t *testing.T) {
		dataDir := t.TempDir()
		writeLiveCosignerEndpoint(t, dataDir, "field", "ssh://old.example:2223", "old-token")
		result, err := newEndpointTestApp(t, dataDir).EndpointCreateCosigner(t.Context(), EndpointCreateCosignerRequest{
			Alias: "field", URL: "ssh://new.example:2223", CosignerPort: 12270,
		})
		if err != nil {
			t.Fatal(err)
		}
		if !result.TokenRetired {
			t.Fatalf("result = %#v, want the retired token reported", result)
		}
		if _, err := os.Stat(filepath.Join(dataDir, "tokens", "field.token")); !os.IsNotExist(err) {
			t.Fatalf("token stat error = %v, want the previous destination's token removed", err)
		}
	})
}

// A replaced destination must not inherit the old token, including when the
// first attempt stops before a new token is in place and setup is rerun.
func TestCosignerSetupNeverPresentsPreviousTokenAfterInterruptedReplacement(t *testing.T) {
	dataDir := t.TempDir()
	reference := testCosignerReference(t)
	keys := []signerapi.KeyInfo{advertisedWitness(reference)}
	previous := newRecordingEndpoint(t, "old-token", "cosigner", keys)
	replacement := newRecordingEndpoint(t, "new-token", "cosigner", keys)
	writeLiveCosignerEndpoint(t, dataDir, "field", previous.URL, "old-token")
	app := newEndpointTestApp(t, dataDir)
	tokenPath := filepath.Join(dataDir, "tokens", "field.token")

	plan, _, err := runCosignerSetup(t, app, CosignerSetupRequest{Alias: "field", URL: replacement.URL})
	if !plan.DestinationChanged || !plan.RetiresToken {
		t.Fatalf("plan = %#v, want a destination replacement that retires the token", plan)
	}
	if err == nil || !strings.Contains(err.Error(), "previous destination's token was retired") {
		t.Fatalf("first attempt error = %v, want retired-token guidance", err)
	}
	if _, statErr := os.Stat(tokenPath); !os.IsNotExist(statErr) {
		t.Fatalf("token stat error = %v, want the previous destination's token removed", statErr)
	}

	// The rerun sees an unchanged route. It must find no token rather than
	// reuse the previous destination's.
	rerun, _, err := runCosignerSetup(t, app, CosignerSetupRequest{Alias: "field", URL: replacement.URL})
	if !rerun.Unchanged() {
		t.Fatalf("rerun plan = %#v, want an unchanged route", rerun)
	}
	if err == nil || !strings.Contains(err.Error(), "has no token") {
		t.Fatalf("rerun error = %v, want missing-token guidance", err)
	}
	if presented := replacement.tokens(); len(presented) != 0 {
		t.Fatalf("new destination was presented %q, want no request carrying the previous token", presented)
	}

	// Installing the new destination's token completes setup.
	if err := os.WriteFile(tokenPath, []byte("new-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, result, err := runCosignerSetup(t, app, CosignerSetupRequest{Alias: "field", URL: replacement.URL})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Connected || result.AdvertisedKeys != 1 {
		t.Fatalf("result = %#v, want a connected setup", result)
	}
	for _, presented := range replacement.tokens() {
		if presented != "aplane new-token" {
			t.Fatalf("new destination was presented %q, want only its own token", presented)
		}
	}
}

// Deleting a connection and creating one of the same name for another
// destination must not carry the old token across, on the first attempt or on
// a rerun after the first attempt stopped early.
func TestCosignerSetupNeverPresentsTokenLeftByDeletedConnection(t *testing.T) {
	reference := testCosignerReference(t)
	keys := []signerapi.KeyInfo{advertisedWitness(reference)}

	t.Run("direct connection", func(t *testing.T) {
		dataDir := t.TempDir()
		writeLiveCosignerEndpoint(t, dataDir, "field", "https://old.example", "old-token")
		app := newEndpointTestApp(t, dataDir)
		deleted, err := app.EndpointDelete(context.Background(), "field")
		if err != nil {
			t.Fatal(err)
		}
		tokenPath := filepath.Join(dataDir, "tokens", "field.token")
		if !deleted.TokenRetired || !strings.Contains(strings.Join(deleted.RenderLines, "\n"), "token: removed with the endpoint") {
			t.Fatalf("delete result = %#v, want the token retired with the endpoint", deleted)
		}
		if _, statErr := os.Stat(tokenPath); !os.IsNotExist(statErr) {
			t.Fatalf("token stat error = %v, want the deleted endpoint's token removed", statErr)
		}

		// Even a token file that survives from before this fix is not carried
		// into a newly created connection.
		if err := os.WriteFile(tokenPath, []byte("old-token\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		fresh := newRecordingEndpoint(t, "new-token", "cosigner", keys)
		plan, _, err := runCosignerSetup(t, app, CosignerSetupRequest{Alias: "field", URL: fresh.URL})
		if !plan.Created || !plan.RetiresToken {
			t.Fatalf("plan = %#v, want a create that retires the leftover token", plan)
		}
		if err == nil || !strings.Contains(err.Error(), "a token file left over under this name was removed") {
			t.Fatalf("first attempt error = %v, want leftover-token guidance", err)
		}
		_, _, err = runCosignerSetup(t, app, CosignerSetupRequest{Alias: "field", URL: fresh.URL})
		if err == nil || !strings.Contains(err.Error(), "has no token") {
			t.Fatalf("rerun error = %v, want missing-token guidance", err)
		}
		if presented := fresh.tokens(); len(presented) != 0 {
			t.Fatalf("new destination was presented %q, want no request carrying the old token", presented)
		}
	})

	t.Run("ssh connection whose enrollment stops", func(t *testing.T) {
		dataDir := t.TempDir()
		tokenPath := filepath.Join(dataDir, "tokens", "field.token")
		if err := os.MkdirAll(filepath.Dir(tokenPath), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(tokenPath, []byte("old-token\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		app := newEndpointTestApp(t, dataDir)
		// Nothing listens here, so the access request fails.
		request := CosignerSetupRequest{Alias: "field", URL: "ssh://127.0.0.1:1"}
		plan, _, err := runCosignerSetup(t, app, request)
		if !plan.Created || err == nil || !strings.Contains(err.Error(), "request token from endpoint") {
			t.Fatalf("plan = %#v error = %v, want a create whose access request failed", plan, err)
		}
		if _, statErr := os.Stat(tokenPath); !os.IsNotExist(statErr) {
			t.Fatalf("token stat error = %v, want the leftover token gone before the rerun", statErr)
		}
		// The rerun sees an existing, unchanged connection. With no token left
		// it must request access again rather than skip enrollment.
		rerun, _, err := runCosignerSetup(t, app, request)
		if !rerun.Unchanged() || err == nil || !strings.Contains(err.Error(), "request token from endpoint") {
			t.Fatalf("rerun plan = %#v error = %v, want another access request", rerun, err)
		}
	})
}

func TestSaveEndpointTokenIfCurrentDiscardsTokenForReplacedDestination(t *testing.T) {
	const alias = "field"
	requested := func(t *testing.T, dataDir string) config.ClientEndpointConfig {
		t.Helper()
		registry, err := config.LoadClientEndpointRegistry(dataDir)
		if err != nil {
			t.Fatal(err)
		}
		endpoint, ok := registry.Endpoint(alias)
		if !ok {
			t.Fatalf("endpoint %q missing", alias)
		}
		return endpoint
	}
	setup := func(t *testing.T) (string, *App, config.ClientEndpointConfig) {
		t.Helper()
		dataDir := t.TempDir()
		if _, err := config.UpsertStoredClientEndpoint(dataDir, alias, config.ClientEndpointConfig{
			Role: config.ClientEndpointRoleCosigner, URL: "ssh://old.example:2223",
		}, true); err != nil {
			t.Fatal(err)
		}
		return dataDir, newEndpointTestApp(t, dataDir), requested(t, dataDir)
	}
	tokenPath := func(dataDir string) string { return filepath.Join(dataDir, "tokens", alias+".token") }

	t.Run("unchanged destination saves", func(t *testing.T) {
		dataDir, app, endpoint := setup(t)
		path, err := app.saveEndpointTokenIfCurrent(alias, endpoint, "issued")
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil || strings.TrimSpace(string(data)) != "issued" || path != tokenPath(dataDir) {
			t.Fatalf("saved %q at %s (err %v), want the issued token at the alias's token path", data, path, err)
		}
	})
	t.Run("destination replaced while approval was pending", func(t *testing.T) {
		dataDir, app, endpoint := setup(t)
		if _, err := lockedEndpointUpsert(dataDir, alias, config.ClientEndpointConfig{
			Role: config.ClientEndpointRoleCosigner, URL: "ssh://new.example:2223",
		}, true); err != nil {
			t.Fatal(err)
		}
		_, err := app.saveEndpointTokenIfCurrent(alias, endpoint, "issued-by-old-destination")
		if err == nil || !strings.Contains(err.Error(), "the issued token was discarded") {
			t.Fatalf("saveEndpointTokenIfCurrent() error = %v, want the late token discarded", err)
		}
		if _, statErr := os.Stat(tokenPath(dataDir)); !os.IsNotExist(statErr) {
			t.Fatalf("token stat error = %v, want no token under the new route", statErr)
		}
	})
	t.Run("api port replaced while approval was pending", func(t *testing.T) {
		dataDir, app, endpoint := setup(t)
		if _, err := lockedEndpointUpsert(dataDir, alias, config.ClientEndpointConfig{
			Role: config.ClientEndpointRoleCosigner, URL: "ssh://old.example:2223", SignerPort: 12999,
		}, true); err != nil {
			t.Fatal(err)
		}
		if _, err := app.saveEndpointTokenIfCurrent(alias, endpoint, "issued"); err == nil {
			t.Fatal("saveEndpointTokenIfCurrent() succeeded, want the late token discarded")
		}
	})
	t.Run("token file moved while approval was pending", func(t *testing.T) {
		dataDir, app, endpoint := setup(t)
		if _, err := lockedEndpointUpsert(dataDir, alias, config.ClientEndpointConfig{
			Role: config.ClientEndpointRoleCosigner, URL: "ssh://old.example:2223", TokenFile: "elsewhere.token",
		}, true); err != nil {
			t.Fatal(err)
		}
		if _, err := app.saveEndpointTokenIfCurrent(alias, endpoint, "issued"); err == nil {
			t.Fatal("saveEndpointTokenIfCurrent() succeeded, want the late token discarded")
		}
		if _, statErr := os.Stat(filepath.Join(dataDir, "elsewhere.token")); !os.IsNotExist(statErr) {
			t.Fatalf("token stat error = %v, want nothing written to the new token file", statErr)
		}
	})
	t.Run("alias removed while approval was pending", func(t *testing.T) {
		dataDir, app, endpoint := setup(t)
		if _, err := config.DeleteStoredClientEndpoint(dataDir, alias); err != nil {
			t.Fatal(err)
		}
		if _, err := app.saveEndpointTokenIfCurrent(alias, endpoint, "issued"); err == nil {
			t.Fatal("saveEndpointTokenIfCurrent() succeeded, want the late token discarded")
		}
	})
}

func TestCompleteCosignerSetupRequiresCosignerRole(t *testing.T) {
	reference := testCosignerReference(t)
	keys := []signerapi.KeyInfo{advertisedWitness(reference)}
	tests := []struct {
		name     string
		nodeRole string
		want     error
		message  string
	}{
		{name: "signer", nodeRole: "signer", want: ErrCosignerSetupNotCosigner, message: "endpoints import --alias <alias> --role signer"},
		{name: "absent", nodeRole: "", want: ErrCosignerSetupRoleUnverified, message: "did not report a node role"},
		{name: "unrecognized", nodeRole: "auditor", want: ErrCosignerSetupRoleUnverified, message: `unrecognized role "auditor"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dataDir := t.TempDir()
			server := newRecordingEndpoint(t, "token", tt.nodeRole, keys)
			writeLiveCosignerEndpoint(t, dataDir, "field", server.URL, "token")
			_, result, err := runCosignerSetup(t, newEndpointTestApp(t, dataDir), CosignerSetupRequest{Alias: "field"})
			if !errors.Is(err, tt.want) || !strings.Contains(err.Error(), tt.message) {
				t.Fatalf("CompleteCosignerSetup() error = %v, want %v mentioning %q", err, tt.want, tt.message)
			}
			if result.Connected || result.NodeRole != tt.nodeRole {
				t.Fatalf("result = %#v, want an unverified connection reporting role %q", result, tt.nodeRole)
			}
		})
	}

	t.Run("status failed", func(t *testing.T) {
		dataDir := t.TempDir()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "boom", http.StatusInternalServerError)
		}))
		t.Cleanup(server.Close)
		writeLiveCosignerEndpoint(t, dataDir, "field", server.URL, "token")
		_, result, err := runCosignerSetup(t, newEndpointTestApp(t, dataDir), CosignerSetupRequest{Alias: "field"})
		if !errors.Is(err, ErrCosignerSetupRoleUnverified) {
			t.Fatalf("CompleteCosignerSetup() error = %v, want %v", err, ErrCosignerSetupRoleUnverified)
		}
		if result.Connected {
			t.Fatalf("result = %#v, want no claim of a cosigner connection", result)
		}
	})
}

func TestCompleteCosignerSetupReportsAdvertisedKeyCount(t *testing.T) {
	dataDir := t.TempDir()
	reference := testCosignerReference(t)
	server := newRecordingEndpoint(t, "token", "cosigner", []signerapi.KeyInfo{advertisedWitness(reference)})
	writeLiveCosignerEndpoint(t, dataDir, "field", server.URL, "token")
	app := newEndpointTestApp(t, dataDir)

	_, result, err := runCosignerSetup(t, app, CosignerSetupRequest{URL: server.URL, Alias: "field"})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Connected || result.AdvertisedKeys != 1 {
		t.Fatalf("result = %#v, want access with the advertised key count", result)
	}
	output := strings.Join(result.RenderLines, "\n")
	if !strings.Contains(output, "1 cosigner key(s) advertised.") || strings.Contains(output, "setup file") {
		t.Fatalf("output = %q, want the inventory count and no key claim", output)
	}
}

func TestCompleteCosignerSetupFailsOnlyForRoutesThroughThisConnection(t *testing.T) {
	reference := testCosignerReference(t)
	keys := []signerapi.KeyInfo{advertisedWitness(reference)}

	t.Run("another connection cannot be read", func(t *testing.T) {
		dataDir := t.TempDir()
		server := newRecordingEndpoint(t, "token", "cosigner", keys)
		down := httptest.NewServer(http.NotFoundHandler())
		downURL := down.URL
		down.Close()
		writeLiveCosignerEndpoint(t, dataDir, "elsewhere", downURL, "token")
		writeLiveCosignerEndpoint(t, dataDir, "field", server.URL, "token")

		_, result, err := runCosignerSetup(t, newEndpointTestApp(t, dataDir), CosignerSetupRequest{Alias: "field"})
		if err != nil {
			t.Fatalf("CompleteCosignerSetup() error = %v, want another connection's failure reported without failing setup", err)
		}
		if len(result.Routes.Unread) != 1 || result.Routes.Unread[0].Alias != "elsewhere" || result.Routes.Stopped != "" {
			t.Fatalf("routes = %#v, want elsewhere reported as tried and unread", result.Routes)
		}
		output := strings.Join(result.RenderLines, "\n")
		for _, want := range []string{
			"Connection field ready.",
			"1 cosigner key(s) advertised.",
			"Account routes not checked: primary signer disconnected",
			"Could not read: elsewhere (unavailable). Duplicates there cannot be ruled out.",
		} {
			if !strings.Contains(output, want) {
				t.Fatalf("output = %q, want %q", output, want)
			}
		}
	})

	t.Run("duplicate route through the new connection", func(t *testing.T) {
		dataDir := t.TempDir()
		first := newRecordingEndpoint(t, "token", "cosigner", keys)
		second := newRecordingEndpoint(t, "token", "cosigner", keys)
		writeLiveCosignerEndpoint(t, dataDir, "first", first.URL, "token")
		app := newEndpointTestApp(t, dataDir)
		// A direct connection cannot enroll, so its token is installed once
		// setup has created the route, standing in for the token an SSH
		// enrollment would deliver during the same run.
		plan, err := app.PrepareCosignerSetup(CosignerSetupRequest{Alias: "second", URL: second.URL})
		if err != nil {
			t.Fatal(err)
		}
		endpoint, err := app.ApplyCosignerSetupEndpoint(plan, false)
		if err != nil {
			t.Fatal(err)
		}
		tokenPath := filepath.Join(dataDir, "tokens", "second.token")
		if err := os.WriteFile(tokenPath, []byte("token\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		result, err := app.CompleteCosignerSetup(context.Background(), plan, endpoint, nil, nil)
		if !errors.Is(err, ErrCosignerSetupDuplicateRoute) {
			t.Fatalf("CompleteCosignerSetup() error = %v, want %v", err, ErrCosignerSetupDuplicateRoute)
		}
		if !plan.Created || len(result.Routes.Duplicates) != 1 || len(result.Routes.OtherDuplicates) != 0 {
			t.Fatalf("plan = %#v routes = %#v, want one duplicate through the created connection", plan, result.Routes)
		}
		if !strings.Contains(err.Error(), "first and second") {
			t.Fatalf("error = %v, want both connection names", err)
		}

		if err := app.RemoveCreatedCosignerConnection(plan); err != nil {
			t.Fatal(err)
		}
		registry, _, err := config.LoadStoredClientEndpointRegistry(dataDir)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := registry.Endpoint("second"); ok {
			t.Fatal("created connection was not removed")
		}
		if _, ok := registry.Endpoint("first"); !ok {
			t.Fatal("existing connection was removed")
		}
		// A token's lifetime ends with its connection.
		if _, err := os.Stat(tokenPath); !os.IsNotExist(err) {
			t.Fatalf("token stat error = %v, want the removed connection's token retired", err)
		}
		if _, err := os.Stat(filepath.Join(dataDir, "tokens", "first.token")); err != nil {
			t.Fatalf("token stat error = %v, want the existing connection's token kept", err)
		}
	})

	t.Run("existing connections are not removable", func(t *testing.T) {
		dataDir := t.TempDir()
		server := newRecordingEndpoint(t, "token", "cosigner", keys)
		writeLiveCosignerEndpoint(t, dataDir, "field", server.URL, "token")
		app := newEndpointTestApp(t, dataDir)
		plan, _, err := runCosignerSetup(t, app, CosignerSetupRequest{Alias: "field"})
		if err != nil {
			t.Fatal(err)
		}
		if err := app.RemoveCreatedCosignerConnection(plan); err == nil {
			t.Fatal("RemoveCreatedCosignerConnection() succeeded for a connection this run did not create")
		}
	})
}

func TestCosignerSetupRoutesKeepResolverClassifications(t *testing.T) {
	const witnessID = "U2QQHAZCHRMLJLR62M5ZC24YEXAMPLEEXAMPLEEXAMPLEEXAMPLE"
	result := func(routes *CosignerSetupRoutes) string {
		return strings.Join(cosignerSetupRenderLines(&CosignerSetupResult{
			Alias: "field", Connected: true, AdvertisedKeys: 1, Routes: routes,
		}, nil), "\n")
	}

	t.Run("host key mismatch stops the sweep", func(t *testing.T) {
		routes := cosignerSetupRoutes("field", engine.CosignerStatusResult{
			AccountInventory: "available",
			RouteStatus: engine.CosignerRouteStatus{
				DiscoveryError: "cosigner endpoint SSH host key mismatch at endpoint \"old\"",
				Connections: []engine.CosignerConnectionObservation{
					{Alias: "dr", State: engine.CosignerConnectionNotChecked},
					{Alias: "field", State: engine.CosignerConnectionReachable, Witnesses: []string{witnessID}},
					{Alias: "old", State: engine.CosignerConnectionHostKeyMismatch, Error: "mismatch"},
				},
				Accounts: []engine.CosignerAccountRouteObservation{
					{Address: "ACCOUNT", WitnessKeyID: witnessID, Routes: []string{"field"}, State: engine.CosignerAccountRouteCheckIncomplete},
				},
			},
		})
		if len(routes.HostKeyMismatch) != 1 || routes.HostKeyMismatch[0] != "old" ||
			len(routes.NotContacted) != 1 || routes.NotContacted[0] != "dr" || len(routes.Unread) != 0 {
			t.Fatalf("routes = %#v, want old as a mismatch and dr as never contacted", routes)
		}
		output := result(routes)
		for _, want := range []string{
			"Route check stopped: the host key for old does not match its pinned key.",
			"Not contacted: dr.",
		} {
			if !strings.Contains(output, want) {
				t.Fatalf("output = %q, want %q", output, want)
			}
		}
		for _, unwanted := range []string{"routes available", "Matching route observed", "old not checked"} {
			if strings.Contains(output, unwanted) {
				t.Fatalf("output = %q, must not claim %q after a stopped sweep", output, unwanted)
			}
		}
	})

	t.Run("failed connection qualifies an observed route", func(t *testing.T) {
		routes := cosignerSetupRoutes("field", engine.CosignerStatusResult{
			AccountInventory: "available",
			RouteStatus: engine.CosignerRouteStatus{
				Connections: []engine.CosignerConnectionObservation{
					{Alias: "dr", State: "signer locked", Error: "locked"},
					{Alias: "field", State: engine.CosignerConnectionReachable, Witnesses: []string{witnessID}},
				},
				Accounts: []engine.CosignerAccountRouteObservation{
					{Address: "ROUTED", WitnessKeyID: witnessID, Routes: []string{"field"}, State: engine.CosignerAccountRouteAvailable},
					{Address: "UNROUTED", WitnessKeyID: witnessID, Routes: []string{}, State: engine.CosignerAccountRouteMissing},
				},
			},
		})
		if routes.AccountsRequired != 2 || routes.AccountsRouted != 1 || len(routes.Unrouted) != 1 {
			t.Fatalf("routes = %#v, want one of two accounts routed", routes)
		}
		output := result(routes)
		for _, want := range []string{
			"Matching route observed for 1 of 2 accounts on the connected signer.",
			"UNROUTED: " + engine.CosignerAccountRouteMissing,
			"Could not read: dr (signer locked). Duplicates there cannot be ruled out.",
		} {
			if !strings.Contains(output, want) {
				t.Fatalf("output = %q, want %q", output, want)
			}
		}
		if strings.Contains(output, "Cosigner routes available for") {
			t.Fatalf("output = %q, must qualify routes when a connection could not be read", output)
		}
	})

	t.Run("complete sweep reports routes plainly", func(t *testing.T) {
		routes := cosignerSetupRoutes("field", engine.CosignerStatusResult{
			AccountInventory: "available",
			RouteStatus: engine.CosignerRouteStatus{
				Connections: []engine.CosignerConnectionObservation{
					{Alias: "field", State: engine.CosignerConnectionReachable, Witnesses: []string{witnessID}},
				},
				Accounts: []engine.CosignerAccountRouteObservation{
					{Address: "ROUTED", WitnessKeyID: witnessID, Routes: []string{"field"}, State: engine.CosignerAccountRouteAvailable},
				},
			},
		})
		if output := result(routes); !strings.Contains(output, "Cosigner routes available for 1 of 1 accounts on the connected signer.") {
			t.Fatalf("output = %q, want an unqualified route count", output)
		}
	})

	t.Run("empty and unavailable inventories differ", func(t *testing.T) {
		empty := result(cosignerSetupRoutes("field", engine.CosignerStatusResult{AccountInventory: "available"}))
		unavailable := result(cosignerSetupRoutes("field", engine.CosignerStatusResult{
			AccountInventory: "unavailable", InventoryError: "primary signer locked",
		}))
		if !strings.Contains(empty, "No accounts requiring a cosigner on the connected signer.") ||
			!strings.Contains(empty, "Next: create an account in signer-side apadmin and choose this cosigner's key file.") {
			t.Fatalf("empty inventory output = %q", empty)
		}
		if !strings.Contains(unavailable, "Account routes not checked: primary signer locked.") ||
			strings.Contains(unavailable, "No accounts requiring a cosigner") {
			t.Fatalf("unavailable inventory output = %q", unavailable)
		}
	})

	t.Run("duplicates are split by whether they involve this connection", func(t *testing.T) {
		routes := cosignerSetupRoutes("field", engine.CosignerStatusResult{
			AccountInventory: "available",
			RouteStatus: engine.CosignerRouteStatus{DuplicateRoutes: map[string][]string{
				witnessID:    {"field", "twin"},
				"OTHERKEYID": {"a", "b"},
			}},
		})
		if len(routes.Duplicates) != 1 || len(routes.OtherDuplicates) != 1 {
			t.Fatalf("routes = %#v, want one duplicate through field and one elsewhere", routes)
		}
	})
}

func TestResolveCosignerSetupTargetReusesExistingConnectionOrSuggestsName(t *testing.T) {
	const cosignerURL = "ssh://cosigner.example:1127"

	t.Run("suggests a name from the host", func(t *testing.T) {
		target, err := newEndpointTestApp(t, t.TempDir()).ResolveCosignerSetupTarget(CosignerSetupRequest{URL: cosignerURL})
		if err != nil {
			t.Fatal(err)
		}
		if target.ExistingAlias != "" || target.SuggestedAlias != "cosigner-example" || target.URL != "ssh://cosigner.example:1127" {
			t.Fatalf("target = %#v, want a suggested name", target)
		}
	})
	t.Run("makes the suggestion unique", func(t *testing.T) {
		dataDir := t.TempDir()
		if _, err := config.UpsertStoredClientEndpoint(dataDir, "cosigner-example", config.ClientEndpointConfig{
			Role: config.ClientEndpointRoleCosigner, URL: "ssh://elsewhere.example",
		}, true); err != nil {
			t.Fatal(err)
		}
		target, err := newEndpointTestApp(t, dataDir).ResolveCosignerSetupTarget(CosignerSetupRequest{URL: cosignerURL})
		if err != nil {
			t.Fatal(err)
		}
		if target.SuggestedAlias != "cosigner-example-2" {
			t.Fatalf("target = %#v, want a unique suggestion", target)
		}
	})
	t.Run("reuses the connection already at that url", func(t *testing.T) {
		dataDir := t.TempDir()
		if _, err := config.UpsertStoredClientEndpoint(dataDir, "treasury", config.ClientEndpointConfig{
			Role: config.ClientEndpointRoleCosigner, URL: "ssh://cosigner.example:1127",
		}, true); err != nil {
			t.Fatal(err)
		}
		app := newEndpointTestApp(t, dataDir)
		target, err := app.ResolveCosignerSetupTarget(CosignerSetupRequest{URL: cosignerURL})
		if err != nil {
			t.Fatal(err)
		}
		if target.ExistingAlias != "treasury" || target.SuggestedAlias != "" {
			t.Fatalf("target = %#v, want the existing connection", target)
		}
		// A second name for the same destination is refused with guidance to
		// the existing one, not to deleting it.
		_, err = app.PrepareCosignerSetup(CosignerSetupRequest{URL: cosignerURL, Alias: "another"})
		if !errors.Is(err, ErrCosignerEndpointAlreadyConfigured) || !strings.Contains(err.Error(), "--alias treasury") ||
			strings.Contains(err.Error(), "delete") {
			t.Fatalf("PrepareCosignerSetup() error = %v, want guidance to reuse treasury", err)
		}
	})
	t.Run("loopback and missing url", func(t *testing.T) {
		app := newEndpointTestApp(t, t.TempDir())
		target, err := app.ResolveCosignerSetupTarget(CosignerSetupRequest{URL: "ssh://127.0.0.1:2223"})
		if err != nil || target.SuggestedAlias != "cosigner-local" {
			t.Fatalf("target = %#v err = %v, want cosigner-local", target, err)
		}
		if _, err := app.ResolveCosignerSetupTarget(CosignerSetupRequest{}); !errors.Is(err, ErrCosignerEndpointURLRequired) {
			t.Fatalf("ResolveCosignerSetupTarget() error = %v, want %v", err, ErrCosignerEndpointURLRequired)
		}
	})
}
