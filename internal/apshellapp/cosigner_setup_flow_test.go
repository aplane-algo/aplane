// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/aplane-algo/aplane/internal/sshtunnel/sshtest"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/witness"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// newRecordingEndpoint starts a fake node of the given role advertising keys.
func newRecordingEndpoint(t *testing.T, nodeRole string, keys []signerapi.KeyInfo) *sshtest.Node {
	t.Helper()
	return sshtest.Serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			server := newRecordingEndpoint(t, tt.nodeRole, keys)
			writeLiveCosignerEndpoint(t, dataDir, "field", server)
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
		server := sshtest.Serve(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "boom", http.StatusInternalServerError)
		}))
		writeLiveCosignerEndpoint(t, dataDir, "field", server)
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
	server := newRecordingEndpoint(t, "cosigner", []signerapi.KeyInfo{advertisedWitness(reference)})
	writeLiveCosignerEndpoint(t, dataDir, "field", server)
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
		server := newRecordingEndpoint(t, "cosigner", keys)
		writeCosignerEndpointURL(t, dataDir, "elsewhere", "ssh://127.0.0.1:1")
		writeLiveCosignerEndpoint(t, dataDir, "field", server)

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
		first := newRecordingEndpoint(t, "cosigner", keys)
		// The created connection uses the client's default identity, which
		// the second node is started with.
		second := sshtest.ServeWithOptions(t, endpointRoleKeysHandler("cosigner", keys), sshtest.Options{Dir: filepath.Join(dataDir, ".ssh")})
		writeLiveCosignerEndpoint(t, dataDir, "first", first)
		app := newEndpointTestApp(t, dataDir)
		plan, err := app.PrepareCosignerSetup(CosignerSetupRequest{Alias: "second", URL: second.URL})
		if err != nil {
			t.Fatal(err)
		}
		endpoint, err := app.ApplyCosignerSetupEndpoint(plan, false)
		if err != nil {
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
	})

	t.Run("existing connections are not removable", func(t *testing.T) {
		dataDir := t.TempDir()
		server := newRecordingEndpoint(t, "cosigner", keys)
		writeLiveCosignerEndpoint(t, dataDir, "field", server)
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
