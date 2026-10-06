// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/endpointrefs"
)

func TestEndpointMachineProjectionOmitsCredentialPaths(t *testing.T) {
	projection := projectEndpointEntry(apshellapp.EndpointEntry{
		Alias: "remote", Role: "signer", URL: "ssh://signer.example:22",
		IdentityFile: "/secret/id", KnownHostsPath: "/secret/known_hosts",
		TokenFile: "/secret/token", TokenPresent: true,
	})
	data, err := json.Marshal(projection)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"identity", "known_hosts", "token_file", "/secret/"} {
		if bytes.Contains(data, []byte(forbidden)) {
			t.Fatalf("machine endpoint projection contains %q: %s", forbidden, data)
		}
	}
}

func TestEndpointCreateCosignerCommandWritesManualEndpoint(t *testing.T) {
	dataDir := t.TempDir()
	cfg := config.DefaultConfig()
	eng, err := newIsolatedTestEngine(t, "testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	var out bytes.Buffer
	state := &REPLState{
		Out:               &out,
		App:               apshellapp.New(eng, cfg, dataDir),
		DataDir:           dataDir,
		currentCommandCtx: context.Background(),
	}

	result, err := state.cmdEndpoints([]string{
		"create",
		"--alias", "cosigner-local",
		"--endpoint", "ssh://127.0.0.1:2223",
	}, nil)
	if err != nil {
		t.Fatalf("cmdEndpoints(create) error = %v", err)
	}
	if err := result.RenderText(state.Out); err != nil {
		t.Fatalf("RenderText() error = %v", err)
	}
	rendered := out.String()
	if !strings.Contains(rendered, "Configured cosigner endpoint cosigner-local") ||
		strings.Contains(rendered, "port:") ||
		!strings.Contains(rendered, "request-token --endpoint cosigner-local") {
		t.Fatalf("output missing create details:\n%s", rendered)
	}

	cfg, err = config.LoadConfig(dataDir)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	endpoint, ok := cfg.Endpoints.Endpoint("cosigner-local")
	if !ok {
		t.Fatal("cosigner-local endpoint missing")
	}
	if endpoint.Role != config.ClientEndpointRoleCosigner || endpoint.URL != "ssh://127.0.0.1:2223" {
		t.Fatalf("endpoint = %#v, want cosigner ssh endpoint", endpoint)
	}
	if live, ok := state.App.Config.Endpoints.Endpoint("cosigner-local"); !ok || live.URL != endpoint.URL {
		t.Fatalf("REPL config endpoint = %#v, %v; same-session request-token would not resolve cosigner-local", live, ok)
	}
}

func TestEndpointImportCommandRefreshesREPLConfig(t *testing.T) {
	dataDir := t.TempDir()
	data, err := endpointrefs.Marshal(endpointrefs.Envelope{
		Schema: endpointrefs.Schema, URL: "ssh://127.0.0.1:2223",
	})
	if err != nil {
		t.Fatal(err)
	}
	envelopePath := filepath.Join(dataDir, "cosigner.endpoint.json")
	if err := os.WriteFile(envelopePath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	eng, err := newIsolatedTestEngine(t, "testnet")
	if err != nil {
		t.Fatal(err)
	}
	state := &REPLState{
		Out: &bytes.Buffer{}, App: apshellapp.New(eng, cfg, dataDir), DataDir: dataDir,
		currentCommandCtx: context.Background(),
	}

	result, err := state.cmdEndpoints([]string{
		"import", "--alias", "local-cosigner", "--role", "cosigner", envelopePath,
	}, nil)
	if err != nil {
		t.Fatalf("cmdEndpoints(import) error = %v", err)
	}
	if err := result.RenderText(state.Out); err != nil {
		t.Fatalf("RenderText() error = %v", err)
	}
	endpoint, ok := state.App.Config.Endpoints.Endpoint("local-cosigner")
	if !ok || endpoint.Role != config.ClientEndpointRoleCosigner || endpoint.URL != "ssh://127.0.0.1:2223" {
		t.Fatalf("REPL config endpoint = %#v, %v; same-session request-token would not resolve local-cosigner", endpoint, ok)
	}
}

func TestEndpointsUsageListsDiscoverCosigners(t *testing.T) {
	state := &REPLState{}
	registry := state.initCommandRegistry()
	cmd, ok := registry.Lookup("endpoints")
	if !ok {
		t.Fatal("endpoints command is not registered")
	}
	if !strings.Contains(cmd.Usage, "endpoints discover-cosigners") || strings.Contains(cmd.Usage, "discover-cosigners [--dry-run]") {
		t.Fatalf("endpoints registry usage = %q, want discover-cosigners", cmd.Usage)
	}
	if strings.Contains(cmd.Usage, "sync-cosigners") {
		t.Fatalf("endpoints registry usage = %q, contains retired sync-cosigners", cmd.Usage)
	}

	_, err := state.cmdEndpoints(nil, nil)
	if err == nil {
		t.Fatal("cmdEndpoints() error = nil, want usage")
	}
	if !strings.Contains(err.Error(), "endpoints discover-cosigners") {
		t.Fatalf("cmdEndpoints() error = %q, want discover-cosigners", err)
	}
}

func TestRenderEndpointShowContainsConnectionStateOnly(t *testing.T) {
	var out bytes.Buffer
	state := &REPLState{Out: &out}
	state.renderEndpointShow(&apshellapp.EndpointShowResult{
		Endpoint: apshellapp.EndpointEntry{
			Alias: "cosigner-local",
			Role:  config.ClientEndpointRoleCosigner,
			URL:   "ssh://127.0.0.1:2223",
		},
	})
	rendered := out.String()
	if strings.Contains(rendered, "Published cosigners") || strings.Contains(rendered, "COSIGNER KEY") || strings.Contains(rendered, "LAST SEEN") {
		t.Fatalf("rendered endpoint show = %q, want connection state only", rendered)
	}
}

func TestRenderEndpointsListOmitsCachedCosignerInventory(t *testing.T) {
	var out bytes.Buffer
	state := &REPLState{Out: &out}

	state.renderEndpointsList(&apshellapp.EndpointsListResult{
		Endpoints: []apshellapp.EndpointEntry{{
			Alias: "cosigner-local",
			Role:  config.ClientEndpointRoleCosigner,
			URL:   "ssh://127.0.0.1:2223",
		}},
	})

	rendered := out.String()
	if strings.Contains(rendered, "COSIGNER KEYS") || strings.Contains(rendered, "ATTESTORS") || strings.Contains(rendered, "COMPONENT") {
		t.Fatalf("rendered endpoint list header = %q, want no cached inventory columns", rendered)
	}
}

// TestEndpointAliasCommandsSeeEndpointsAddedElsewhere covers an endpoint that
// another process adds after this shell started: once the shell has read the
// registry, alias lookups and guarded routing must see the same endpoints.
func TestEndpointAliasCommandsSeeEndpointsAddedElsewhere(t *testing.T) {
	dataDir := t.TempDir()
	cfg := config.DefaultConfig()
	eng, err := newIsolatedTestEngine(t, "testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	state := &REPLState{
		Out: &bytes.Buffer{}, App: apshellapp.New(eng, cfg, dataDir), DataDir: dataDir,
		currentCommandCtx: context.Background(),
	}
	other := apshellapp.New(eng, cfg, dataDir)
	if _, err := other.EndpointCreateCosigner(context.Background(), apshellapp.EndpointCreateCosignerRequest{
		Alias: "added", URL: "ssh://127.0.0.1:2223",
	}); err != nil {
		t.Fatal(err)
	}
	eng.EndpointRegistry = config.ClientEndpointRegistry{}

	if _, err := state.cmdEndpoints([]string{"list"}, nil); err != nil {
		t.Fatalf("cmdEndpoints(list) error = %v", err)
	}
	if _, err := state.App.ResolveTokenRequestTarget("added"); err != nil {
		t.Fatalf("alias listed by endpoints list is unknown to request-token: %v", err)
	}
	if _, ok := eng.EndpointRegistry.Endpoint("added"); !ok {
		t.Fatal("endpoints list left the engine's routing registry without the listed endpoint")
	}
}

func TestEndpointArgParsersShareFlagRules(t *testing.T) {
	importArgs := []string{"--alias", "a", "--role", "signer", "env.json"}
	createArgs := []string{"--alias", "a", "--endpoint", "ssh://h:22"}
	parse := map[string]func([]string) error{
		"import": func(args []string) error { _, err := parseEndpointImportArgs(args); return err },
		"create": func(args []string) error { _, err := parseEndpointCreateCosignerArgs(args); return err },
	}
	base := map[string][]string{"import": importArgs, "create": createArgs}
	for name, run := range parse {
		args := base[name]
		if err := run(append(append([]string{}, args...), "--dry-run")); err != nil {
			t.Errorf("%s with --dry-run: %v", name, err)
		}
		for label, bad := range map[string][]string{
			"repeated --dry-run": append(append([]string{}, args...), "--dry-run", "--dry-run"),
			"repeated --alias":   append(append([]string{}, args...), "--alias", "b"),
			"missing value":      append(append([]string{}, args...), "--alias"),
			"flag as value":      {"--alias", "--dry-run"},
		} {
			if err := run(bad); err == nil || !strings.HasPrefix(err.Error(), "usage: endpoints "+name) {
				t.Errorf("%s %s: error = %v, want usage", name, label, err)
			}
		}
		if err := run(append(append([]string{}, args...), "--bogus")); err == nil ||
			err.Error() != `unknown endpoints `+name+` flag "--bogus"` {
			t.Errorf("%s unknown flag: error = %v", name, err)
		}
	}
	// The cosigner port was retired: the node's SSH server forwards to its
	// own REST listener, so the client never chose it.
	if err := parse["create"]([]string{"--alias", "a", "--endpoint", "ssh://h:22", "--cosignerport", "12270"}); err == nil ||
		!strings.Contains(err.Error(), "--cosignerport") {
		t.Errorf("create accepted the retired --cosignerport flag: %v", err)
	}
}
