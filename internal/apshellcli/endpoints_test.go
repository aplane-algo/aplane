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

func TestEndpointMachineProjectionOmitsLocalPortForCosignerRole(t *testing.T) {
	projection := projectEndpointEntry(apshellapp.EndpointEntry{
		Alias: "cosigner", Role: config.ClientEndpointRoleCosigner,
		URL: "ssh://cosigner.example:22", LocalPort: 12271,
	})
	data, err := json.Marshal(projection)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("local_port")) {
		t.Fatalf("machine cosigner endpoint projection contains local_port: %s", data)
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
		Config:            cfg,
		currentCommandCtx: context.Background(),
	}

	result, err := state.cmdEndpoints([]string{
		"create",
		"--alias", "cosigner-local",
		"--endpoint", "ssh://127.0.0.1:2223",
		"--cosignerport", "12270",
	}, nil)
	if err != nil {
		t.Fatalf("cmdEndpoints(create) error = %v", err)
	}
	if err := result.RenderText(state.Out); err != nil {
		t.Fatalf("RenderText() error = %v", err)
	}
	rendered := out.String()
	if !strings.Contains(rendered, "Configured cosigner endpoint cosigner-local") ||
		!strings.Contains(rendered, "cosigner port: 12270") ||
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
	if endpoint.Role != config.ClientEndpointRoleCosigner || endpoint.URL != "ssh://127.0.0.1:2223" || endpoint.SignerPort != 12270 {
		t.Fatalf("endpoint = %#v, want cosigner ssh endpoint with signer_port 12270", endpoint)
	}
	if live, ok := state.Config.Endpoints.Endpoint("cosigner-local"); !ok || live.URL != endpoint.URL {
		t.Fatalf("REPL config endpoint = %#v, %v; same-session request-token would not resolve cosigner-local", live, ok)
	}
}

func TestEndpointImportCommandRefreshesREPLConfig(t *testing.T) {
	dataDir := t.TempDir()
	data, err := endpointrefs.Marshal(endpointrefs.Envelope{
		Schema: endpointrefs.Schema, URL: "ssh://127.0.0.1:2223", SignerPort: 12270,
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
		Config: cfg, currentCommandCtx: context.Background(),
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
	endpoint, ok := state.Config.Endpoints.Endpoint("local-cosigner")
	if !ok || endpoint.Role != config.ClientEndpointRoleCosigner || endpoint.URL != "ssh://127.0.0.1:2223" {
		t.Fatalf("REPL config endpoint = %#v, %v; same-session request-token would not resolve local-cosigner", endpoint, ok)
	}
}

func TestParseEndpointCreateCosignerArgsAcceptsHyphenatedPortFlag(t *testing.T) {
	req, err := parseEndpointCreateCosignerArgs([]string{
		"--alias", "cosigner-local",
		"--endpoint", "ssh://127.0.0.1:2223",
		"--cosigner-port", "12270",
		"--dry-run",
	})
	if err != nil {
		t.Fatalf("parseEndpointCreateCosignerArgs() error = %v", err)
	}
	if req.Alias != "cosigner-local" || req.URL != "ssh://127.0.0.1:2223" || req.CosignerPort != 12270 || !req.DryRun {
		t.Fatalf("request = %#v, want parsed manual cosigner endpoint", req)
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
