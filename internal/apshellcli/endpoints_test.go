// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/endpointrefs"
	"github.com/aplane-algo/aplane/internal/engine"
)

func TestEndpointCreateSentryCommandWritesManualEndpoint(t *testing.T) {
	dataDir := t.TempDir()
	cfg := config.DefaultConfig()
	eng, err := engine.NewEngine("testnet")
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

	err = state.cmdEndpoints([]string{
		"create",
		"--alias", "sentry-local",
		"--endpoint", "ssh://127.0.0.1:2223",
		"--sentryport", "12270",
	}, nil)
	if err != nil {
		t.Fatalf("cmdEndpoints(create) error = %v", err)
	}
	rendered := out.String()
	if !strings.Contains(rendered, "Configured sentry endpoint sentry-local") ||
		!strings.Contains(rendered, "sentry port: 12270") ||
		!strings.Contains(rendered, "request-token --endpoint sentry-local") {
		t.Fatalf("output missing create details:\n%s", rendered)
	}

	cfg, err = config.LoadConfig(dataDir)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	endpoint, ok := cfg.Endpoints.Endpoint("sentry-local")
	if !ok {
		t.Fatal("sentry-local endpoint missing")
	}
	if endpoint.Role != config.ClientEndpointRoleSentry || endpoint.URL != "ssh://127.0.0.1:2223" || endpoint.SignerPort != 12270 {
		t.Fatalf("endpoint = %#v, want sentry ssh endpoint with signer_port 12270", endpoint)
	}
	if live, ok := state.Config.Endpoints.Endpoint("sentry-local"); !ok || live.URL != endpoint.URL {
		t.Fatalf("REPL config endpoint = %#v, %v; same-session request-token would not resolve sentry-local", live, ok)
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
	envelopePath := filepath.Join(dataDir, "sentry.endpoint.json")
	if err := os.WriteFile(envelopePath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatal(err)
	}
	state := &REPLState{
		Out: &bytes.Buffer{}, App: apshellapp.New(eng, cfg, dataDir), DataDir: dataDir,
		Config: cfg, currentCommandCtx: context.Background(),
	}

	if err := state.cmdEndpoints([]string{
		"import", "--alias", "local-sentry", "--role", "sentry", envelopePath,
	}, nil); err != nil {
		t.Fatalf("cmdEndpoints(import) error = %v", err)
	}
	endpoint, ok := state.Config.Endpoints.Endpoint("local-sentry")
	if !ok || endpoint.Role != config.ClientEndpointRoleSentry || endpoint.URL != "ssh://127.0.0.1:2223" {
		t.Fatalf("REPL config endpoint = %#v, %v; same-session request-token would not resolve local-sentry", endpoint, ok)
	}
}

func TestParseEndpointCreateSentryArgsAcceptsHyphenatedPortFlag(t *testing.T) {
	req, err := parseEndpointCreateSentryArgs([]string{
		"--alias", "sentry-local",
		"--endpoint", "ssh://127.0.0.1:2223",
		"--sentry-port", "12270",
		"--dry-run",
	})
	if err != nil {
		t.Fatalf("parseEndpointCreateSentryArgs() error = %v", err)
	}
	if req.Alias != "sentry-local" || req.URL != "ssh://127.0.0.1:2223" || req.SentryPort != 12270 || !req.DryRun {
		t.Fatalf("request = %#v, want parsed manual sentry endpoint", req)
	}
}

func TestEndpointsUsageListsDiscoverSentries(t *testing.T) {
	state := &REPLState{}
	registry := state.initCommandRegistry()
	cmd, ok := registry.Lookup("endpoints")
	if !ok {
		t.Fatal("endpoints command is not registered")
	}
	if !strings.Contains(cmd.Usage, "endpoints discover-sentries") || strings.Contains(cmd.Usage, "discover-sentries [--dry-run]") {
		t.Fatalf("endpoints registry usage = %q, want discover-sentries", cmd.Usage)
	}
	if strings.Contains(cmd.Usage, "sync-sentries") {
		t.Fatalf("endpoints registry usage = %q, contains retired sync-sentries", cmd.Usage)
	}

	err := state.cmdEndpoints(nil, nil)
	if err == nil {
		t.Fatal("cmdEndpoints() error = nil, want usage")
	}
	if !strings.Contains(err.Error(), "endpoints discover-sentries") {
		t.Fatalf("cmdEndpoints() error = %q, want discover-sentries", err)
	}
}

func TestRenderEndpointShowContainsConnectionStateOnly(t *testing.T) {
	var out bytes.Buffer
	state := &REPLState{Out: &out}
	state.renderEndpointShow(&apshellapp.EndpointShowResult{
		Endpoint: apshellapp.EndpointEntry{
			Alias: "sentry-local",
			Role:  config.ClientEndpointRoleSentry,
			URL:   "ssh://127.0.0.1:2223",
		},
	})
	rendered := out.String()
	if strings.Contains(rendered, "Published sentries") || strings.Contains(rendered, "SENTRY KEY") || strings.Contains(rendered, "LAST SEEN") {
		t.Fatalf("rendered endpoint show = %q, want connection state only", rendered)
	}
}

func TestRenderEndpointsListOmitsCachedSentryInventory(t *testing.T) {
	var out bytes.Buffer
	state := &REPLState{Out: &out}

	state.renderEndpointsList(&apshellapp.EndpointsListResult{
		Endpoints: []apshellapp.EndpointEntry{{
			Alias: "sentry-local",
			Role:  config.ClientEndpointRoleSentry,
			URL:   "ssh://127.0.0.1:2223",
		}},
	})

	rendered := out.String()
	if strings.Contains(rendered, "SENTRY KEYS") || strings.Contains(rendered, "ATTESTORS") || strings.Contains(rendered, "COMPONENT") {
		t.Fatalf("rendered endpoint list header = %q, want no cached inventory columns", rendered)
	}
}
