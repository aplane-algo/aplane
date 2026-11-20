// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
	eng := newIsolatedTestEngine(t, "testnet")
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
		!strings.Contains(rendered, "enroll --endpoint cosigner-local") {
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
		t.Fatalf("REPL config endpoint = %#v, %v; same-session enroll would not resolve cosigner-local", live, ok)
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
	eng := newIsolatedTestEngine(t, "testnet")
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
		t.Fatalf("REPL config endpoint = %#v, %v; same-session enroll would not resolve local-cosigner", endpoint, ok)
	}
}

// What MCP clients read back from the endpoints subcommands: the signer
// endpoint is marked as the default in a listing. There is no default to
// set, so endpoints default is an unknown subcommand.
func TestEndpointCommandMachineResults(t *testing.T) {
	dataDir := t.TempDir()
	data, err := endpointrefs.Marshal(endpointrefs.Envelope{Schema: endpointrefs.Schema, URL: "ssh://127.0.0.1:2223"})
	if err != nil {
		t.Fatal(err)
	}
	envelopePath := filepath.Join(dataDir, "signer.endpoint.json")
	if err := os.WriteFile(envelopePath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	state := &REPLState{
		Out: &bytes.Buffer{}, App: apshellapp.New(newIsolatedTestEngine(t, "testnet"), config.DefaultConfig(), dataDir),
		DataDir: dataDir, currentCommandCtx: context.Background(),
	}
	machine := func(args ...string) string {
		t.Helper()
		result, err := state.cmdEndpoints(args, nil)
		if err != nil {
			t.Fatalf("cmdEndpoints(%v) error = %v", args, err)
		}
		out, err := result.MarshalMachine()
		if err != nil {
			t.Fatal(err)
		}
		return string(out)
	}
	steps := []struct {
		args []string
		want string
	}{
		{[]string{"import", "--alias", "main", "--role", "signer", envelopePath},
			`{"mode":"import","alias":"main","role":"signer","url":"ssh://127.0.0.1:2223","created":true}`},
		{[]string{"create", "--alias", "cos", "--endpoint", "ssh://127.0.0.1:3333"},
			`{"mode":"create","alias":"cos","role":"cosigner","url":"ssh://127.0.0.1:3333","created":true}`},
		{[]string{"list"},
			`[{"alias":"cos","role":"cosigner","url":"ssh://127.0.0.1:3333","default":false},{"alias":"main","role":"signer","url":"ssh://127.0.0.1:2223","default":true}]`},
		{[]string{"show", "main"}, `{"alias":"main","role":"signer","url":"ssh://127.0.0.1:2223","default":true}`},
		{[]string{"delete", "cos"}, `{"mode":"delete","alias":"cos","deleted":true}`},
	}
	for _, step := range steps {
		if got := machine(step.args...); got != step.want {
			t.Fatalf("endpoints %v machine result = %s, want %s", step.args, got, step.want)
		}
	}
	if _, err := state.cmdEndpoints([]string{"default", "main"}, nil); err == nil || err.Error() != `unknown endpoints subcommand "default"` {
		t.Fatalf("endpoints default error = %v, want an unknown subcommand", err)
	}
}

// No endpoints writer turns the signer endpoint into a cosigner endpoint,
// from the shell or over MCP, and a refused write leaves endpoints.yaml as
// it was. Moving the signer endpoint to another URL still works.
func TestEndpointWritersRefuseChangingTheSignerRole(t *testing.T) {
	const registry = "schema_version: 2\nendpoints:\n  primary:\n    role: signer\n    url: ssh://127.0.0.1:2223\n"
	const roleRefusal = `endpoint alias "primary" is the signer endpoint; it cannot become a cosigner endpoint`
	newState := func(t *testing.T) (*REPLState, string, string) {
		t.Helper()
		dataDir := t.TempDir()
		if err := os.WriteFile(config.GetClientEndpointsPath(dataDir), []byte(registry), 0o600); err != nil {
			t.Fatal(err)
		}
		data, err := endpointrefs.Marshal(endpointrefs.Envelope{Schema: endpointrefs.Schema, URL: "ssh://127.0.0.1:4444"})
		if err != nil {
			t.Fatal(err)
		}
		envelopePath := filepath.Join(dataDir, "moved.endpoint.json")
		if err := os.WriteFile(envelopePath, data, 0o600); err != nil {
			t.Fatal(err)
		}
		state := &REPLState{
			Out: &bytes.Buffer{}, App: apshellapp.New(newIsolatedTestEngine(t, "testnet"), config.DefaultConfig(), dataDir),
			DataDir: dataDir, currentCommandCtx: context.Background(), AutoConfirm: true,
		}
		state.CommandRegistry = state.initCommandRegistry()
		return state, dataDir, envelopePath
	}
	shell := func(state *REPLState, args []string) error {
		_, err := state.cmdEndpoints(args, nil)
		return err
	}
	overMCP := func(state *REPLState, args []string) error {
		result := mcpExecuteCommand(state, Command{Name: "endpoints", Args: args})
		if !result.IsError {
			return nil
		}
		return errors.New(mcpResultText(t, result))
	}
	tests := []struct {
		name    string
		run     func(*REPLState, []string) error
		args    func(envelope string) []string
		wantErr string
	}{
		{"create", shell, func(string) []string {
			return []string{"create", "--alias", "primary", "--endpoint", "ssh://127.0.0.1:4444"}
		}, roleRefusal},
		{"create over MCP", overMCP, func(string) []string {
			return []string{"create", "--alias", "primary", "--endpoint", "ssh://127.0.0.1:4444"}
		}, roleRefusal},
		{"import", shell, func(envelope string) []string {
			return []string{"import", "--alias", "primary", "--role", "cosigner", envelope}
		}, roleRefusal},
		{"import over MCP", overMCP, func(envelope string) []string {
			return []string{"import", "--alias", "primary", "--role", "cosigner", envelope}
		}, roleRefusal},
		{"add", shell, func(string) []string {
			return []string{"add", "ssh://127.0.0.1:4444", "--alias", "primary", "--replace"}
		}, `endpoint alias "primary" has role "signer"; choose a cosigner alias`},
		{"add over MCP", overMCP, func(string) []string {
			return []string{"add", "ssh://127.0.0.1:4444", "--alias", "primary", "--replace"}
		}, "endpoints add is unavailable through MCP; use apshell directly"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state, dataDir, envelope := newState(t)
			if err := tt.run(state, tt.args(envelope)); err == nil || err.Error() != tt.wantErr {
				t.Fatalf("endpoints %v error = %v, want %q", tt.args(envelope), err, tt.wantErr)
			}
			data, err := os.ReadFile(config.GetClientEndpointsPath(dataDir))
			if err != nil || string(data) != registry {
				t.Fatalf("a refused write changed endpoints.yaml: %q, %v", data, err)
			}
		})
	}

	for name, run := range map[string]func(*REPLState, []string) error{"shell": shell, "MCP": overMCP} {
		t.Run("move the signer endpoint over "+name, func(t *testing.T) {
			state, _, envelope := newState(t)
			if err := run(state, []string{"import", "--alias", "primary", "--role", "signer", envelope}); err != nil {
				t.Fatalf("endpoints import of the signer endpoint at a new URL: %v", err)
			}
			if alias, endpoint, _ := state.App.Config.Endpoints.SignerEndpoint(); alias != "primary" || endpoint.URL != "ssh://127.0.0.1:4444" {
				t.Fatalf("SignerEndpoint() after the move = %q, %+v", alias, endpoint)
			}
		})
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
// registry, alias lookups and cosigned routing must see the same endpoints.
func TestEndpointAliasCommandsSeeEndpointsAddedElsewhere(t *testing.T) {
	dataDir := t.TempDir()
	cfg := config.DefaultConfig()
	eng := newIsolatedTestEngine(t, "testnet")
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
	if _, err := state.App.ResolveEnrollmentTarget("added"); err != nil {
		t.Fatalf("alias listed by endpoints list is unknown to enroll: %v", err)
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

func TestEndpointPublicKeyProjectionOmitsCredentialPaths(t *testing.T) {
	data, err := json.Marshal(endpointPublicKeyProjection{
		Alias: "main", PublicKey: "ssh-ed25519 AAAA", Fingerprint: "SHA256:abc",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"identity", ".ssh", "/secret/"} {
		if bytes.Contains(data, []byte(forbidden)) {
			t.Fatalf("projection %s contains %q", data, forbidden)
		}
	}
}
