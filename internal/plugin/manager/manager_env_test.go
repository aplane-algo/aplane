// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package manager

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/plugin/discovery"
	"github.com/aplane-algo/aplane/internal/plugin/manifest"
	"github.com/aplane-algo/aplane/internal/plugin/sandbox"
)

// envProbeScript records the environment it starts with and the initialize
// request it receives in its state directory, then answers every request.
const envProbeScript = `#!/bin/sh
env > "$APSHELL_PLUGIN_STATE_DIR/env"
while IFS= read -r line; do
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
  case "$line" in
  *'"method":"initialize"'*)
    printf '%s\n' "$line" > "$APSHELL_PLUGIN_STATE_DIR/initialize"
    printf '{"jsonrpc":"2.0","id":%s,"result":{"success":true,"protocol":"aplane-plugin/2"}}\n' "$id" ;;
  *)
    printf '{"jsonrpc":"2.0","id":%s,"result":{}}\n' "$id" ;;
  esac
done
`

// apshellEnvNames are the APSHELL_* names a plugin's environment is checked
// for, whether or not the host sets them.
var apshellEnvNames = []string{
	"APSHELL_NETWORK",
	"APSHELL_ALGOD_URL",
	"APSHELL_ALGOD_TOKEN",
	"APSHELL_INDEXER_URL",
	"APSHELL_PLUGIN",
	"APSHELL_PLUGIN_STATE_DIR",
}

// A real sandboxed plugin sees the host's environment, filtered, plus its state
// directory; the network and algod settings reach it in initialize.
func TestPluginStartsWithItsEnvironmentAndInitialize(t *testing.T) {
	base := sandboxedPluginBase(t)

	pluginDir := filepath.Join(base, "plugins", "env-probe")
	if err := os.MkdirAll(pluginDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "run.sh"), []byte(envProbeScript), 0o700); err != nil {
		t.Fatal(err)
	}

	for _, name := range apshellEnvNames {
		t.Setenv(name, "")
		_ = os.Unsetenv(name)
	}
	// An operator's own APSHELL_ALGOD_TOKEN, a manifest-declared setting, an
	// undeclared host variable, and a secret-shaped name.
	t.Setenv("APSHELL_ALGOD_TOKEN", "operator-token")
	t.Setenv("APLANE_ENV_PROBE_SETTING", "kept")
	t.Setenv("APLANE_ENV_PROBE_UNDECLARED", "stripped-undeclared")
	t.Setenv("APLANE_ENV_PROBE_TOKEN", "stripped")

	m := NewManagerWithDataDir(filepath.Join(base, "data"))
	m.SetConfig("localnet", "http://localhost:4001", "config-token")
	m.SetCachedPluginsForTest([]*discovery.Plugin{{
		Dir: pluginDir,
		Manifest: &manifest.Manifest{
			Name:       "env-probe",
			Executable: "run.sh",
			Env:        []string{"APLANE_ENV_PROBE_SETTING", "APLANE_ENV_PROBE_TOKEN"},
			Timeout:    10,
		},
	}})
	if _, err := m.StartPlugin(context.Background(), "env-probe"); err != nil {
		t.Fatalf("StartPlugin() error = %v", err)
	}
	defer m.StopAll()

	stateDir := filepath.Join(base, "data", "plugin-state", "env-probe")
	env := readEnvFile(t, filepath.Join(stateDir, "env"))

	// The operator's APSHELL_ALGOD_TOKEN is stripped like any secret-shaped
	// name.
	wantAPShell := map[string]string{"APSHELL_PLUGIN_STATE_DIR": stateDir}
	for _, name := range apshellEnvNames {
		got, gotOK := env[name]
		want, wantOK := wantAPShell[name]
		if got != want || gotOK != wantOK {
			t.Errorf("plugin env %s = %q (set %v), want %q (set %v)", name, got, gotOK, want, wantOK)
		}
	}
	if got := env["APLANE_ENV_PROBE_SETTING"]; got != "kept" {
		t.Errorf("plugin env APLANE_ENV_PROBE_SETTING = %q, want the operator's value", got)
	}
	if got, ok := env["APLANE_ENV_PROBE_UNDECLARED"]; ok {
		t.Errorf("plugin env APLANE_ENV_PROBE_UNDECLARED = %q, want it stripped", got)
	}
	if got, ok := env["APLANE_ENV_PROBE_TOKEN"]; ok {
		t.Errorf("plugin env APLANE_ENV_PROBE_TOKEN = %q, want it stripped", got)
	}

	raw, err := os.ReadFile(filepath.Join(stateDir, "initialize"))
	if err != nil {
		t.Fatalf("read the initialize request: %v", err)
	}
	var req struct {
		Params json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		t.Fatalf("decode the initialize request %s: %v", raw, err)
	}
	const wantParams = `{"network":"localnet","algodUrl":"http://localhost:4001","algodToken":"config-token"}`
	if got := string(req.Params); got != wantParams {
		t.Errorf("initialize params = %s, want %s", got, wantParams)
	}
}

// sandboxedPluginBase returns a directory for a sandboxed plugin's files, or
// skips the test where the plugin sandbox cannot run a script from it. The
// directory is outside /tmp, which the Linux sandbox replaces with an empty
// tmpfs; a noexec mount there skips the test.
func sandboxedPluginBase(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("runs a plugin in the Linux sandbox")
	}
	base, err := os.MkdirTemp("/var/tmp", "aplane-plugin-env-")
	if err != nil {
		t.Skipf("no directory outside /tmp for the plugin: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })

	probe := filepath.Join(base, "probe.sh")
	if err := os.WriteFile(probe, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	cmd, _, err := sandbox.BuildCommand(sandbox.Config{
		PluginName: "probe",
		PluginDir:  base,
		ExecPath:   probe,
		Env:        []string{"PATH=/usr/bin:/bin"},
	})
	if err != nil {
		t.Skipf("no plugin sandbox: %v", err)
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("the plugin sandbox cannot run here: %v: %s", err, out)
	}
	return base
}

// The host adds only the plugin's state directory to its own environment, after
// the operator's copy of the name so that the host's value is the one used.
func TestPluginEnvAddsOnlyTheStateDir(t *testing.T) {
	host := []string{"HOME=/home/operator", "APSHELL_PLUGIN_STATE_DIR=/operator-state"}

	env := pluginEnv(host, "/data/plugin-state/p")
	for _, name := range apshellEnvNames {
		value, ok := lastEnvValue(env, name)
		if name == "APSHELL_PLUGIN_STATE_DIR" {
			if value != "/data/plugin-state/p" {
				t.Errorf("plugin env %s = %q, want the host's", name, value)
			}
		} else if ok {
			t.Errorf("plugin env %s = %q, want it unset", name, value)
		}
	}
	if value, _ := lastEnvValue(env, "HOME"); value != "/home/operator" {
		t.Errorf("plugin env HOME = %q, want the operator's", value)
	}

	if got := pluginEnv([]string{"HOME=/home/operator"}, ""); len(got) != 1 {
		t.Errorf("plugin env without a state dir = %q, want the host's alone", got)
	}
}

// lastEnvValue reads env as exec does: the last entry for a name is the one
// used.
func lastEnvValue(env []string, name string) (string, bool) {
	for i := len(env) - 1; i >= 0; i-- {
		if key, value, ok := strings.Cut(env[i], "="); ok && key == name {
			return value, true
		}
	}
	return "", false
}

func readEnvFile(t *testing.T, path string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the plugin's environment: %v", err)
	}
	env := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if key, value, ok := strings.Cut(line, "="); ok {
			env[key] = value
		}
	}
	return env
}
