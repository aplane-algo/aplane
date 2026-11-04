// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/plugin/integrity"
)

// noisyPlugin logs to stderr as it works, and can crash on request.
const noisyPlugin = `#!/usr/bin/python3
import json, sys
def log(s):
    sys.stderr.write(s + "\n"); sys.stderr.flush()
log("plugin started")
for raw in sys.stdin:
    req = json.loads(raw)
    method, params = req.get("method"), req.get("params") or {}
    if method == "initialize":
        result = {"success": True, "protocol": "aplane-plugin/2"}
    elif method == "execute":
        log("working on " + params.get("command", ""))
        if params.get("command") == "crash":
            log("cannot find module foo")
            sys.exit(1)
        result = {"success": True, "message": "PLUGIN RESULT"}
    else:
        result = {"success": True}
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": req.get("id"), "result": result}) + "\n")
    sys.stdout.flush()
    if method == "shutdown":
        break
`

const noisyManifest = `{"name": "noisy", "version": "1.0.0", "description": "logs to stderr", "executable": "./noisy.py",
 "commands": [{"name": "noisy", "description": "work", "usage": "noisy"},
              {"name": "crash", "description": "fail", "usage": "crash"}],
 "networks": ["testnet"], "timeout": 10, "manifest_format": "2.0"}`

const outputTestConfig = `network: testnet
networks:
  testnet:
    algod:
      server: http://127.0.0.1:1
      token: "x"
`

// buildApshell builds the real binary once for the calling test.
func buildApshell(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "apshell")
	if output, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, output)
	}
	return binary
}

// outputDataDir returns a cold client data directory. It sits under the working
// directory rather than the system temp directory, because the plugin sandbox
// mounts a tmpfs over /tmp, which would hide a plugin stored there.
func outputDataDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp(".", ".client-output-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	abs, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(abs, "config.yaml"), []byte(outputTestConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	return abs
}

func installNoisyPlugin(t *testing.T, dataDir string) {
	t.Helper()
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("plugins need bubblewrap")
	}
	if _, err := os.Stat("/usr/bin/python3"); err != nil {
		t.Skip("the test plugin needs /usr/bin/python3")
	}
	if strings.HasPrefix(dataDir, "/tmp/") {
		t.Skip("the plugin sandbox hides /tmp, where this checkout is")
	}
	pluginDir := filepath.Join(dataDir, "plugins.available", "noisy")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "noisy.py"), []byte(noisyPlugin), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "manifest.json"), []byte(noisyManifest), 0o644); err != nil {
		t.Fatal(err)
	}
	checksums, err := integrity.GenerateChecksums(pluginDir, []string{"manifest.json", "noisy.py"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "checksums.sha256"), []byte(checksums), 0o644); err != nil {
		t.Fatal(err)
	}
	activation := []byte("enabled_plugins:\n  - noisy\n")
	if err := os.WriteFile(filepath.Join(dataDir, "plugins.yaml"), activation, 0o644); err != nil {
		t.Fatal(err)
	}
}

// runScript runs commands through apshell --script and returns the two streams.
func runScript(t *testing.T, binary, dataDir string, commands ...string) (stdout, stderr string) {
	t.Helper()
	script := filepath.Join(t.TempDir(), "commands.txt")
	if err := os.WriteFile(script, []byte(strings.Join(commands, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "-n", "testnet", "--script", script)
	cmd.Dir = t.TempDir()
	cmd.Env = append(os.Environ(), "APCLIENT_DATA="+dataDir, "APSHELL_DEBUG=")
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	_ = cmd.Run() // A failing script is one of the cases under test.
	return out.String(), errOut.String()
}

func assertContains(t *testing.T, stream, got string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(got, want) {
			t.Fatalf("%s = %q, want %q", stream, got, want)
		}
	}
}

func assertOmits(t *testing.T, stream, got string, unwanted ...string) {
	t.Helper()
	for _, s := range unwanted {
		if strings.Contains(got, s) {
			t.Fatalf("%s = %q, must not contain %q", stream, got, s)
		}
	}
}

func TestColdStartKeepsDiagnosticsOffStdout(t *testing.T) {
	binary := buildApshell(t)
	dataDir := outputDataDir(t)

	stdout, stderr := runScript(t, binary, dataDir,
		"alias probe AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ")

	assertContains(t, "stdout", stdout, "Added alias: probe")
	assertOmits(t, "stdout", stdout, "msg=", "cache integrity", "[cache]")
	if stderr != "" {
		t.Fatalf("stderr = %q, want nothing at the default level", stderr)
	}
}

func TestPluginOutputGoesToStderrOnlyWhenAskedFor(t *testing.T) {
	binary := buildApshell(t)
	dataDir := outputDataDir(t)
	installNoisyPlugin(t, dataDir)

	t.Run("hidden by default", func(t *testing.T) {
		stdout, stderr := runScript(t, binary, dataDir, "noisy")
		assertContains(t, "stdout", stdout, "PLUGIN RESULT")
		assertOmits(t, "stdout", stdout, "plugin started", "working on")
		if stderr != "" {
			t.Fatalf("stderr = %q, want nothing at the default level", stderr)
		}
	})

	t.Run("verbose does not show it", func(t *testing.T) {
		_, stderr := runScript(t, binary, dataDir, "verbose on", "noisy")
		if stderr != "" {
			t.Fatalf("stderr = %q, verbose is signing detail only", stderr)
		}
	})

	t.Run("shown on stderr at info", func(t *testing.T) {
		stdout, stderr := runScript(t, binary, dataDir, "loglevel info", "noisy")
		assertContains(t, "stdout", stdout, "PLUGIN RESULT")
		assertOmits(t, "stdout", stdout, "plugin started", "[plugin")
		assertContains(t, "stderr", stderr,
			"[plugin noisy] Running in sandbox", "[plugin noisy stderr] working on noisy")
	})

	t.Run("a failure replays what was hidden", func(t *testing.T) {
		stdout, stderr := runScript(t, binary, dataDir, "crash")
		assertContains(t, "stdout", stdout, "Error on line 1")
		assertOmits(t, "stdout", stdout, "cannot find module")
		assertContains(t, "stderr", stderr, "[plugin noisy stderr] warning: cannot find module foo")
	})
}
