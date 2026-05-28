// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sandbox

import (
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestFilterEnv(t *testing.T) {
	input := []string{
		"HOME=/home/user",
		"PATH=/usr/bin:/usr/local/bin:/home/user/.nvm/bin:/sbin",
		"AWS_ACCESS_KEY_ID=secret123",
		"AWS_SECRET_ACCESS_KEY=secret456",
		"GITHUB_TOKEN=ghp_xxx",
		"GH_TOKEN=gho_xxx",
		"NPM_TOKEN=npm_xxx",
		"SSH_AUTH_SOCK=/tmp/ssh-agent",
		"SSH_AGENT_PID=1234",
		"GPG_AGENT_INFO=/tmp/gpg",
		"LANG=en_US.UTF-8",
		"TERM=xterm",
		"AWS_SESSION_TOKEN=session_xxx",
		"OPENAI_API_KEY=openai_xxx",
		"ANTHROPIC_API_KEY=anthropic_xxx",
		"GOOGLE_API_KEY=google_xxx",
		"CUSTOM_API_KEY=custom_xxx",
		"SERVICE_TOKEN=service_xxx",
		"LOCAL_SECRET=local_xxx",
		"DATABASE_PASSWORD=hunter2",
		"APSHELL_ALGOD_TOKEN=intentional_plugin_token",
	}

	result := filterEnv(input)

	// Build lookup
	envMap := make(map[string]string)
	for _, e := range result {
		parts := strings.SplitN(e, "=", 2)
		envMap[parts[0]] = parts[1]
	}

	// Sensitive vars should be excluded
	excluded := []string{
		"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
		"GITHUB_TOKEN", "GH_TOKEN", "NPM_TOKEN",
		"SSH_AUTH_SOCK", "SSH_AGENT_PID", "GPG_AGENT_INFO",
		"OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY",
		"CUSTOM_API_KEY", "SERVICE_TOKEN", "LOCAL_SECRET", "DATABASE_PASSWORD",
	}
	for _, key := range excluded {
		if _, exists := envMap[key]; exists {
			t.Errorf("filterEnv should exclude %s", key)
		}
	}

	// Safe vars should remain
	if envMap["HOME"] != "/home/user" {
		t.Error("filterEnv should keep HOME")
	}
	if envMap["LANG"] != "en_US.UTF-8" {
		t.Error("filterEnv should keep LANG")
	}
	if envMap["TERM"] != "xterm" {
		t.Error("filterEnv should keep TERM")
	}
	if envMap["APSHELL_ALGOD_TOKEN"] != "intentional_plugin_token" {
		t.Error("filterEnv should keep APSHELL plugin runtime variables")
	}
}

func TestFilterEnvPathSanitization(t *testing.T) {
	input := []string{
		"PATH=/usr/bin:/usr/local/bin:/home/user/.nvm/bin:/sbin:/lib/custom:/opt/custom",
	}

	result := filterEnv(input)

	var pathValue string
	for _, e := range result {
		if strings.HasPrefix(e, "PATH=") {
			pathValue = strings.TrimPrefix(e, "PATH=")
			break
		}
	}

	if pathValue == "" {
		t.Fatal("filterEnv should include PATH")
	}

	dirs := strings.Split(pathValue, ":")

	// Should include sandbox-visible paths
	sandboxVisible := map[string]bool{
		"/usr/bin":       false,
		"/usr/local/bin": false,
		"/sbin":          false,
	}
	for _, dir := range dirs {
		sandboxVisible[dir] = true
	}
	for dir, found := range sandboxVisible {
		if !found {
			t.Errorf("PATH should include %s", dir)
		}
	}

	// Should exclude non-sandbox paths
	for _, dir := range dirs {
		if strings.Contains(dir, ".nvm") || strings.HasPrefix(dir, "/opt") {
			t.Errorf("PATH should not include %s", dir)
		}
	}
}

func TestFilterEnvEmpty(t *testing.T) {
	result := filterEnv(nil)
	if len(result) != 0 {
		t.Errorf("filterEnv(nil) should return empty, got %d", len(result))
	}

	result = filterEnv([]string{})
	if len(result) != 0 {
		t.Errorf("filterEnv([]) should return empty, got %d", len(result))
	}
}

func TestGenerateSeatbeltProfile(t *testing.T) {
	cfg := Config{
		PluginDir:    "/opt/plugins/myplugin",
		ExecPath:     "/opt/plugins/myplugin/run",
		AllowNetwork: true,
	}

	profile := generateSeatbeltProfile(cfg)

	// Should start with version and deny default
	if !strings.Contains(profile, "(version 1)") {
		t.Error("profile should contain (version 1)")
	}
	if !strings.Contains(profile, "(deny default)") {
		t.Error("profile should contain (deny default)")
	}

	// Should allow reading root and system libraries
	if !strings.Contains(profile, `(literal "/")`) {
		t.Error("profile should allow root literal \"/\" (required by libuv/CoreFoundation init)")
	}
	if !strings.Contains(profile, "/usr/lib") {
		t.Error("profile should allow /usr/lib")
	}
	if !strings.Contains(profile, "/System/Library") {
		t.Error("profile should allow /System/Library")
	}

	// Should allow plugin directory read access
	if !strings.Contains(profile, cfg.PluginDir) {
		t.Error("profile should allow plugin directory")
	}

	// Should allow network when configured
	if !strings.Contains(profile, "(allow network*)") {
		t.Error("profile should allow network when AllowNetwork=true")
	}

	// Should allow file-read-metadata (required for HTTPS fetch / DNS stat calls)
	if !strings.Contains(profile, "(allow file-read-metadata)") {
		t.Error("profile should allow file-read-metadata (required by Node.js TLS/undici for HTTPS fetch)")
	}

	// Should deny sensitive paths
	if !strings.Contains(profile, ".ssh") {
		t.Error("profile should deny .ssh")
	}
	if !strings.Contains(profile, ".aws") {
		t.Error("profile should deny .aws")
	}
	if !strings.Contains(profile, ".gnupg") {
		t.Error("profile should deny .gnupg")
	}
}

func TestGenerateSeatbeltProfileNoNetwork(t *testing.T) {
	cfg := Config{
		PluginDir:    "/opt/plugins/myplugin",
		ExecPath:     "/opt/plugins/myplugin/run",
		AllowNetwork: false,
	}

	profile := generateSeatbeltProfile(cfg)

	if strings.Contains(profile, "(allow network*)") {
		t.Error("profile should NOT allow network when AllowNetwork=false")
	}
}

func TestGenerateSeatbeltProfileEscapesPluginDir(t *testing.T) {
	cfg := Config{
		PluginDir:    `/tmp/plugin" ) (allow network*) ("`,
		ExecPath:     "/tmp/plugin/run",
		AllowNetwork: false,
	}

	profile := generateSeatbeltProfile(cfg)

	if strings.Contains(profile, `(subpath "/tmp/plugin" ) (allow network*) ("`) {
		t.Fatal("profile should not interpolate raw plugin path")
	}
	if !strings.Contains(profile, strconv.Quote(cfg.PluginDir)) {
		t.Fatal("profile should contain escaped plugin path literal")
	}
	if strings.Contains(profile, "\n(allow network*)\n") {
		t.Fatal("profile should not gain network access from injected plugin path")
	}
}

func TestBuildCommandLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-only test")
	}

	// Check if bwrap is available
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bubblewrap not installed")
	}

	cfg := Config{
		PluginDir:    "/tmp/test-plugin",
		ExecPath:     "/tmp/test-plugin/run.sh",
		Args:         []string{"--foo", "bar"},
		Env:          []string{"HOME=/home/test", "PATH=/usr/bin"},
		AllowNetwork: true,
	}

	cmd, err := BuildCommand(cfg)
	if err != nil {
		t.Fatalf("BuildCommand() error: %v", err)
	}

	args := strings.Join(cmd.Args, " ")

	// Should use bwrap
	if !strings.Contains(cmd.Path, "bwrap") {
		t.Error("should use bwrap")
	}

	// Should mount system dirs read-only
	if !strings.Contains(args, "--ro-bind /usr /usr") {
		t.Error("should mount /usr read-only")
	}

	// Should mount plugin dir read-only
	if !strings.Contains(args, "--ro-bind /tmp/test-plugin /tmp/test-plugin") {
		t.Error("should mount plugin dir read-only")
	}

	// Should share network when allowed
	if !strings.Contains(args, "--share-net") {
		t.Error("should share network when AllowNetwork=true")
	}

	// Should include namespace isolation
	if !strings.Contains(args, "--unshare-pid") {
		t.Error("should unshare PID namespace")
	}
	if !strings.Contains(args, "--unshare-ipc") {
		t.Error("should unshare IPC namespace")
	}

	// Should include die-with-parent
	if !strings.Contains(args, "--die-with-parent") {
		t.Error("should die with parent")
	}

	// Should include plugin args after --
	if !strings.Contains(args, "-- /tmp/test-plugin/run.sh --foo bar") {
		t.Errorf("should include plugin command and args, got: %s", args)
	}
}

func TestBuildCommandLinuxNoNetwork(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-only test")
	}
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bubblewrap not installed")
	}

	cfg := Config{
		PluginDir:    "/tmp/test-plugin",
		ExecPath:     "/tmp/test-plugin/run.sh",
		AllowNetwork: false,
	}

	cmd, err := BuildCommand(cfg)
	if err != nil {
		t.Fatalf("BuildCommand() error: %v", err)
	}

	args := strings.Join(cmd.Args, " ")

	if !strings.Contains(args, "--unshare-net") {
		t.Error("should unshare network when AllowNetwork=false")
	}
	if strings.Contains(args, "--share-net") {
		t.Error("should NOT share network when AllowNetwork=false")
	}
}

func TestGetSandboxInfo(t *testing.T) {
	info := GetSandboxInfo()
	if info == "" {
		t.Error("GetSandboxInfo() should return non-empty string")
	}

	switch runtime.GOOS {
	case "linux":
		if _, err := exec.LookPath("bwrap"); err == nil {
			if !strings.Contains(info, "bubblewrap") {
				t.Errorf("GetSandboxInfo() = %q, want containing 'bubblewrap'", info)
			}
		} else {
			if !strings.Contains(info, "unavailable") {
				t.Errorf("GetSandboxInfo() = %q, want containing 'unavailable'", info)
			}
		}
	case "darwin":
		// Either "sandbox-exec" or "unavailable"
		if !strings.Contains(info, "sandbox") && !strings.Contains(info, "unavailable") {
			t.Errorf("GetSandboxInfo() = %q, unexpected on darwin", info)
		}
	default:
		if !strings.Contains(info, "unsupported") {
			t.Errorf("GetSandboxInfo() = %q, want containing 'unsupported'", info)
		}
	}
}
