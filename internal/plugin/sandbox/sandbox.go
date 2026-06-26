// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package sandbox provides OS-level sandboxing for external plugins.
// On Linux, it uses bubblewrap (bwrap) for filesystem isolation.
// On macOS, it uses sandbox-exec with Seatbelt profiles.
// On unsupported platforms, plugin execution is rejected rather than run unsandboxed.
package sandbox

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

// Config holds sandbox configuration
type Config struct {
	// PluginDir is the plugin's directory (read-only access granted)
	PluginDir string

	// StateDir is the plugin's private persistent state directory. When set, it is
	// mounted read-write inside the sandbox. It must live outside PluginDir (and
	// outside the checksummed payload), since it is mutable by design.
	StateDir string

	// ExecPath is the path to the plugin executable
	ExecPath string

	// Args are the arguments to pass to the plugin
	Args []string

	// Env are the environment variables for the plugin
	Env []string

	// AllowNetwork permits network access (required for algod/indexer)
	AllowNetwork bool
}

// ErrSandboxUnavailable is returned when sandboxing is required but not available
var ErrSandboxUnavailable = errors.New("sandbox unavailable: external plugins require sandboxing for security")

// BuildCommand creates an exec.Cmd with appropriate sandboxing for the current OS.
// Returns an error if sandboxing is not available - plugins cannot run unsandboxed.
func BuildCommand(cfg Config) (*exec.Cmd, error) {
	switch runtime.GOOS {
	case "linux":
		return buildLinuxCommand(cfg)
	case "darwin":
		return buildDarwinCommand(cfg)
	default:
		return nil, fmt.Errorf("%w: unsupported platform %s (use WSL2 on Windows)", ErrSandboxUnavailable, runtime.GOOS)
	}
}

// buildLinuxCommand creates a sandboxed command using bubblewrap
func buildLinuxCommand(cfg Config) (*exec.Cmd, error) {
	// Check if bwrap is available
	bwrapPath, err := exec.LookPath("bwrap")
	if err != nil {
		return nil, fmt.Errorf("%w: bubblewrap not installed (apt install bubblewrap)", ErrSandboxUnavailable)
	}

	args := []string{
		// Mount system directories read-only
		"--ro-bind", "/usr", "/usr",
		"--ro-bind", "/lib", "/lib",
		"--ro-bind", "/bin", "/bin",
	}

	// /lib64 may not exist on all systems
	if _, err := os.Stat("/lib64"); err == nil {
		args = append(args, "--ro-bind", "/lib64", "/lib64")
	}

	// /sbin may be needed for some tools
	if _, err := os.Stat("/sbin"); err == nil {
		args = append(args, "--ro-bind", "/sbin", "/sbin")
	}

	// SSL certificates for HTTPS
	if _, err := os.Stat("/etc/ssl"); err == nil {
		args = append(args, "--ro-bind", "/etc/ssl", "/etc/ssl")
	}
	if _, err := os.Stat("/etc/ca-certificates"); err == nil {
		args = append(args, "--ro-bind", "/etc/ca-certificates", "/etc/ca-certificates")
	}

	// DNS resolution
	if _, err := os.Stat("/etc/resolv.conf"); err == nil {
		args = append(args, "--ro-bind", "/etc/resolv.conf", "/etc/resolv.conf")
	}
	if _, err := os.Stat("/etc/hosts"); err == nil {
		args = append(args, "--ro-bind", "/etc/hosts", "/etc/hosts")
	}
	if _, err := os.Stat("/etc/nsswitch.conf"); err == nil {
		args = append(args, "--ro-bind", "/etc/nsswitch.conf", "/etc/nsswitch.conf")
	}

	// Plugin directory (read-only)
	args = append(args, "--ro-bind", cfg.PluginDir, cfg.PluginDir)

	// Plugin private state directory (read-write), if configured.
	if cfg.StateDir != "" {
		args = append(args, "--bind", cfg.StateDir, cfg.StateDir)
	}

	// Temp space (read-write)
	args = append(args, "--tmpfs", "/tmp")

	// Proc and dev (minimal, needed for Node.js/Go runtime)
	args = append(args, "--proc", "/proc")
	args = append(args, "--dev", "/dev")

	// Namespace isolation
	args = append(args, "--unshare-user")
	args = append(args, "--unshare-pid")
	args = append(args, "--unshare-ipc")
	args = append(args, "--unshare-uts")
	args = append(args, "--unshare-cgroup")

	// Network: share if allowed, otherwise unshare
	if cfg.AllowNetwork {
		args = append(args, "--share-net")
	} else {
		args = append(args, "--unshare-net")
	}

	// Die when parent dies (prevents orphaned sandboxed processes)
	args = append(args, "--die-with-parent")

	// New session (detach from controlling terminal)
	args = append(args, "--new-session")

	// Set working directory inside sandbox
	args = append(args, "--chdir", cfg.PluginDir)

	// Add the actual command
	args = append(args, "--", cfg.ExecPath)
	args = append(args, cfg.Args...)

	cmd := exec.Command(bwrapPath, args...)
	cmd.Dir = cfg.PluginDir
	cmd.Env = filterEnv(cfg.Env)

	return cmd, nil
}

// buildDarwinCommand creates a sandboxed command using sandbox-exec
func buildDarwinCommand(cfg Config) (*exec.Cmd, error) {
	// Check if sandbox-exec is available (should always be on macOS)
	sandboxExecPath, err := exec.LookPath("sandbox-exec")
	if err != nil {
		return nil, fmt.Errorf("%w: sandbox-exec not found", ErrSandboxUnavailable)
	}

	// Generate Seatbelt profile
	profile := generateSeatbeltProfile(cfg)

	// sandbox-exec -p <profile> <command> <args...>
	args := []string{"-p", profile, cfg.ExecPath}
	args = append(args, cfg.Args...)

	cmd := exec.Command(sandboxExecPath, args...)
	cmd.Dir = cfg.PluginDir
	cmd.Env = filterEnv(cfg.Env)

	return cmd, nil
}

// generateSeatbeltProfile creates a Seatbelt profile for macOS sandbox-exec
func generateSeatbeltProfile(cfg Config) string {
	var sb strings.Builder

	sb.WriteString("(version 1)\n")
	sb.WriteString("(deny default)\n\n")

	// Allow reading system libraries and frameworks
	// (literal "/") is required: libuv/CoreFoundation stat(2) the root during
	// process init to probe filesystem properties; without it, Node SEA aborts.
	sb.WriteString("; System libraries\n")
	sb.WriteString("(allow file-read*\n")
	sb.WriteString("    (literal \"/\")\n")
	sb.WriteString("    (subpath \"/usr/lib\")\n")
	sb.WriteString("    (subpath \"/usr/share\")\n")
	sb.WriteString("    (subpath \"/System/Library\")\n")
	sb.WriteString("    (subpath \"/Library/Frameworks\")\n")
	sb.WriteString("    (subpath \"/private/var/db/dyld\")\n") // dyld shared cache
	sb.WriteString(")\n\n")

	// SSL certificates
	sb.WriteString("; SSL certificates\n")
	sb.WriteString("(allow file-read*\n")
	sb.WriteString("    (subpath \"/private/etc/ssl\")\n")
	sb.WriteString("    (subpath \"/etc/ssl\")\n")
	sb.WriteString(")\n\n")

	// DNS resolution
	sb.WriteString("; DNS resolution\n")
	sb.WriteString("(allow file-read*\n")
	sb.WriteString("    (literal \"/private/etc/resolv.conf\")\n")
	sb.WriteString("    (literal \"/private/etc/hosts\")\n")
	sb.WriteString("    (literal \"/etc/resolv.conf\")\n")
	sb.WriteString("    (literal \"/etc/hosts\")\n")
	sb.WriteString(")\n\n")

	// Plugin directory (read-only)
	sb.WriteString("; Plugin directory\n")
	sb.WriteString(fmt.Sprintf("(allow file-read* (subpath %s))\n\n", seatbeltStringLiteral(cfg.PluginDir)))

	// Plugin private state directory (read-write)
	if cfg.StateDir != "" {
		sb.WriteString("; Plugin state directory\n")
		sb.WriteString(fmt.Sprintf("(allow file-read* file-write* (subpath %s))\n\n", seatbeltStringLiteral(cfg.StateDir)))
	}

	// Temp directory (read-write)
	sb.WriteString("; Temp directory\n")
	sb.WriteString("(allow file-read* file-write* (subpath \"/private/tmp\"))\n")
	sb.WriteString("(allow file-read* file-write* (subpath \"/tmp\"))\n")
	sb.WriteString("(allow file-read* file-write* (subpath \"/var/folders\"))\n\n")

	// Process operations
	sb.WriteString("; Process operations\n")
	sb.WriteString("(allow process-fork)\n")
	sb.WriteString("(allow process-exec*)\n\n")

	// Network access
	if cfg.AllowNetwork {
		sb.WriteString("; Network access\n")
		sb.WriteString("(allow network*)\n\n")
	}

	// Mach operations (needed for basic process functionality)
	sb.WriteString("; Mach IPC (required for process operation)\n")
	sb.WriteString("(allow mach-lookup)\n")
	sb.WriteString("(allow mach-register)\n\n")

	// Signal handling
	sb.WriteString("; Signals\n")
	sb.WriteString("(allow signal (target self))\n\n")

	// sysctl read (needed by Go/Node.js runtime)
	sb.WriteString("; Sysctl (runtime info)\n")
	sb.WriteString("(allow sysctl-read)\n\n")

	// File metadata reads (stat/lstat/access on arbitrary paths).
	// Node.js undici/TLS calls stat() on socket files and symlink targets
	// (e.g. /var/run/mDNSResponder, /etc/resolv.conf -> /private/etc/resolv.conf)
	// during connection setup. Without this, HTTPS fetch fails even with network*.
	sb.WriteString("; File metadata (required for HTTPS fetch / DNS resolution)\n")
	sb.WriteString("(allow file-read-metadata)\n\n")

	// Deny sensitive paths explicitly (for clarity in logs)
	sb.WriteString("; Explicitly denied paths\n")
	homeDir, _ := os.UserHomeDir()
	if homeDir != "" {
		sb.WriteString(fmt.Sprintf("(deny file-read* (subpath %s))\n", seatbeltStringLiteral(homeDir+"/.ssh")))
		sb.WriteString(fmt.Sprintf("(deny file-read* (subpath %s))\n", seatbeltStringLiteral(homeDir+"/.aws")))
		sb.WriteString(fmt.Sprintf("(deny file-read* (subpath %s))\n", seatbeltStringLiteral(homeDir+"/.gnupg")))
		sb.WriteString(fmt.Sprintf("(deny file-read* (subpath %s))\n", seatbeltStringLiteral(homeDir+"/.config")))
	}

	return sb.String()
}

func seatbeltStringLiteral(path string) string {
	return strconv.Quote(path)
}

// filterEnv filters environment variables for sandboxed execution
// Removes potentially sensitive variables
func filterEnv(env []string) []string {
	// Directories accessible inside the sandbox (bind-mounted read-only)
	sandboxPrefixes := []string{"/usr/", "/bin/", "/lib/", "/lib64/", "/sbin/"}

	var filtered []string
	for _, e := range env {
		parts := strings.SplitN(e, "=", 2)
		key := parts[0]
		if sensitiveEnvKey(key) {
			continue
		}
		// Sanitize PATH to only include directories visible inside the sandbox.
		// The host PATH may contain user-local paths (e.g. ~/.nvm) that aren't
		// bind-mounted, causing child process spawns to fail with ENOENT.
		if key == "PATH" && len(parts) == 2 {
			var sandboxDirs []string
			for _, dir := range strings.Split(parts[1], ":") {
				for _, prefix := range sandboxPrefixes {
					if strings.HasPrefix(dir, prefix) || dir == strings.TrimSuffix(prefix, "/") {
						sandboxDirs = append(sandboxDirs, dir)
						break
					}
				}
			}
			filtered = append(filtered, "PATH="+strings.Join(sandboxDirs, ":"))
			continue
		}
		filtered = append(filtered, e)
	}
	return filtered
}

func sensitiveEnvKey(key string) bool {
	if strings.HasPrefix(key, "APSHELL_") {
		return false
	}
	exact := map[string]bool{
		"AWS_ACCESS_KEY_ID":     true,
		"AWS_SECRET_ACCESS_KEY": true,
		"AWS_SESSION_TOKEN":     true,
		"GITHUB_TOKEN":          true,
		"GH_TOKEN":              true,
		"NPM_TOKEN":             true,
		"SSH_AUTH_SOCK":         true,
		"SSH_AGENT_PID":         true,
		"GPG_AGENT_INFO":        true,
	}
	if exact[key] {
		return true
	}
	for _, suffix := range []string{"_TOKEN", "_SECRET", "_API_KEY", "_PASSWORD"} {
		if strings.HasSuffix(key, suffix) {
			return true
		}
	}
	return false
}

// GetSandboxInfo returns information about the sandbox for display
func GetSandboxInfo() string {
	switch runtime.GOOS {
	case "linux":
		if _, err := exec.LookPath("bwrap"); err == nil {
			return "bubblewrap (Linux)"
		}
		return "unavailable (install bubblewrap)"
	case "darwin":
		if _, err := exec.LookPath("sandbox-exec"); err == nil {
			return "sandbox-exec (macOS)"
		}
		return "unavailable"
	default:
		return fmt.Sprintf("unsupported (%s)", runtime.GOOS)
	}
}
