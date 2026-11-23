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
	// PluginName is the plugin's manifest name. It selects which plugin-specific
	// configuration variables survive the environment filter.
	PluginName string

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

	// AllowedEnv lists additional host environment variable names declared by
	// the plugin manifest. Only variables in the base runtime allowlist or in
	// AllowedEnv (and not blocked as host credentials) pass into the sandbox.
	AllowedEnv []string
}

// ErrSandboxUnavailable is returned when sandboxing is required but not available
var ErrSandboxUnavailable = errors.New("sandbox unavailable: external plugins require sandboxing for security")

// BuildCommand creates an exec.Cmd with appropriate sandboxing for the current
// OS, and names the sandbox for display. Returns an error if sandboxing is not
// available - plugins cannot run unsandboxed.
func BuildCommand(cfg Config) (*exec.Cmd, string, error) {
	switch runtime.GOOS {
	case "linux":
		cmd, err := buildLinuxCommand(cfg)
		return cmd, "bubblewrap (Linux)", err
	case "darwin":
		cmd, err := buildDarwinCommand(cfg)
		return cmd, "sandbox-exec (macOS)", err
	default:
		return nil, "", fmt.Errorf("%w: unsupported platform %s (use WSL2 on Windows)", ErrSandboxUnavailable, runtime.GOOS)
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

	// Plugins need the network to reach algod, KMD and indexer.
	args = append(args, "--share-net")

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
	cmd.Env = filterEnv(cfg.PluginName, cfg.AllowedEnv, cfg.Env)

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
	cmd.Env = filterEnv(cfg.PluginName, cfg.AllowedEnv, cfg.Env)

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

	// Plugins need the network to reach algod, KMD and indexer.
	sb.WriteString("; Network access\n")
	sb.WriteString("(allow network*)\n\n")

	// Mach operations (allowlisted services required by Go/Node.js DNS, TLS,
	// and runtime startup; mach-register is intentionally omitted).
	// com.apple.logd and com.apple.diagnosticd are intentionally left denied:
	// losing system-library log lines does not affect plugins (their output goes
	// over stderr and JSON-RPC), and plugins do not need write access to the
	// system log.
	sb.WriteString("; Mach IPC (allowlisted services for DNS, TLS, and runtime init)\n")
	sb.WriteString("(allow mach-lookup\n")
	sb.WriteString("    (global-name \"com.apple.CoreServices.coreservicesd\")\n")
	sb.WriteString("    (global-name \"com.apple.SecurityServer\")\n")
	sb.WriteString("    (global-name \"com.apple.SystemConfiguration.DNSConfiguration\")\n")
	sb.WriteString("    (global-name \"com.apple.SystemConfiguration.configd\")\n")
	sb.WriteString("    (global-name \"com.apple.bsd.dirhelper\")\n")
	sb.WriteString("    (global-name \"com.apple.dnssd.service\")\n")
	sb.WriteString("    (global-name \"com.apple.mDNSResponder\")\n")
	sb.WriteString("    (global-name \"com.apple.ocspd\")\n")
	sb.WriteString("    (global-name \"com.apple.system.logger\")\n")
	sb.WriteString("    (global-name \"com.apple.system.notification_center\")\n")
	sb.WriteString("    (global-name \"com.apple.system.opendirectoryd.libinfo\")\n")
	sb.WriteString("    (global-name \"com.apple.trustd.agent\")\n")
	sb.WriteString(")\n\n")

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

// baseAllowedEnvKeys are the minimal OS/runtime environment variables passed
// into every sandboxed plugin. All other host variables are stripped unless
// explicitly declared by the plugin manifest and permitted by sensitiveEnvKey.
var baseAllowedEnvKeys = map[string]bool{
	"APSHELL_PLUGIN_STATE_DIR": true,
	"HOME":                     true,
	"LANG":                     true,
	"LC_ALL":                   true,
	"LC_CTYPE":                 true,
	"NODE_EXTRA_CA_CERTS":      true,
	"PATH":                     true,
	"SSL_CERT_DIR":             true,
	"SSL_CERT_FILE":            true,
	"TERM":                     true,
	"TMPDIR":                   true,
	"TZ":                       true,
	// macOS CoreFoundation reads this locale/encoding tag; stripping it makes
	// CoreFoundation fall back to reading ~/.CFUserTextEncoding and probing
	// /dev/autofs_nowait under Seatbelt.
	"__CF_USER_TEXT_ENCODING": true,
}

// filterEnv filters environment variables for sandboxed execution using an
// allowlist: only base runtime variables and names explicitly declared in
// allowedEnv survive, and credential-shaped names are always refused unless
// explicitly exempted for pluginName.
func filterEnv(pluginName string, allowedEnv []string, env []string) []string {
	// Directories accessible inside the sandbox (bind-mounted read-only)
	sandboxPrefixes := []string{"/usr/", "/bin/", "/lib/", "/lib64/", "/sbin/"}

	declared := make(map[string]bool, len(allowedEnv))
	for _, name := range allowedEnv {
		declared[name] = true
	}

	var filtered []string
	for _, e := range env {
		parts := strings.SplitN(e, "=", 2)
		key := parts[0]
		if !baseAllowedEnvKeys[key] && !declared[key] {
			continue
		}
		if sensitiveEnvKey(pluginName, key) {
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

// pluginConfigEnvKeys are secret-shaped names that a bundled plugin reads as
// its own configuration, so the suffix rule below must not strip them for that
// plugin. They are keyed by manifest name so no other plugin receives them: the
// operator sets them for one plugin, and every plugin runs with network access.
var pluginConfigEnvKeys = map[string]map[string]bool{
	"algokit-localnet": {
		"APLANE_LOCALNET_TOKEN":           true, // algod/KMD token
		"APLANE_LOCALNET_WALLET_PASSWORD": true, // KMD wallet password
	},
}

// secretEnvSuffixes mark a variable as a credential: tokens, secrets, API keys,
// passwords, and APlane's own passphrase, mnemonic, and key material (e.g.
// APSIGNER_PASSPHRASE, TEST_FUNDING_MNEMONIC).
var secretEnvSuffixes = []string{
	"_TOKEN", "_SECRET", "_API_KEY", "_PASSWORD",
	"_PASSPHRASE", "_MNEMONIC", "_PRIVATE_KEY", "_SEED",
	"_PROXY",
}

// secretEnvKeys are credential variables secretEnvSuffixes does not catch.
// Checked case-insensitively so manifest declarations cannot bypass the block.
var secretEnvKeys = map[string]bool{
	"AWS_ACCESS_KEY_ID":     true,
	"AWS_SECRET_ACCESS_KEY": true,
	"AWS_SESSION_TOKEN":     true,
	"DATABASE_URL":          true,
	"GITHUB_TOKEN":          true,
	"GH_TOKEN":              true,
	"NPM_TOKEN":             true,
	"SSH_AUTH_SOCK":         true,
	"SSH_AGENT_PID":         true,
	"GPG_AGENT_INFO":        true,
}

func sensitiveEnvKey(pluginName, key string) bool {
	if pluginConfigEnvKeys[pluginName][key] {
		return false
	}
	upper := strings.ToUpper(key)
	if secretEnvKeys[upper] {
		return true
	}
	for _, suffix := range secretEnvSuffixes {
		if strings.HasSuffix(upper, suffix) {
			return true
		}
	}
	return false
}
