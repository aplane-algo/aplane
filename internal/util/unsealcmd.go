// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package util

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	// unsealCommandTimeout is the maximum time allowed for the unseal command to complete.
	unsealCommandTimeout = 5 * time.Second

	// maxUnsealOutputBytes is the maximum stdout size from the unseal command (8 KB).
	maxUnsealOutputBytes = 8 * 1024
)

// lockedPATH is the restricted PATH used when allow_path_lookup is true.
// Only system directories are included to prevent PATH injection.
var lockedPATH = "/usr/sbin:/usr/bin:/sbin:/bin"

// UnsealCommandConfig holds the full configuration for the unseal command.
type UnsealCommandConfig struct {
	Argv           []string          // Command and arguments
	Env            map[string]string // Explicit environment variables (not inherited)
	AllowPathLookup bool            // Allow non-absolute argv[0] resolved via locked PATH
	Kind           string           // "passphrase" (default) or "master_key"
}

// RunUnsealCommand executes the unseal command and returns the output.
//
// Output contract:
//   - Exactly one trailing newline is stripped (not TrimSpace)
//   - NUL bytes are rejected
//   - Output prefixed with "base64:" is base64-decoded
//   - Output prefixed with "hex:" is hex-decoded
//   - Otherwise output is returned as raw bytes
//
// The returned []byte should be zeroed by the caller after use.
func RunUnsealCommand(cfg *UnsealCommandConfig) ([]byte, error) {
	resolvedPath, err := validateAndResolveArgv(cfg.Argv, cfg.AllowPathLookup)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), unsealCommandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, resolvedPath, cfg.Argv[1:]...) //nolint:gosec // validated above
	cmd.Env = buildUnsealEnv(cfg.Env)
	cmd.Stdin = nil

	// Capture stdout with size limit
	var stdoutBuf bytes.Buffer
	lw := &limitedWriter{w: &stdoutBuf, remaining: maxUnsealOutputBytes}
	cmd.Stdout = lw

	// Capture stderr separately for error messages
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf

	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("unseal_command_argv: command timed out after %s", unsealCommandTimeout)
		}
		stderrMsg := bytes.TrimSpace(stderrBuf.Bytes())
		if len(stderrMsg) > 0 {
			return nil, fmt.Errorf("unseal_command_argv: command failed: %w (stderr: %s)", err, stderrMsg)
		}
		return nil, fmt.Errorf("unseal_command_argv: command failed: %w", err)
	}

	// Check if output was silently truncated (single write filled the buffer exactly)
	if lw.truncated {
		return nil, fmt.Errorf("unseal_command_argv: stdout exceeded %d bytes", maxUnsealOutputBytes)
	}

	// Strip exactly one trailing newline (preserve leading/trailing spaces in passphrase)
	output := stdoutBuf.Bytes()
	if len(output) > 0 && output[len(output)-1] == '\n' {
		output = output[:len(output)-1]
		// Also strip \r if present (Windows-style \r\n)
		if len(output) > 0 && output[len(output)-1] == '\r' {
			output = output[:len(output)-1]
		}
	}

	if len(output) == 0 {
		return nil, fmt.Errorf("unseal_command_argv: command produced empty output")
	}

	// Reject NUL bytes (invalid in passphrases, indicates binary corruption)
	if bytes.ContainsRune(output, 0) {
		return nil, fmt.Errorf("unseal_command_argv: output contains NUL bytes (invalid)")
	}

	// Decode prefixed output formats
	result, err := decodeUnsealOutput(output)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// decodeUnsealOutput handles base64: and hex: prefixed output, or returns raw bytes.
func decodeUnsealOutput(output []byte) ([]byte, error) {
	if bytes.HasPrefix(output, []byte("base64:")) {
		encoded := output[len("base64:"):]
		decoded, err := base64.StdEncoding.DecodeString(string(encoded))
		if err != nil {
			return nil, fmt.Errorf("unseal_command_argv: invalid base64 output: %w", err)
		}
		return decoded, nil
	}

	if bytes.HasPrefix(output, []byte("hex:")) {
		encoded := output[len("hex:"):]
		decoded, err := hex.DecodeString(string(encoded))
		if err != nil {
			return nil, fmt.Errorf("unseal_command_argv: invalid hex output: %w", err)
		}
		return decoded, nil
	}

	// Raw bytes — return a copy so the buffer can be GC'd
	result := make([]byte, len(output))
	copy(result, output)
	return result, nil
}

// ValidateUnsealCommandConfig validates the full unseal command configuration.
func ValidateUnsealCommandConfig(cfg *UnsealCommandConfig) error {
	_, err := validateAndResolveArgv(cfg.Argv, cfg.AllowPathLookup)
	return err
}

// validateAndResolveArgv checks that argv is well-formed and returns the resolved binary path.
// If allowPathLookup is true and argv[0] is not absolute, resolves via locked PATH.
func validateAndResolveArgv(argv []string, allowPathLookup bool) (string, error) {
	if len(argv) == 0 {
		return "", fmt.Errorf("unseal_command_argv: must be non-empty")
	}

	binaryPath := argv[0]

	if !filepath.IsAbs(binaryPath) {
		if !allowPathLookup {
			return "", fmt.Errorf("unseal_command_argv: argv[0] must be an absolute path, got %q (set allow_path_lookup:true to resolve via system PATH)", binaryPath)
		}

		// Resolve via locked PATH
		resolved, err := lookupInLockedPath(binaryPath)
		if err != nil {
			return "", fmt.Errorf("unseal_command_argv: %w", err)
		}
		binaryPath = resolved
	}

	if err := validateBinary(binaryPath); err != nil {
		return "", err
	}

	return binaryPath, nil
}

// lookupInLockedPath resolves a binary name using the locked PATH.
// The name must be a plain basename (no slashes, no ".." components) to prevent
// traversal outside the locked PATH directories.
func lookupInLockedPath(name string) (string, error) {
	if strings.Contains(name, "/") || strings.Contains(name, "..") || name == "." {
		return "", fmt.Errorf("command name %q must be a plain basename (no path separators or traversal)", name)
	}
	for _, dir := range filepath.SplitList(lockedPATH) {
		candidate := filepath.Join(dir, name)
		info, err := os.Stat(candidate)
		if err != nil {
			continue
		}
		if info.IsDir() {
			continue
		}
		if info.Mode().Perm()&0111 != 0 {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("command %q not found in locked PATH (%s)", name, lockedPATH)
}

// validateBinary checks that a binary path points to a valid, secure executable.
func validateBinary(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("unseal_command_argv: %w", err)
	}

	if info.IsDir() {
		return fmt.Errorf("unseal_command_argv: %s is a directory, not an executable", path)
	}

	perm := info.Mode().Perm()

	// Check executable bit (owner, group, or other)
	if perm&0111 == 0 {
		return fmt.Errorf("unseal_command_argv: %s is not executable (mode %04o)", path, perm)
	}

	// Reject group/world-writable binaries (could be tampered with)
	if perm&0022 != 0 {
		return fmt.Errorf("unseal_command_argv: %s is group or world writable (mode %04o) — potential tampering risk", path, perm)
	}

	return nil
}

// buildUnsealEnv constructs the environment for the unseal command.
// Only explicitly declared variables are included — the process env is never inherited.
func buildUnsealEnv(declaredEnv map[string]string) []string {
	if len(declaredEnv) == 0 {
		return []string{}
	}

	env := make([]string, 0, len(declaredEnv))
	for k, v := range declaredEnv {
		env = append(env, k+"="+v)
	}
	return env
}

// limitedWriter wraps an io.Writer and stops writing after a byte limit.
// It tracks whether output was truncated so the caller can detect silent truncation.
type limitedWriter struct {
	w         io.Writer
	remaining int64
	truncated bool
}

func (lw *limitedWriter) Write(p []byte) (int, error) {
	if lw.remaining <= 0 {
		// Already exhausted — silently discard and report full length
		// so the child process doesn't get a short write error.
		lw.truncated = true
		return len(p), nil
	}
	originalLen := len(p)
	if int64(originalLen) > lw.remaining {
		p = p[:lw.remaining]
		lw.truncated = true
	}
	n, err := lw.w.Write(p)
	lw.remaining -= int64(n)
	if err != nil {
		return n, err
	}
	// Report the original length so the child process doesn't see a short write.
	return originalLen, nil
}
