// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package util

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

const (
	// passphraseCommandTimeout is the maximum time allowed for the passphrase command to complete.
	passphraseCommandTimeout = 5 * time.Second

	// maxPassphraseOutputBytes is the maximum stdout size from the passphrase command (8 KB).
	maxPassphraseOutputBytes = 8 * 1024
)

// PassphraseCommandConfig holds the full configuration for the passphrase command.
type PassphraseCommandConfig struct {
	Argv []string          // Command and arguments
	Env  map[string]string // Explicit environment variables (not inherited)
	Verb string            // "read" (default) or "write"
}

// RunPassphraseCommand executes the passphrase command with the configured verb
// and returns the output.
//
// The verb is injected as argv[1] before the user-supplied arguments:
//
//	argv[0] verb argv[1] argv[2] ...
//
// For "write" verb, stdinData is piped to the command's stdin.
// For "read" verb (default), stdin is nil.
//
// Output contract:
//   - Exactly one trailing newline is stripped (not TrimSpace)
//   - NUL bytes are rejected
//   - Output prefixed with "base64:" is base64-decoded
//   - Output prefixed with "hex:" is hex-decoded
//   - Otherwise output is returned as raw bytes
//
// The returned []byte should be zeroed by the caller after use.
func RunPassphraseCommand(cfg *PassphraseCommandConfig, stdinData []byte) ([]byte, error) {
	resolvedPath, err := validateAndResolveArgv(cfg.Argv)
	if err != nil {
		return nil, err
	}

	verb := cfg.Verb
	if verb == "" {
		verb = "read"
	}

	// Build final args: verb + user args (argv[1:])
	args := make([]string, 0, 1+len(cfg.Argv)-1)
	args = append(args, verb)
	args = append(args, cfg.Argv[1:]...)

	ctx, cancel := context.WithTimeout(context.Background(), passphraseCommandTimeout)
	defer cancel()

	// Don't use exec.CommandContext's built-in cancel — it only kills the direct process.
	// We use a process group so child processes (e.g., sh -> sleep) are also killed.
	cmd := exec.Command(resolvedPath, args...) //nolint:gosec // validated above
	cmd.Env = buildPassphraseEnv(cfg.Env)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	// For "write" verb, pipe stdinData to the command's stdin
	if len(stdinData) > 0 {
		cmd.Stdin = bytes.NewReader(stdinData)
	} else {
		cmd.Stdin = nil
	}

	// Capture stdout with size limit; defer zeroing so all exit paths are covered.
	var stdoutBuf bytes.Buffer
	defer zeroBuffer(&stdoutBuf)
	lw := &limitedWriter{w: &stdoutBuf, remaining: maxPassphraseOutputBytes}
	cmd.Stdout = lw

	// Discard stderr — do not capture or propagate it, as a misbehaving helper
	// could write sensitive content (passphrases, keys) to stderr.
	cmd.Stderr = io.Discard

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("passphrase_command_argv: failed to start: %w", err)
	}

	// Wait for completion or timeout, killing the entire process group on timeout.
	waitDone := make(chan error, 1)
	go func() { waitDone <- cmd.Wait() }()

	var runErr error
	select {
	case runErr = <-waitDone:
		// Process exited (success or failure)
	case <-ctx.Done():
		// Timeout: kill the entire process group
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		<-waitDone // Wait for cmd.Wait to return after kill
		return nil, fmt.Errorf("passphrase_command_argv: command timed out after %s", passphraseCommandTimeout)
	}

	if runErr != nil {
		return nil, fmt.Errorf("passphrase_command_argv: command failed: %w", runErr)
	}

	// Check if output was silently truncated (single write filled the buffer exactly)
	if lw.truncated {
		return nil, fmt.Errorf("passphrase_command_argv: stdout exceeded %d bytes", maxPassphraseOutputBytes)
	}

	// Copy stdout content so we can work on it; the buffer itself is zeroed by defer.
	rawOutput := make([]byte, stdoutBuf.Len())
	copy(rawOutput, stdoutBuf.Bytes())

	// Strip exactly one trailing newline (preserve leading/trailing spaces in passphrase)
	output := rawOutput
	if len(output) > 0 && output[len(output)-1] == '\n' {
		output = output[:len(output)-1]
		// Also strip \r if present (Windows-style \r\n)
		if len(output) > 0 && output[len(output)-1] == '\r' {
			output = output[:len(output)-1]
		}
	}

	if len(output) == 0 {
		zeroBytes(rawOutput)
		return nil, fmt.Errorf("passphrase_command_argv: command produced empty output")
	}

	// Reject NUL bytes (invalid in passphrases, indicates binary corruption)
	if bytes.ContainsRune(output, 0) {
		zeroBytes(rawOutput)
		return nil, fmt.Errorf("passphrase_command_argv: output contains NUL bytes (invalid)")
	}

	// Decode prefixed output formats
	result, err := decodePassphraseOutput(output)
	// Zero the raw output now that we have the decoded result (or an error)
	zeroBytes(rawOutput)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// WritePassphrase stores a passphrase via the passphrase command's "write" verb.
// It sends the passphrase on stdin, reads back the round-trip value from stdout,
// and verifies they match using constant-time comparison.
//
// Returns nil on success. Returns an error if:
//   - The command exits non-zero (write verb unsupported)
//   - The read-back value doesn't match the input
//   - Any other execution error
func WritePassphrase(cfg *PassphraseCommandConfig, passphrase []byte) error {
	writeCfg := *cfg
	writeCfg.Verb = "write"

	readBack, err := RunPassphraseCommand(&writeCfg, passphrase)
	if err != nil {
		return fmt.Errorf("passphrase_command_argv write: %w", err)
	}
	defer zeroBytes(readBack)

	if subtle.ConstantTimeCompare(readBack, passphrase) != 1 {
		return fmt.Errorf("passphrase_command_argv write: read-back mismatch (helper returned different value)")
	}

	return nil
}

// decodePassphraseOutput handles base64: and hex: prefixed output, or returns raw bytes.
// Uses []byte-native decode APIs to avoid creating immutable string copies of secret material.
// The caller is responsible for zeroing both the input and the returned slice.
func decodePassphraseOutput(output []byte) ([]byte, error) {
	if bytes.HasPrefix(output, []byte("base64:")) {
		encoded := output[len("base64:"):]
		decoded := make([]byte, base64.StdEncoding.DecodedLen(len(encoded)))
		n, err := base64.StdEncoding.Decode(decoded, encoded)
		if err != nil {
			zeroBytes(decoded)
			return nil, fmt.Errorf("passphrase_command_argv: invalid base64 output: %w", err)
		}
		return decoded[:n], nil
	}

	if bytes.HasPrefix(output, []byte("hex:")) {
		encoded := output[len("hex:"):]
		decoded := make([]byte, hex.DecodedLen(len(encoded)))
		n, err := hex.Decode(decoded, encoded)
		if err != nil {
			zeroBytes(decoded)
			return nil, fmt.Errorf("passphrase_command_argv: invalid hex output: %w", err)
		}
		return decoded[:n], nil
	}

	// Raw bytes — return a copy so the caller can zero the original
	result := make([]byte, len(output))
	copy(result, output)
	return result, nil
}

// zeroBytes overwrites a byte slice with zeros using constant-time copy
// to prevent compiler optimization from eliding the operation.
func zeroBytes(b []byte) {
	if len(b) == 0 {
		return
	}
	subtle.ConstantTimeCopy(1, b, make([]byte, len(b)))
}

// zeroBuffer zeros the internal contents of a bytes.Buffer.
func zeroBuffer(buf *bytes.Buffer) {
	b := buf.Bytes()
	zeroBytes(b)
	buf.Reset()
}

// ValidatePassphraseCommandConfig validates the full passphrase command configuration.
func ValidatePassphraseCommandConfig(cfg *PassphraseCommandConfig) error {
	_, err := validateAndResolveArgv(cfg.Argv)
	return err
}

// validateAndResolveArgv checks that argv is well-formed and returns the resolved binary path.
// argv[0] must be an absolute path (config loader resolves relative paths against the data directory).
func validateAndResolveArgv(argv []string) (string, error) {
	if len(argv) == 0 {
		return "", fmt.Errorf("passphrase_command_argv: must be non-empty")
	}

	binaryPath := argv[0]

	if !filepath.IsAbs(binaryPath) {
		return "", fmt.Errorf("passphrase_command_argv: argv[0] must be an absolute path, got %q (use an absolute path or a path relative to the data directory)", binaryPath)
	}

	if err := validateBinary(binaryPath); err != nil {
		return "", err
	}

	return binaryPath, nil
}

// validateBinary checks that a binary path points to a valid, secure executable.
func validateBinary(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("passphrase_command_argv: %w", err)
	}

	if info.IsDir() {
		return fmt.Errorf("passphrase_command_argv: %s is a directory, not an executable", path)
	}

	perm := info.Mode().Perm()

	// Check executable bit (owner, group, or other)
	if perm&0111 == 0 {
		return fmt.Errorf("passphrase_command_argv: %s is not executable (mode %04o)", path, perm)
	}

	// Reject group/world-writable binaries (could be tampered with)
	if perm&0022 != 0 {
		return fmt.Errorf("passphrase_command_argv: %s is group or world writable (mode %04o) — potential tampering risk", path, perm)
	}

	return nil
}

// buildPassphraseEnv constructs the environment for the passphrase command.
// Only explicitly declared variables are included — the process env is never inherited.
func buildPassphraseEnv(declaredEnv map[string]string) []string {
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
