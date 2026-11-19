// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package serverconfig

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

const (
	// passphraseCommandTimeout is the maximum time allowed for the passphrase command to complete.
	passphraseCommandTimeout = 5 * time.Second

	// passphraseOutputCloseWait is how long the helper's stdout may stay open
	// after the helper exits or is killed. A process the helper started can
	// hold it open, even from outside the helper's process group, for as long
	// as that process lives.
	passphraseOutputCloseWait = time.Second

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
	// Wait returns once the helper has exited and stdout has closed; this
	// bounds the second part, closing the pipe and failing with ErrWaitDelay
	// if a successful helper left stdout held open.
	cmd.WaitDelay = passphraseOutputCloseWait

	// For "write" verb, pipe stdinData to the command's stdin
	if len(stdinData) > 0 {
		cmd.Stdin = bytes.NewReader(stdinData)
	} else {
		cmd.Stdin = nil
	}

	// Capture stdout in one buffer of the size limit, which never grows;
	// defer zeroing so all exit paths are covered.
	stdout := newHelperOutput(maxPassphraseOutputBytes)
	defer stdout.zero()
	cmd.Stdout = stdout

	// Discard stderr — do not capture or propagate it, as a misbehaving helper
	// could write sensitive content (passphrases, keys) to stderr. Nil is the
	// null device, so there is no pipe for a lingering process to hold open.
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("passphrase_command_argv: failed to start: %w", err)
	}

	// Wait for completion or timeout, killing the entire process group on timeout.
	waitDone := make(chan error, 1)
	go func() { waitDone <- cmd.Wait() }()

	killGroup := func() { _ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	// A run that fails for any reason ends whatever the helper left in its
	// process group, as the timeout always has.
	succeeded := false
	defer func() {
		if !succeeded {
			killGroup()
		}
	}()

	var runErr error
	timedOut := false
	select {
	case runErr = <-waitDone:
		// Process exited (success or failure)
	case <-ctx.Done():
		// Timeout: kill the entire process group. Wait then returns within
		// WaitDelay, even if a process outside the group holds stdout open.
		timedOut = true
		killGroup()
		runErr = <-waitDone
	}

	switch {
	case errors.Is(runErr, exec.ErrWaitDelay):
		// The helper exited 0, but a process it started still holds its stdout
		// and could still write to it, so what was read is not its settled
		// answer. Fail closed. (After a non-zero exit, Wait reports the exit
		// status instead, and the run fails as any failed helper does.)
		return nil, fmt.Errorf("passphrase_command_argv: helper exited, but a process it started kept its stdout open for %s afterwards; redirect background processes' output away from the helper's stdout", passphraseOutputCloseWait)
	case timedOut:
		return nil, fmt.Errorf("passphrase_command_argv: command timed out after %s", passphraseCommandTimeout)
	case runErr != nil:
		return nil, fmt.Errorf("passphrase_command_argv: command failed: %w", runErr)
	}

	if stdout.truncated {
		return nil, fmt.Errorf("passphrase_command_argv: stdout exceeded %d bytes", maxPassphraseOutputBytes)
	}

	// Strip exactly one trailing newline (preserve leading/trailing spaces in
	// passphrase). The output is read in place; decodePassphraseOutput returns
	// a copy, and the deferred zero clears the buffer.
	output := stdout.buf
	if len(output) > 0 && output[len(output)-1] == '\n' {
		output = output[:len(output)-1]
		// Also strip \r if present (Windows-style \r\n)
		if len(output) > 0 && output[len(output)-1] == '\r' {
			output = output[:len(output)-1]
		}
	}

	if len(output) == 0 {
		return nil, fmt.Errorf("passphrase_command_argv: command produced empty output")
	}

	// Reject NUL bytes (invalid in passphrases, indicates binary corruption)
	if bytes.ContainsRune(output, 0) {
		return nil, fmt.Errorf("passphrase_command_argv: output contains NUL bytes (invalid)")
	}

	// Decode prefixed output formats
	result, err := decodePassphraseOutput(output)
	if err != nil {
		return nil, err
	}

	succeeded = true
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

// passthroughEnvVars lists environment variables automatically forwarded from
// the process environment to the passphrase command, even when not declared in
// passphrase_command_env. Currently limited to CREDENTIALS_DIRECTORY, which
// systemd sets to the tmpfs path containing decrypted credentials when the
// unit uses LoadCredentialEncrypted. This allows appass-systemd-creds to read the
// pre-decrypted passphrase without requiring root access.
var passthroughEnvVars = []string{
	"CREDENTIALS_DIRECTORY",
}

// buildPassphraseEnv constructs the environment for the passphrase command.
// Only explicitly declared variables and passthroughEnvVars are included —
// the process env is never inherited wholesale.
func buildPassphraseEnv(declaredEnv map[string]string) []string {
	env := make([]string, 0, len(declaredEnv)+len(passthroughEnvVars))

	for k, v := range declaredEnv {
		env = append(env, k+"="+v)
	}

	// Forward systemd-provided variables from the process environment,
	// unless explicitly overridden by the user's declared env.
	for _, key := range passthroughEnvVars {
		if _, overridden := declaredEnv[key]; overridden {
			continue
		}
		if val, ok := os.LookupEnv(key); ok {
			env = append(env, key+"="+val)
		}
	}

	return env
}

// helperOutput collects the helper's stdout in one buffer of the output
// limit, allocated once, so it never grows and leaves no outgrown copy of the
// passphrase behind. Output past the limit is discarded and marks the output
// truncated; the full length is still reported, so the helper sees no short
// write.
type helperOutput struct {
	buf       []byte
	truncated bool
}

func newHelperOutput(limit int) *helperOutput {
	return &helperOutput{buf: make([]byte, 0, limit)}
}

func (o *helperOutput) Write(p []byte) (int, error) {
	n := copy(o.buf[len(o.buf):cap(o.buf)], p)
	o.buf = o.buf[:len(o.buf)+n]
	if n < len(p) {
		o.truncated = true
	}
	return len(p), nil
}

// zero clears the whole buffer, up to its capacity.
func (o *helperOutput) zero() {
	zeroBytes(o.buf[:cap(o.buf)])
	o.buf = o.buf[:0]
}
