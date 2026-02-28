// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package harness

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ApshellHarness manages apshell CLI testing
type ApshellHarness struct {
	t              *testing.T
	workDir        string
	signerURL      string
	signerHostPort string
	binaryPath     string
	envVars        []string
}

// NewApshellHarness creates a new apshell CLI test harness
// signerWorkDir should be the signer's work directory to copy the token from
func NewApshellHarness(t *testing.T, signerURL string) *ApshellHarness {
	// Create a unique work directory for this test
	workDir := filepath.Join(t.TempDir(), "apshell-test")
	if err := os.MkdirAll(workDir, 0755); err != nil {
		t.Fatalf("Failed to create work directory: %v", err)
	}

	// Create identity-scoped keys subdirectory
	keysDir := filepath.Join(workDir, "users", "default", "keys")
	if err := os.MkdirAll(keysDir, 0755); err != nil {
		t.Fatalf("Failed to create keys directory: %v", err)
	}

	h := &ApshellHarness{
		t:         t,
		workDir:   workDir,
		signerURL: signerURL,
		envVars:   []string{},
	}

	// Extract port from URL for connect command
	// URL format: http://localhost:12345
	if strings.HasPrefix(signerURL, "http://") {
		hostPort := strings.TrimPrefix(signerURL, "http://")
		// Parse host:port
		parts := strings.Split(hostPort, ":")
		if len(parts) == 2 {
			// For localhost, use: connect localhost --signer-port <port>
			h.signerHostPort = parts[1] // Just the port number
		}
	}

	return h
}

// Build compiles apshell if needed
func (a *ApshellHarness) Build() error {
	// Build to a specific location
	binaryPath := filepath.Join(a.workDir, "apshell")
	a.binaryPath = binaryPath

	// Check if binary already exists
	if _, err := os.Stat(binaryPath); err == nil {
		return nil // Already built
	}

	// Get project root (where go.mod is)
	projectRoot, err := findProjectRoot()
	if err != nil {
		return fmt.Errorf("failed to find project root: %w", err)
	}

	// Build apshell
	cmd := exec.Command("go", "build", "-o", binaryPath, "./cmd/apshell")
	cmd.Dir = projectRoot
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to build apshell: %w\nOutput: %s", err, output)
	}

	return nil
}

// SetEnv adds an environment variable for apshell commands
func (a *ApshellHarness) SetEnv(key, value string) {
	a.envVars = append(a.envVars, fmt.Sprintf("%s=%s", key, value))
}

// CopyTokenFrom copies the aplane.token from the signer's identity-scoped directory.
// Token is located at: <signerWorkDir>/users/default/aplane.token
func (a *ApshellHarness) CopyTokenFrom(signerWorkDir string) error {
	srcPath := filepath.Join(signerWorkDir, "users", "default", "aplane.token")
	dstPath := filepath.Join(a.workDir, "aplane.token")

	data, err := os.ReadFile(srcPath)
	if err != nil {
		return fmt.Errorf("failed to read token from signer (%s): %w", srcPath, err)
	}

	if err := os.WriteFile(dstPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write token: %w", err)
	}

	return nil
}

// Run executes an apshell command and returns the output
func (a *ApshellHarness) Run(args ...string) (string, error) {
	return a.RunWithInput("", args...)
}

// RunWithInput executes an apshell command with stdin input
func (a *ApshellHarness) RunWithInput(input string, args ...string) (string, error) {
	// Ensure it's built
	if err := a.Build(); err != nil {
		return "", err
	}

	// Prepend connect command to explicitly connect to our test server
	// This overrides any auto-connect to default localhost:11270
	if a.signerHostPort != "" {
		// Format: connect localhost --signer-port <port>
		input = fmt.Sprintf("connect localhost --signer-port %s\n%s", a.signerHostPort, input)
	}

	// Run the command with the input
	return a.runRaw(input, args...)
}

// runRaw executes apshell without connection management
func (a *ApshellHarness) runRaw(input string, args ...string) (string, error) {
	// Create command
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, a.binaryPath, args...)
	cmd.Dir = a.workDir

	// Set environment
	cmd.Env = append(os.Environ(), a.envVars...)

	// Set stdin if provided
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}

	// Capture output
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Run command
	err := cmd.Run()

	// Log output for debugging
	if testing.Verbose() {
		if stdout.Len() > 0 {
			a.t.Logf("apshell stdout: %s", stdout.String())
		}
		if stderr.Len() > 0 {
			a.t.Logf("apshell stderr: %s", stderr.String())
		}
	}

	// Return combined output
	output := stdout.String()
	if stderr.Len() > 0 {
		output += "\n" + stderr.String()
	}

	if err != nil {
		return output, fmt.Errorf("apshell command failed: %w\nOutput: %s", err, output)
	}

	return output, nil
}

// RunExpectError executes an apshell command expecting it to fail
func (a *ApshellHarness) RunExpectError(args ...string) (string, error) {
	output, err := a.Run(args...)
	if err == nil {
		return output, fmt.Errorf("expected command to fail but it succeeded")
	}
	return output, nil
}

// ImportKey imports a key file into the test environment
func (a *ApshellHarness) ImportKey(keyFilePath string) error {
	// Copy the key file to our test keys directory
	filename := filepath.Base(keyFilePath)
	destPath := filepath.Join(a.workDir, "users", "default", "keys", filename)

	data, err := os.ReadFile(keyFilePath)
	if err != nil {
		return fmt.Errorf("failed to read key file: %w", err)
	}

	if err := os.WriteFile(destPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}

	return nil
}

// SendTransaction sends a payment transaction using apshell
func (a *ApshellHarness) SendTransaction(from, to string, amount float64) (string, error) {
	// Format: send <amount> <asset> from <sender> to <receiver>
	// Note: txn_auto_approve is set in config.yaml so no "y" needed
	input := fmt.Sprintf("send %f algo from %s to %s\nquit\n", amount, from, to)
	output, err := a.RunWithInput(input)
	if err != nil {
		return "", err
	}

	// Parse transaction ID from output
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "Transaction ID:") ||
			strings.Contains(line, "Submitted transaction") ||
			strings.Contains(line, "Transaction submitted:") {
			// Extract transaction ID (typically after the colon or in the message)
			parts := strings.Fields(line)
			for _, part := range parts {
				// Transaction IDs are typically 52 characters
				if len(part) == 52 && !strings.Contains(part, ":") {
					return part, nil
				}
			}
		}
	}

	return "", fmt.Errorf("could not find transaction ID in output: %s", output)
}

// GetWorkDir returns the working directory for this harness
func (a *ApshellHarness) GetWorkDir() string {
	return a.workDir
}

// GetKeysDir returns the keys directory for this harness
func (a *ApshellHarness) GetKeysDir() string {
	return filepath.Join(a.workDir, "users", "default", "keys")
}
