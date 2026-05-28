// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

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

	"github.com/aplane-algo/aplane/internal/config"
)

// ApshellHarness manages apshell CLI testing
type ApshellHarness struct {
	t          *testing.T
	workDir    string
	signerURL  string
	binaryPath string
	clientData string
	envVars    []string
	timeout    time.Duration
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
	keysDir := filepath.Join(workDir, "identities", "default", "keys")
	if err := os.MkdirAll(keysDir, 0755); err != nil {
		t.Fatalf("Failed to create keys directory: %v", err)
	}

	return &ApshellHarness{
		t:          t,
		workDir:    workDir,
		signerURL:  signerURL,
		clientData: os.Getenv("APCLIENT_DATA"),
		envVars:    []string{},
		timeout:    30 * time.Second,
	}
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

// CopyTokenFrom copies the aplane.token from the signer's identity-scoped directory.
// Token is located at: <signerWorkDir>/identities/default/aplane.token
func (a *ApshellHarness) CopyTokenFrom(signerWorkDir string) error {
	srcPath := filepath.Join(signerWorkDir, "identities", "default", "aplane.token")
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

	// APCLIENT_DATA must be set so apshell auto-connects from config.yaml
	// (which has the correct SSH port, signer port, identity file, and known_hosts).
	// The connect command takes no arguments — connection target is always from config.
	if strings.TrimSpace(a.clientData) == "" {
		return "", fmt.Errorf("APCLIENT_DATA must be set for apshell harness (connect uses config.yaml, not CLI args)")
	}
	if err := ensureIntegrationClientConfig(a.clientData); err != nil {
		return "", err
	}

	// Run the command with the input
	return a.runRaw(input, args...)
}

func ensureIntegrationClientConfig(clientData string) error {
	network := IntegrationNetwork()
	if network == "" {
		return fmt.Errorf("%s must be set to %q or %q", IntegrationNetworkEnv, IntegrationNetworkTestnet, IntegrationNetworkLocalnet)
	}
	cfg, err := config.LoadConfig(clientData)
	if err != nil {
		return fmt.Errorf("failed to load APCLIENT_DATA config for integration test: %w", err)
	}
	if cfg.Network != network {
		return fmt.Errorf("integration apshell harness requires APCLIENT_DATA network %s, got %q in %s", network, cfg.Network, filepath.Join(clientData, "config.yaml"))
	}
	algodCfg, err := cfg.GetAlgodConfig(network)
	if err != nil {
		return fmt.Errorf("integration apshell harness requires %s algod config in %s: %w", network, filepath.Join(clientData, "config.yaml"), err)
	}
	if strings.TrimSpace(algodCfg.Server) == "" {
		return fmt.Errorf("integration apshell harness requires non-empty %s algod server in %s", network, filepath.Join(clientData, "config.yaml"))
	}
	return nil
}

// runRaw executes apshell without connection management
func (a *ApshellHarness) runRaw(input string, args ...string) (string, error) {
	// Create command
	ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, a.binaryPath, args...)
	cmd.Dir = a.workDir

	// Set environment
	cmd.Env = append(os.Environ(), fmt.Sprintf("APCLIENT_DATA=%s", a.clientData))
	cmd.Env = append(cmd.Env, a.envVars...)

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

// SendTransaction sends a payment transaction using apshell
func (a *ApshellHarness) SendTransaction(from, to string, amount float64) (string, error) {
	// Format: send <amount> <asset> from <sender> to <receiver>
	// Note: user_auto_approve is enabled in config.yaml so no "y" needed
	input := fmt.Sprintf("send %f algo from %s to %s\nquit\n", amount, from, to)
	return a.parseTxID(input)
}

// CloseAccount closes an account by sending all remaining ALGO to the destination.
// This uses the "close <account> to <destination>" apshell command which sets
// CloseRemainderTo, returning the full balance minus fee.
func (a *ApshellHarness) CloseAccount(account, destination string) (string, error) {
	input := fmt.Sprintf("close %s to %s\nquit\n", account, destination)
	return a.parseTxID(input)
}

// parseTxID runs an apshell command and extracts the transaction ID from output.
func (a *ApshellHarness) parseTxID(input string) (string, error) {
	output, err := a.RunWithInput(input)
	if err != nil {
		return "", err
	}

	// Parse transaction ID from output
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "transaction id:") ||
			strings.Contains(lower, "transaction submitted:") {
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
