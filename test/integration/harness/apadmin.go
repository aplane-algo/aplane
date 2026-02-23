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

// ApAdminHarness manages apadmin CLI testing.
// It assumes APSIGNER_DATA and TEST_PASSPHRASE are already set in the environment.
type ApAdminHarness struct {
	t             *testing.T
	dataDir       string
	buildDir      string
	binaryPath    string
	unlockProcess *exec.Cmd
	createdKeys   []string // Track keys created for cleanup
}

// NewApAdminHarness creates a new apadmin CLI test harness.
// It uses the same data directory as the SignerHarness (from APSIGNER_DATA).
func NewApAdminHarness(t *testing.T, signerWorkDir string) *ApAdminHarness {
	// Create temp build directory for binary
	buildDir := filepath.Join(t.TempDir(), "apadmin-build")
	if err := os.MkdirAll(buildDir, 0755); err != nil {
		t.Fatalf("Failed to create build directory: %v", err)
	}

	return &ApAdminHarness{
		t:        t,
		dataDir:  signerWorkDir,
		buildDir: buildDir,
	}
}

// Build compiles apadmin if needed
func (v *ApAdminHarness) Build() error {
	// Build to a specific location
	binaryPath := filepath.Join(v.buildDir, "apadmin")
	v.binaryPath = binaryPath

	// Check if binary already exists
	if _, err := os.Stat(binaryPath); err == nil {
		return nil // Already built
	}

	// Get project root (where go.mod is)
	projectRoot, err := findProjectRoot()
	if err != nil {
		return fmt.Errorf("failed to find project root: %w", err)
	}

	// Build apadmin
	cmd := exec.Command("go", "build", "-o", binaryPath, "./cmd/apadmin")
	cmd.Dir = projectRoot
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to build apadmin: %w\nOutput: %s", err, output)
	}

	return nil
}

// Run executes a apadmin command and returns the output
func (v *ApAdminHarness) Run(args ...string) (string, error) {
	return v.RunWithInput("", args...)
}

// RunWithInput executes a apadmin command with stdin input
func (v *ApAdminHarness) RunWithInput(input string, args ...string) (string, error) {
	// Ensure it's built
	if err := v.Build(); err != nil {
		return "", err
	}

	// Create command
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, v.binaryPath, args...)
	cmd.Dir = v.dataDir

	// Pass through environment (APSIGNER_DATA, TEST_PASSPHRASE already set)
	// Add DISABLE_MEMORY_LOCK for tests
	cmd.Env = append(os.Environ(), "DISABLE_MEMORY_LOCK=1")

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
			v.t.Logf("apadmin stdout: %s", stdout.String())
		}
		if stderr.Len() > 0 {
			v.t.Logf("apadmin stderr: %s", stderr.String())
		}
	}

	// Return combined output
	output := stdout.String()
	if stderr.Len() > 0 {
		output += "\n" + stderr.String()
	}

	if err != nil {
		return output, fmt.Errorf("apadmin command failed: %w\nOutput: %s", err, output)
	}

	return output, nil
}

// GenerateKey generates a new Falcon key using apadmin batch mode
// The seed parameter is ignored as apadmin always generates random keys
func (v *ApAdminHarness) GenerateKey(seed string) (string, error) {
	return v.GenerateKeyWithType("falcon1024-v1")
}

// GenerateKeyWithType generates a new key of the specified type using batch mode
func (v *ApAdminHarness) GenerateKeyWithType(keyType string) (string, error) {
	output, err := v.Run("--batch", "generate", keyType)
	if err != nil {
		return "", err
	}

	// Parse the address from output
	// Looking for lines like: "Generated falcon1024 key: <address>"
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "Generated") && strings.Contains(line, "key:") {
			parts := strings.Fields(line)
			for _, part := range parts {
				if len(part) == 58 && isAlgorandAddress(part) {
					v.createdKeys = append(v.createdKeys, part)
					return part, nil
				}
			}
		}
	}

	return "", fmt.Errorf("could not find generated address in output: %s", output)
}

// ImportKey imports a key from mnemonic using apadmin batch mode
func (v *ApAdminHarness) ImportKey(mnemonic string) (string, error) {
	return v.ImportKeyWithType("ed25519", mnemonic)
}

// ImportKeyWithType imports a key of the specified type from mnemonic using batch mode.
// Note: Imported keys are NOT tracked for cleanup since they are pre-existing.
func (v *ApAdminHarness) ImportKeyWithType(keyType, mnemonic string) (string, error) {
	// Build args: --batch import <keyType> <word1> <word2> ...
	args := []string{"--batch", "import", keyType}
	args = append(args, strings.Fields(mnemonic)...)

	output, err := v.Run(args...)
	if err != nil {
		return "", err
	}

	// Parse the address from output
	// Looking for lines like: "Imported ed25519 key: <address>"
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "Imported") && strings.Contains(line, "key:") {
			parts := strings.Fields(line)
			for _, part := range parts {
				if len(part) == 58 && isAlgorandAddress(part) {
					// Don't track imported keys - they are pre-existing
					return part, nil
				}
			}
		}
	}

	return "", fmt.Errorf("could not find imported address in output: %s", output)
}

// ListKeys lists all keys using apadmin batch mode
func (v *ApAdminHarness) ListKeys() ([]string, error) {
	output, err := v.Run("--batch", "list")
	if err != nil {
		return nil, err
	}

	// Parse addresses from output
	// Each line is: <address>\t<keyType>
	var addresses []string
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) >= 1 && len(parts[0]) == 58 && isAlgorandAddress(parts[0]) {
			addresses = append(addresses, parts[0])
		}
	}

	return addresses, nil
}

// DeleteKey deletes a key using apadmin batch mode
func (v *ApAdminHarness) DeleteKey(address string) error {
	_, err := v.Run("--batch", "delete", address)
	return err
}

// Cleanup deletes all keys created during this test session.
// Call this with defer after creating the harness.
// Uses IPC delete first; falls back to direct file removal if the signer
// hasn't reloaded the key yet.
func (v *ApAdminHarness) Cleanup() {
	for _, addr := range v.createdKeys {
		if err := v.DeleteKey(addr); err != nil {
			// IPC delete failed (signer may not have detected the key yet).
			// Fall back to removing the key file directly.
			if v.removeKeyFile(addr) {
				v.t.Logf("Cleaned up key (file): %s", addr)
			} else {
				v.t.Logf("Warning: failed to delete key %s: %v", addr, err)
			}
		} else {
			v.t.Logf("Cleaned up key: %s", addr)
		}
	}
	v.createdKeys = nil
}

// removeKeyFile removes a key file directly from the keystore directory.
// Returns true if the file was found and removed.
func (v *ApAdminHarness) removeKeyFile(addr string) bool {
	// Search for ADDRESS.key in identity-scoped keystore locations
	candidates := []string{
		filepath.Join(v.dataDir, "store", "users", "default", "keys", addr+".key"),
		filepath.Join(v.dataDir, "users", "default", "keys", addr+".key"),
	}
	for _, path := range candidates {
		if err := os.Remove(path); err == nil {
			return true
		}
	}
	return false
}

// GetWorkDir returns the working directory for this harness
func (v *ApAdminHarness) GetWorkDir() string {
	return v.dataDir
}

// UnlockSigner unlocks the signer using batch mode
func (v *ApAdminHarness) UnlockSigner() error {
	_, err := v.Run("--batch", "unlock")
	return err
}

// StartUnlockBackground starts apadmin in background mode to keep signer unlocked
// Call StopUnlockBackground when done
func (v *ApAdminHarness) StartUnlockBackground() error {
	if err := v.Build(); err != nil {
		return err
	}

	ctx := context.Background()
	v.unlockProcess = exec.CommandContext(ctx, v.binaryPath, "--batch", "unlock", "--wait")
	v.unlockProcess.Dir = v.dataDir
	// Pass through environment (APSIGNER_DATA, TEST_PASSPHRASE already set)
	v.unlockProcess.Env = append(os.Environ(), "DISABLE_MEMORY_LOCK=1")

	if err := v.unlockProcess.Start(); err != nil {
		return fmt.Errorf("failed to start unlock process: %w", err)
	}

	// Give it a moment to connect and unlock
	time.Sleep(500 * time.Millisecond)

	v.t.Log("Started background unlock process")
	return nil
}

// StopUnlockBackground stops the background unlock process
func (v *ApAdminHarness) StopUnlockBackground() {
	if v.unlockProcess != nil && v.unlockProcess.Process != nil {
		_ = v.unlockProcess.Process.Kill()
		_ = v.unlockProcess.Wait()
		v.unlockProcess = nil
		v.t.Log("Stopped background unlock process")
	}
}

// isAlgorandAddress checks if a string looks like an Algorand address
func isAlgorandAddress(s string) bool {
	if len(s) != 58 {
		return false
	}

	// Algorand addresses are base32 encoded, so only contain A-Z and 2-7
	for _, c := range s {
		isUpperAlpha := c >= 'A' && c <= 'Z'
		isBase32Digit := c >= '2' && c <= '7'
		if !isUpperAlpha && !isBase32Digit {
			return false
		}
	}

	return true
}
