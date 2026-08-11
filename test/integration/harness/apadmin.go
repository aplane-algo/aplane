// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package harness

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/genstore"
	apkeys "github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/transport"

	"gopkg.in/yaml.v3"
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

type apadminConfig struct {
	IPCPath string `yaml:"ipc_path"`
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

	// Build apadmin with testmode tag for test harness access to test mode
	cmd := exec.Command("go", "build", "-tags", "testmode", "-o", binaryPath, "./cmd/apadmin")
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
	cmd.Env = append(
		os.Environ(),
		fmt.Sprintf("APSIGNER_DATA=%s", v.dataDir),
		"DISABLE_MEMORY_LOCK=1",
	)

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

// GenerateKey generates a new Falcon key using apadmin test mode
// The seed parameter is ignored as apadmin always generates random keys
func (v *ApAdminHarness) GenerateKey(seed string) (string, error) {
	return v.GenerateKeyWithType("aplane.falcon1024.v1")
}

// GenerateKeyWithType generates a new key of the specified type using test mode
func (v *ApAdminHarness) GenerateKeyWithType(keyType string) (string, error) {
	output, err := v.Run("--test", "generate", keyType)
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

// GenerateKeyWithTypeAndParams generates a key of the specified type with
// creation parameters over the admin IPC protocol. This is required for key
// types that need generation inputs, such as a guarded account that embeds a
// sentry_public_key. Returns the generated address and tracks it for cleanup.
func (v *ApAdminHarness) GenerateKeyWithTypeAndParams(keyType string, params map[string]string) (string, error) {
	response, err := v.ipcRequest(protocol.GenerateKeyMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeGenerateKey,
			ID:   fmt.Sprintf("generate-%d", time.Now().UnixNano()),
		},
		KeyType:    keyType,
		Parameters: params,
	}, 30*time.Second)
	if err != nil {
		return "", err
	}

	var result protocol.GenerateResultMessage
	if err := json.Unmarshal(response, &result); err != nil {
		return "", fmt.Errorf("failed to parse generate result: %w", err)
	}
	if !result.Success {
		return "", fmt.Errorf("generate %s failed: %s", keyType, result.Error)
	}
	if result.Address == "" {
		return "", fmt.Errorf("generate %s succeeded but returned an empty address", keyType)
	}
	v.createdKeys = append(v.createdKeys, result.Address)
	return result.Address, nil
}

// ImportKey imports a key from mnemonic using apadmin test mode
func (v *ApAdminHarness) ImportKey(mnemonic string) (string, error) {
	return v.ImportKeyWithType("ed25519", mnemonic)
}

// ImportFundingKey imports TEST_FUNDING_MNEMONIC using its fixed integration
// contract: the funding account is always protocol-native Falcon-1024.
func (v *ApAdminHarness) ImportFundingKey(mnemonic string) (string, error) {
	return v.ImportKeyWithType("falcon1024", mnemonic)
}

// ImportKeyWithType imports a key of the specified type from mnemonic using test mode.
// Note: Imported keys are NOT tracked for cleanup since they are pre-existing.
func (v *ApAdminHarness) ImportKeyWithType(keyType, mnemonic string) (string, error) {
	// Build args: --test import <keyType> <word1> <word2> ...
	args := []string{"--test", "import", keyType}
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

// ImportKeyWithTypeAndParams imports a key with creation parameters over the admin IPC protocol.
func (v *ApAdminHarness) ImportKeyWithTypeAndParams(keyType, mnemonic string, params map[string]string) (string, error) {
	response, err := v.ipcRequest(protocol.ImportKeyMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeImportKey,
			ID:   fmt.Sprintf("import-%d", time.Now().UnixNano()),
		},
		KeyType:    keyType,
		Mnemonic:   mnemonic,
		Parameters: params,
	}, 30*time.Second)
	if err != nil {
		return "", err
	}

	var result protocol.ImportResultMessage
	if err := json.Unmarshal(response, &result); err != nil {
		return "", fmt.Errorf("failed to parse import result: %w", err)
	}
	if !result.Success {
		return "", fmt.Errorf("import failed: %s", result.Error)
	}
	if result.Address == "" {
		return "", fmt.Errorf("import succeeded but returned an empty address")
	}
	return result.Address, nil
}

// ActivateKeyType activates a library-gated key type for the current identity
// over the admin IPC protocol. Used by integration tests that need to
// exercise providers which default to AvailabilityLibrary.
func (v *ApAdminHarness) ActivateKeyType(keyType string) error {
	response, err := v.ipcRequest(protocol.ActivateKeyTypeMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeActivateKeyType,
			ID:   fmt.Sprintf("activate-%d", time.Now().UnixNano()),
		},
		KeyType: keyType,
	}, 30*time.Second)
	if err != nil {
		return err
	}
	var result protocol.ActivateKeyTypeResultMessage
	if err := json.Unmarshal(response, &result); err != nil {
		return fmt.Errorf("failed to parse activate result: %w", err)
	}
	if !result.Success {
		return fmt.Errorf("activate %s failed: %s", keyType, result.Error)
	}
	return nil
}

// DeactivateKeyType deactivates or disables a key type for the current identity
// over the admin IPC protocol and returns the structured protocol result.
func (v *ApAdminHarness) DeactivateKeyType(keyType string) (*protocol.DeactivateKeyTypeResultMessage, error) {
	response, err := v.ipcRequest(protocol.DeactivateKeyTypeMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeDeactivateKeyType,
			ID:   fmt.Sprintf("deactivate-%d", time.Now().UnixNano()),
		},
		KeyType: keyType,
	}, 30*time.Second)
	if err != nil {
		return nil, err
	}
	var result protocol.DeactivateKeyTypeResultMessage
	if err := json.Unmarshal(response, &result); err != nil {
		return nil, fmt.Errorf("failed to parse deactivate result: %w", err)
	}
	return &result, nil
}

// BackupResult contains the managed archive path returned by signer backup.
type BackupResult struct {
	ArchivePath string
}

// CreateBackup triggers signer-managed backup for the bound identity and returns
// the signer-managed archive path.
func (v *ApAdminHarness) CreateBackup(exportPassphrase string) (*BackupResult, error) {
	response, err := v.ipcRequest(protocol.BackupMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeBackup,
			ID:   fmt.Sprintf("backup-%d", time.Now().UnixNano()),
		},
		ExportPassphrase: protocol.NewSensitiveBytes(exportPassphrase),
	}, 30*time.Second)
	if err != nil {
		return nil, err
	}

	var result protocol.BackupResultMessage
	if err := json.Unmarshal(response, &result); err != nil {
		return nil, fmt.Errorf("failed to parse backup result: %w", err)
	}
	if !result.Success {
		return nil, fmt.Errorf("backup failed: %s", result.Error)
	}
	if result.ArchivePath == "" {
		return nil, fmt.Errorf("backup succeeded but returned an empty archive path")
	}
	return &BackupResult{ArchivePath: result.ArchivePath}, nil
}

func (v *ApAdminHarness) ipcRequest(msg interface{}, timeout time.Duration) ([]byte, error) {
	passphrase, err := v.testPassphrase()
	if err != nil {
		return nil, err
	}
	ipcPath, err := v.ipcPath()
	if err != nil {
		return nil, err
	}

	ipcClient := transport.NewIPC(ipcPath)
	if err := ipcClient.Dial(); err != nil {
		return nil, fmt.Errorf("failed to dial signer IPC: %w", err)
	}
	defer ipcClient.Close()

	if err := ipcClient.Authenticate(passphrase, 10*time.Second); err != nil {
		return nil, fmt.Errorf("failed to authenticate signer IPC: %w", err)
	}
	status, err := ipcClient.WaitForStatus(10 * time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to receive signer status over IPC: %w", err)
	}
	if status.State == "locked" {
		result, err := ipcClient.Unlock(passphrase, timeout)
		if err != nil {
			return nil, fmt.Errorf("failed to unlock signer over IPC: %w", err)
		}
		if !result.Success {
			return nil, fmt.Errorf("failed to unlock signer over IPC: %s", result.Error)
		}
	}

	return ipcClient.SendAndReceive(msg, timeout)
}

func (v *ApAdminHarness) ipcPath() (string, error) {
	configPath := filepath.Join(v.dataDir, "config.yaml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return "", fmt.Errorf("failed to read signer config %s: %w", configPath, err)
	}

	var cfg apadminConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return "", fmt.Errorf("failed to parse signer config %s: %w", configPath, err)
	}
	if cfg.IPCPath == "" {
		return filepath.Join(v.dataDir, "aplane.sock"), nil
	}
	if filepath.IsAbs(cfg.IPCPath) {
		return cfg.IPCPath, nil
	}
	return filepath.Join(v.dataDir, cfg.IPCPath), nil
}

func (v *ApAdminHarness) testPassphrase() (string, error) {
	if passphrase := os.Getenv("TEST_PASSPHRASE"); passphrase != "" {
		return passphrase, nil
	}

	passFile := filepath.Join(v.dataDir, "passphrase")
	data, err := os.ReadFile(passFile)
	if err != nil {
		return "", fmt.Errorf("TEST_PASSPHRASE not set and cannot read %s: %w", passFile, err)
	}
	passphrase := strings.TrimSpace(string(data))
	if passphrase == "" {
		return "", fmt.Errorf("passphrase file %s is empty", passFile)
	}
	return passphrase, nil
}

// DeleteKey deletes a key using apadmin test mode
func (v *ApAdminHarness) DeleteKey(address string) error {
	_, err := v.Run("--test", "delete", address)
	return err
}

// DeleteGeneratedKey deletes a key generated by this harness and removes it
// from deferred cleanup tracking.
func (v *ApAdminHarness) DeleteGeneratedKey(address string) error {
	if err := v.DeleteKey(address); err != nil {
		return err
	}
	v.forgetCreatedKey(address)
	return nil
}

func (v *ApAdminHarness) forgetCreatedKey(address string) {
	kept := v.createdKeys[:0]
	for _, addr := range v.createdKeys {
		if addr != address {
			kept = append(kept, addr)
		}
	}
	v.createdKeys = kept
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

// removeKeyFile removes a managed credential directly from the keystore directory.
// Returns true if the file was found and removed.
func (v *ApAdminHarness) removeKeyFile(addr string) bool {
	active, err := genstore.ResolveActive(storepaths.NewPaths(v.dataDir), "default")
	if err != nil {
		return false
	}
	keysDir := active.KeysDir()
	candidates := []string{
		filepath.Join(keysDir, addr+apkeys.AccountKeyExtension),
		filepath.Join(keysDir, addr+apkeys.SentryCredentialExtension),
	}
	for _, path := range candidates {
		if err := os.Remove(path); err == nil {
			return true
		}
	}
	return false
}

// UnlockSigner unlocks the signer using test mode
func (v *ApAdminHarness) UnlockSigner() error {
	_, err := v.Run("--test", "unlock")
	return err
}

// StartUnlockBackground starts apadmin in background mode to keep signer unlocked
// Call StopUnlockBackground when done
func (v *ApAdminHarness) StartUnlockBackground() error {
	if err := v.Build(); err != nil {
		return err
	}

	ctx := context.Background()
	v.unlockProcess = exec.CommandContext(ctx, v.binaryPath, "--test", "unlock", "--wait")
	v.unlockProcess.Dir = v.dataDir
	// Pass through environment (APSIGNER_DATA, TEST_PASSPHRASE already set)
	v.unlockProcess.Env = append(
		os.Environ(),
		fmt.Sprintf("APSIGNER_DATA=%s", v.dataDir),
		"DISABLE_MEMORY_LOCK=1",
	)

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
