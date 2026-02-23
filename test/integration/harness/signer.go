// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package harness

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// SignerHarness manages an Signer process for testing.
// It assumes APSIGNER_DATA and TEST_PASSPHRASE are already set in the environment.
type SignerHarness struct {
	t          *testing.T
	cmd        *exec.Cmd
	dataDir    string // From APSIGNER_DATA
	buildDir   string // Temp dir for binary
	port       string // Read from config.yaml
	storeDir   string // Store directory from config.yaml
	logFile    *os.File
	stdout     io.ReadCloser
	stderr     io.ReadCloser
	cancelFunc context.CancelFunc
}

// signerConfig represents the relevant parts of apsignerd's config.yaml
type signerConfig struct {
	SignerPort int    `yaml:"signer_port"`
	Store      string `yaml:"store"`
}

// NewSignerHarness creates a new Signer test harness.
// Requires APSIGNER_DATA environment variable to be set.
// TEST_PASSPHRASE can be set in environment or read from $APSIGNER_DATA/passphrase.
func NewSignerHarness(t *testing.T) *SignerHarness {
	// Get data directory from environment
	dataDir := os.Getenv("APSIGNER_DATA")
	if dataDir == "" {
		t.Fatal("APSIGNER_DATA environment variable must be set")
	}

	// Verify data directory exists
	if _, err := os.Stat(dataDir); os.IsNotExist(err) {
		t.Fatalf("APSIGNER_DATA directory does not exist: %s", dataDir)
	}

	// If TEST_PASSPHRASE not set, try to read from passphrase file
	if os.Getenv("TEST_PASSPHRASE") == "" {
		passFile := filepath.Join(dataDir, "passphrase")
		data, err := os.ReadFile(passFile)
		if err != nil {
			t.Fatalf("TEST_PASSPHRASE not set and cannot read %s: %v", passFile, err)
		}
		passphrase := strings.TrimSpace(string(data))
		if passphrase == "" {
			t.Fatalf("Passphrase file %s is empty", passFile)
		}
		if err := os.Setenv("TEST_PASSPHRASE", passphrase); err != nil {
			t.Fatalf("Failed to set TEST_PASSPHRASE: %v", err)
		}
		t.Logf("Read passphrase from %s", passFile)
	}

	// Read port from config.yaml
	configPath := filepath.Join(dataDir, "config.yaml")
	configData, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("Failed to read config.yaml: %v", err)
	}
	var cfg signerConfig
	if err := yaml.Unmarshal(configData, &cfg); err != nil {
		t.Fatalf("Failed to parse config.yaml: %v", err)
	}
	if cfg.SignerPort == 0 {
		t.Fatal("signer_port not set in config.yaml")
	}
	if cfg.Store == "" {
		t.Fatal("store not set in config.yaml")
	}
	port := fmt.Sprintf("%d", cfg.SignerPort)

	// Create temp build directory for binary
	buildDir := filepath.Join(t.TempDir(), "aplane-build")
	if err := os.MkdirAll(buildDir, 0755); err != nil {
		t.Fatalf("Failed to create build directory: %v", err)
	}

	return &SignerHarness{
		t:        t,
		dataDir:  dataDir,
		buildDir: buildDir,
		port:     port,
		storeDir: cfg.Store,
	}
}

// Build compiles Signer if needed
func (s *SignerHarness) Build() error {
	// Check if binary already exists
	binaryPath := filepath.Join(s.buildDir, "apsignerd")
	if _, err := os.Stat(binaryPath); err == nil {
		return nil // Already built
	}

	// Get project root (where go.mod is)
	projectRoot, err := findProjectRoot()
	if err != nil {
		return fmt.Errorf("failed to find project root: %w", err)
	}

	// Build Signer
	cmd := exec.Command("go", "build", "-o", binaryPath, "./cmd/apsignerd")
	cmd.Dir = projectRoot
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to build apsignerd: %w\nOutput: %s", err, output)
	}

	return nil
}

// Start launches the Signer process
func (s *SignerHarness) Start() error {
	// Check if the port is already in use (e.g., existing apsignerd running)
	listener, err := net.Listen("tcp", "127.0.0.1:"+s.port)
	if err != nil {
		return fmt.Errorf("port %s already in use - stop existing apsignerd before running integration tests", s.port)
	}
	_ = listener.Close()

	// Ensure it's built
	if err := s.Build(); err != nil {
		return err
	}

	// Create context for cancellation
	ctx, cancel := context.WithCancel(context.Background())
	s.cancelFunc = cancel

	// Create log file in build directory
	logPath := filepath.Join(s.buildDir, "aplane.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		return fmt.Errorf("failed to create log file: %w", err)
	}
	s.logFile = logFile

	// Prepare command - apsignerd reads port from config.yaml
	binaryPath := filepath.Join(s.buildDir, "apsignerd")
	s.cmd = exec.CommandContext(ctx, binaryPath)
	s.cmd.Dir = s.dataDir

	// Pass through environment (APSIGNER_DATA, TEST_PASSPHRASE already set)
	// Add DISABLE_MEMORY_LOCK for tests
	s.cmd.Env = append(os.Environ(), "DISABLE_MEMORY_LOCK=1")

	// Capture stdout and stderr
	s.stdout, err = s.cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}
	s.stderr, err = s.cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	// Start output capture goroutines
	go s.captureOutput(s.stdout, "[STDOUT]")
	go s.captureOutput(s.stderr, "[STDERR]")

	// Start the process
	if err := s.cmd.Start(); err != nil {
		return fmt.Errorf("failed to start apsignerd: %w", err)
	}

	// Wait for it to be ready
	if err := s.WaitForReady(10 * time.Second); err != nil {
		_ = s.Stop()
		return fmt.Errorf("apsignerd failed to start: %w", err)
	}

	s.t.Logf("Signer started on port %s", s.port)
	return nil
}

// Stop terminates the Signer process
func (s *SignerHarness) Stop() error {
	if s.cmd == nil || s.cmd.Process == nil {
		return nil
	}

	// Cancel context to signal shutdown
	if s.cancelFunc != nil {
		s.cancelFunc()
	}

	// Give it a moment to shut down gracefully
	done := make(chan error, 1)
	go func() {
		done <- s.cmd.Wait()
	}()

	select {
	case <-done:
		// Graceful shutdown
	case <-time.After(5 * time.Second):
		// Force kill if it doesn't stop
		if err := s.cmd.Process.Kill(); err != nil {
			return fmt.Errorf("failed to kill apsignerd: %w", err)
		}
		<-done
	}

	// Close log file
	if s.logFile != nil {
		_ = s.logFile.Close()
	}

	s.t.Logf("Signer stopped")
	return nil
}

// WaitForReady waits for Signer to be ready to accept connections
func (s *SignerHarness) WaitForReady(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	url := fmt.Sprintf("http://localhost:%s/health", s.port)

	for time.Now().Before(deadline) {
		// Check if process has exited
		if s.cmd.ProcessState != nil && s.cmd.ProcessState.Exited() {
			return fmt.Errorf("apsignerd process exited unexpectedly")
		}

		// Try HTTP health check
		resp, err := http.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				// Service is ready
				return nil
			}
		}

		time.Sleep(100 * time.Millisecond)
	}

	return fmt.Errorf("timeout waiting for apsignerd to be ready")
}

// GetURL returns the URL for connecting to this Signer instance
func (s *SignerHarness) GetURL() string {
	return fmt.Sprintf("http://localhost:%s", s.port)
}

// GetWorkDir returns the data directory (APSIGNER_DATA)
func (s *SignerHarness) GetWorkDir() string {
	return s.dataDir
}

// GetTokenPath returns the path to the API token file.
// Token is stored in: <dataDir>/<storeDir>/users/default/aplane.token
func (s *SignerHarness) GetTokenPath() string {
	return filepath.Join(s.dataDir, s.storeDir, "users", "default", "aplane.token")
}

// captureOutput reads from a pipe and writes to log file
func (s *SignerHarness) captureOutput(r io.Reader, prefix string) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		logLine := fmt.Sprintf("%s %s %s\n", time.Now().Format("15:04:05.000"), prefix, line)

		// Write to log file
		if s.logFile != nil {
			_, _ = s.logFile.WriteString(logLine)
		}

		// Also log to test output in verbose mode
		if testing.Verbose() {
			s.t.Log(strings.TrimSpace(logLine))
		}
	}
}

// GetLogs returns the contents of the log file
func (s *SignerHarness) GetLogs() (string, error) {
	logPath := filepath.Join(s.buildDir, "aplane.log")
	data, err := os.ReadFile(logPath)
	if err != nil {
		return "", fmt.Errorf("failed to read log file: %w", err)
	}
	return string(data), nil
}
