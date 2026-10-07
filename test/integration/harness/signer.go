// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

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
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/sshtunnel"
)

// SignerHarness manages an Signer process for testing.
// It assumes APSIGNER_DATA and TEST_PASSPHRASE are already set in the environment.
type SignerHarness struct {
	t                     *testing.T
	cmd                   *exec.Cmd
	dataDir               string // From APSIGNER_DATA
	buildDir              string // Temp dir for binary
	port                  string // Read from config.yaml
	logFile               *os.File
	stdout                io.ReadCloser
	stderr                io.ReadCloser
	cancelFunc            context.CancelFunc
	omitTestPassphraseEnv bool

	// The REST API is reachable only through the signer's SSH server. GetURL
	// opens a tunnel with the client identity from APCLIENT_DATA on first
	// use and reopens it after a restart.
	tunnelMu     sync.Mutex
	tunnel       *sshtunnel.Client
	tunnelCancel context.CancelFunc
	tunnelURL    string
}

// OmitTestPassphraseEnv starts apsigner without TEST_PASSPHRASE so tests can
// exercise configured startup unlock mechanisms such as passphrase_command_argv.
func (s *SignerHarness) OmitTestPassphraseEnv() {
	s.omitTestPassphraseEnv = true
}

// signerConfig represents the relevant parts of apsigner's config.yaml
type signerConfig struct {
	Endpoint struct {
		SignerPort int `yaml:"signer_port"`
	} `yaml:"endpoint"`
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
	if cfg.Endpoint.SignerPort == 0 {
		t.Fatal("endpoint.signer_port not set in config.yaml")
	}
	port := fmt.Sprintf("%d", cfg.Endpoint.SignerPort)

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
	}
}

// Build compiles Signer if needed
func (s *SignerHarness) Build() error {
	// Check if binary already exists
	binaryPath := filepath.Join(s.buildDir, "apsigner")
	if _, err := os.Stat(binaryPath); err == nil {
		return nil // Already built
	}

	// Get project root (where go.mod is)
	projectRoot, err := findProjectRoot()
	if err != nil {
		return fmt.Errorf("failed to find project root: %w", err)
	}

	// Build Signer
	cmd := exec.Command("go", "build", "-o", binaryPath, "./cmd/apsigner")
	cmd.Dir = projectRoot
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to build apsigner: %w\nOutput: %s", err, output)
	}

	return nil
}

// Start launches the Signer process
func (s *SignerHarness) Start() error {
	// Check if the port is already in use (e.g., existing apsigner running)
	listener, err := net.Listen("tcp", "127.0.0.1:"+s.port)
	if err != nil {
		return fmt.Errorf("port %s already in use - stop existing apsigner before running integration tests", s.port)
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

	// Prepare command - apsigner reads port from config.yaml
	binaryPath := filepath.Join(s.buildDir, "apsigner")
	s.cmd = exec.CommandContext(ctx, binaryPath)
	s.cmd.Dir = s.dataDir

	// Pass through environment (APSIGNER_DATA, TEST_PASSPHRASE already set)
	// Add DISABLE_MEMORY_LOCK for tests
	env := os.Environ()
	if s.omitTestPassphraseEnv {
		env = withoutEnvKey(env, "TEST_PASSPHRASE")
	}
	s.cmd.Env = append(
		env,
		fmt.Sprintf("APSIGNER_DATA=%s", s.dataDir),
		"DISABLE_MEMORY_LOCK=1",
	)

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
		return fmt.Errorf("failed to start apsigner: %w", err)
	}

	// Wait for it to be ready
	if err := s.WaitForReady(10 * time.Second); err != nil {
		_ = s.Stop()
		return fmt.Errorf("apsigner failed to start: %w", err)
	}

	s.t.Logf("Signer started on port %s", s.port)
	return nil
}

func withoutEnvKey(env []string, key string) []string {
	prefix := key + "="
	filtered := env[:0]
	for _, entry := range env {
		if strings.HasPrefix(entry, prefix) {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered
}

// Stop terminates the Signer process
func (s *SignerHarness) Stop() error {
	if s.cmd == nil || s.cmd.Process == nil {
		return nil
	}

	s.tunnelMu.Lock()
	s.closeTunnelLocked()
	s.tunnelMu.Unlock()

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
			return fmt.Errorf("failed to kill apsigner: %w", err)
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
			return fmt.Errorf("apsigner process exited unexpectedly")
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

	return fmt.Errorf("timeout waiting for apsigner to be ready")
}

// GetURL returns a loopback URL that reaches this Signer's REST API through
// an SSH tunnel authenticated with the client identity configured in
// APCLIENT_DATA. The tunnel is opened on first use and reopened when the
// previous one has dropped, for example after a signer restart.
func (s *SignerHarness) GetURL() string {
	s.t.Helper()
	s.tunnelMu.Lock()
	defer s.tunnelMu.Unlock()
	if s.tunnel != nil && s.tunnel.IsConnected() {
		return s.tunnelURL
	}
	s.closeTunnelLocked()

	clientDataDir := os.Getenv("APCLIENT_DATA")
	cfg, err := config.LoadConfig(clientDataDir)
	if err != nil {
		s.t.Fatalf("load client config for signer tunnel: %v", err)
	}
	_, endpoint, ok := cfg.Endpoints.DefaultEndpoint()
	if !ok {
		s.t.Fatalf("client endpoint registry in %s has no default signer endpoint", clientDataDir)
	}
	sshCfg, err := config.ResolveClientEndpointSSH(endpoint)
	if err != nil {
		s.t.Fatalf("resolve client signer endpoint: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		s.t.Fatalf("allocate tunnel port: %v", err)
	}
	localPort := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()

	client := sshtunnel.NewClient(sshCfg.Host, sshCfg.Port, localPort, sshCfg.IdentityFile, sshCfg.KnownHostsPath)
	ctx, cancel := context.WithCancel(context.Background())
	if err := client.ConnectWithKey(ctx); err != nil {
		cancel()
		s.t.Fatalf("open signer tunnel with %s: %v", sshCfg.IdentityFile, err)
	}
	if err := client.StartPortForwarding(ctx); err != nil {
		cancel()
		_ = client.Close()
		s.t.Fatalf("forward signer tunnel: %v", err)
	}
	s.tunnel, s.tunnelCancel = client, cancel
	s.tunnelURL = fmt.Sprintf("http://127.0.0.1:%d", localPort)
	return s.tunnelURL
}

// LoopbackURL returns the signer's loopback REST listener, which carries no
// client identity and therefore answers only /health.
func (s *SignerHarness) LoopbackURL() string {
	return fmt.Sprintf("http://localhost:%s", s.port)
}

func (s *SignerHarness) closeTunnelLocked() {
	if s.tunnel != nil {
		_ = s.tunnel.Close()
	}
	if s.tunnelCancel != nil {
		s.tunnelCancel()
	}
	s.tunnel, s.tunnelCancel, s.tunnelURL = nil, nil, ""
}

// GetWorkDir returns the data directory (APSIGNER_DATA)
func (s *SignerHarness) GetWorkDir() string {
	return s.dataDir
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
