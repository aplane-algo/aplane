// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storeintegration_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

const storeIntegrationEnv = "APLANE_STORE_INTEGRATION"

var suiteBinaries binarySet

type binarySet struct {
	apsigner string
	apstore  string
	apadmin  string
	testmode bool
}

func TestMain(m *testing.M) {
	if os.Getenv(storeIntegrationEnv) != "1" {
		os.Exit(0)
	}
	root, err := projectRoot()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if binDir := strings.TrimSpace(os.Getenv("APLANE_TEST_BIN_DIR")); binDir != "" {
		suiteBinaries = binarySet{
			apsigner: filepath.Join(binDir, "apsigner"),
			apstore:  filepath.Join(binDir, "apstore"),
			apadmin:  filepath.Join(binDir, "apadmin"),
		}
	} else {
		buildDir, err := os.MkdirTemp("", "aplane-store-integration-bins-")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer func() { _ = os.RemoveAll(buildDir) }()
		suiteBinaries = binarySet{
			apsigner: filepath.Join(buildDir, "apsigner"),
			apstore:  filepath.Join(buildDir, "apstore"),
			apadmin:  filepath.Join(buildDir, "apadmin"),
			testmode: true,
		}
		builds := []struct {
			output string
			args   []string
		}{
			{suiteBinaries.apsigner, []string{"build", "-tags", "storetest", "-o", suiteBinaries.apsigner, "./cmd/apsigner"}},
			{suiteBinaries.apstore, []string{"build", "-o", suiteBinaries.apstore, "./cmd/apstore"}},
			{suiteBinaries.apadmin, []string{"build", "-tags", "testmode", "-o", suiteBinaries.apadmin, "./cmd/apadmin"}},
		}
		for _, build := range builds {
			cmd := exec.Command("go", build.args...)
			cmd.Dir = root
			cmd.Env = append(os.Environ(), "GOCACHE="+filepath.Join(buildDir, "go-cache"))
			if output, err := cmd.CombinedOutput(); err != nil {
				fmt.Fprintf(os.Stderr, "build %s: %v\n%s", build.output, err, output)
				os.Exit(1)
			}
		}
	}
	for _, path := range []string{suiteBinaries.apsigner, suiteBinaries.apstore, suiteBinaries.apadmin} {
		if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
			fmt.Fprintf(os.Stderr, "store integration binary unavailable: %s\n", path)
			os.Exit(1)
		}
	}
	os.Exit(m.Run())
}

func projectRoot() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("resolve store integration source path")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		return "", fmt.Errorf("resolve project root: %w", err)
	}
	return root, nil
}

type storeEnv struct {
	t          *testing.T
	root       string
	dataDir    string
	passphrase string
	port       int
	signer     *signerProcess
	checkpoint checkpointConfig
}

type checkpointConfig struct {
	name string
	dir  string
	mode string
}

func newFreshStoreEnv(t *testing.T, passphrase string) *storeEnv {
	t.Helper()
	root := t.TempDir()
	dataDir := filepath.Join(root, "signer")
	sshDir := filepath.Join(dataDir, ".ssh")
	for _, dir := range []string{dataDir, filepath.Join(dataDir, "run"), sshDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatalf("create fresh store directory: %v", err)
		}
	}
	port := reservePort(t)
	sshPort := reservePort(t)
	_, hostPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate signer SSH host key: %v", err)
	}
	privateBlock, err := ssh.MarshalPrivateKey(hostPrivateKey, "")
	if err != nil {
		t.Fatalf("marshal signer SSH host key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sshDir, "host_key"), pem.EncodeToMemory(privateBlock), 0o600); err != nil {
		t.Fatalf("write signer SSH host key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sshDir, "authorized_keys"), nil, 0o600); err != nil {
		t.Fatalf("write signer SSH authorized keys: %v", err)
	}
	config := fmt.Sprintf(`ipc_path: run/aplane.sock
endpoint:
  signer_port: %d
  ssh:
    port: %d
    host_key_path: .ssh/host_key
    authorized_keys_path: .ssh/authorized_keys
passphrase_timeout: "0m"
lock_on_disconnect: false
user_auto_approve: true
networks:
  testnet:
    algod:
      server: http://127.0.0.1:1
      token: ""
teal_compile_network: testnet
require_memory_protection: false
`, port, sshPort)
	if err := os.WriteFile(filepath.Join(dataDir, "config.yaml"), []byte(config), 0o600); err != nil {
		t.Fatalf("write signer config: %v", err)
	}
	env := &storeEnv{t: t, root: root, dataDir: dataDir, passphrase: passphrase, port: port}
	t.Cleanup(func() { _ = env.stopSigner() })
	return env
}

func reservePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve signer port: %v", err)
	}
	defer func() { _ = listener.Close() }()
	return listener.Addr().(*net.TCPAddr).Port
}

func (e *storeEnv) initialize() {
	e.t.Helper()
	output, err := e.runApstore(e.passphrase+"\n"+e.passphrase+"\n", nil, "initialize")
	if err != nil {
		e.t.Fatalf("initialize fresh store: %v\n%s", err, output)
	}
}

func (e *storeEnv) startSigner(passphrase string) {
	e.t.Helper()
	if e.signer != nil {
		e.t.Fatal("signer already started")
	}
	logPath := filepath.Join(e.root, fmt.Sprintf("apsigner-%d.log", time.Now().UnixNano()))
	logFile, err := os.Create(logPath)
	if err != nil {
		e.t.Fatalf("create signer log: %v", err)
	}
	cmd := exec.Command(suiteBinaries.apsigner)
	cmd.Dir = e.dataDir
	env := append(os.Environ(),
		"APSIGNER_DATA="+e.dataDir,
		"TEST_PASSPHRASE="+passphrase,
		"DISABLE_MEMORY_LOCK=1",
	)
	if e.checkpoint.name != "" {
		env = append(env,
			"APLANE_STORE_TEST_CHECKPOINT="+e.checkpoint.name,
			"APLANE_STORE_TEST_CHECKPOINT_DIR="+e.checkpoint.dir,
			"APLANE_STORE_TEST_CHECKPOINT_MODE="+e.checkpoint.mode,
		)
	}
	cmd.Env = env
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		e.t.Fatalf("start apsigner: %v", err)
	}
	e.signer = &signerProcess{cmd: cmd, logFile: logFile, logPath: logPath}
	if err := e.waitForHealth(10 * time.Second); err != nil {
		logs, _ := os.ReadFile(logPath)
		_ = e.crashSigner()
		e.t.Fatalf("wait for apsigner: %v\n%s", err, logs)
	}
}

func (e *storeEnv) waitForHealth(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	url := fmt.Sprintf("http://127.0.0.1:%d/health", e.port)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url) // #nosec G107 -- test-only loopback URL
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for %s", url)
}

type signerProcess struct {
	cmd     *exec.Cmd
	logFile *os.File
	logPath string
	waited  bool
}

func (e *storeEnv) stopSigner() error {
	if e.signer == nil {
		return nil
	}
	p := e.signer
	e.signer = nil
	if p.cmd.Process != nil && !p.waited {
		_ = p.cmd.Process.Signal(os.Interrupt)
		done := make(chan error, 1)
		go func() { done <- p.cmd.Wait() }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			_ = p.cmd.Process.Kill()
			<-done
		}
		p.waited = true
	}
	return p.logFile.Close()
}

func (e *storeEnv) crashSigner() error {
	if e.signer == nil {
		return nil
	}
	p := e.signer
	e.signer = nil
	if p.cmd.Process != nil && !p.waited {
		if err := p.cmd.Process.Kill(); err != nil {
			return err
		}
		_ = p.cmd.Wait()
		p.waited = true
	}
	return p.logFile.Close()
}

func (e *storeEnv) configureCheckpoint(name, mode string) {
	e.t.Helper()
	if !suiteBinaries.testmode {
		e.t.Skip("process checkpoints require the storetest apsigner build")
	}
	dir := filepath.Join(e.root, "checkpoint-"+strings.ReplaceAll(name, ".", "-"))
	e.checkpoint = checkpointConfig{name: name, dir: dir, mode: mode}
}

func (e *storeEnv) clearCheckpoint() {
	e.checkpoint = checkpointConfig{}
}

func (e *storeEnv) waitForCheckpoint(timeout time.Duration) {
	e.t.Helper()
	path := filepath.Join(e.checkpoint.dir, "reached")
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(path); err == nil && strings.TrimSpace(string(data)) == e.checkpoint.name {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	e.t.Fatalf("checkpoint %s was not reached", e.checkpoint.name)
}

func (e *storeEnv) runApstore(input string, extraEnv []string, args ...string) (string, error) {
	cmdArgs := append([]string{"-d", e.dataDir}, args...)
	return runCommand(e.t, suiteBinaries.apstore, e.dataDir, input, append([]string{"APSIGNER_DATA=" + e.dataDir}, extraEnv...), cmdArgs...)
}

func (e *storeEnv) startApstore(input string, extraEnv []string, args ...string) *commandHandle {
	e.t.Helper()
	cmdArgs := append([]string{"-d", e.dataDir}, args...)
	return startCommand(e.t, suiteBinaries.apstore, e.dataDir, input, append([]string{"APSIGNER_DATA=" + e.dataDir}, extraEnv...), cmdArgs...)
}

func (e *storeEnv) runApadmin(args ...string) (string, error) {
	return runCommand(e.t, suiteBinaries.apadmin, e.dataDir, "", []string{
		"APSIGNER_DATA=" + e.dataDir,
		"TEST_PASSPHRASE=" + e.passphrase,
		"DISABLE_MEMORY_LOCK=1",
	}, args...)
}

func runCommand(t *testing.T, binary, dir, input string, extraEnv []string, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), extraEnv...)
	cmd.Stdin = strings.NewReader(input)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	err := cmd.Run()
	if ctx.Err() != nil {
		return output.String(), ctx.Err()
	}
	return output.String(), err
}

type commandHandle struct {
	cmd    *exec.Cmd
	output *os.File
	path   string
	waited bool
}

func startCommand(t *testing.T, binary, dir, input string, extraEnv []string, args ...string) *commandHandle {
	t.Helper()
	output, err := os.CreateTemp(t.TempDir(), "command-output-")
	if err != nil {
		t.Fatalf("create command output: %v", err)
	}
	cmd := exec.Command(binary, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), extraEnv...)
	cmd.Stdin = strings.NewReader(input)
	cmd.Stdout = output
	cmd.Stderr = output
	if err := cmd.Start(); err != nil {
		_ = output.Close()
		t.Fatalf("start %s: %v", filepath.Base(binary), err)
	}
	return &commandHandle{cmd: cmd, output: output, path: output.Name()}
}

func (h *commandHandle) wait(timeout time.Duration) (string, error) {
	done := make(chan error, 1)
	go func() { done <- h.cmd.Wait() }()
	var err error
	select {
	case err = <-done:
	case <-time.After(timeout):
		_ = h.cmd.Process.Kill()
		err = <-done
		if err == nil {
			err = context.DeadlineExceeded
		}
	}
	h.waited = true
	_ = h.output.Sync()
	_ = h.output.Close()
	data, readErr := os.ReadFile(h.path)
	if readErr != nil {
		return "", readErr
	}
	return string(data), err
}

func copyFile(t *testing.T, source, destination string) {
	t.Helper()
	in, err := os.Open(source)
	if err != nil {
		t.Fatalf("open %s: %v", source, err)
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("create %s: %v", destination, err)
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		t.Fatalf("copy %s: %v", source, err)
	}
	if err := out.Close(); err != nil {
		t.Fatalf("close %s: %v", destination, err)
	}
}
