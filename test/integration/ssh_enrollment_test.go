// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integration_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/transport"
	"github.com/aplane-algo/aplane/test/integration/harness"

	"golang.org/x/crypto/ssh"
)

// The client's SSH key is its only credential. These tests cover the
// request-enrollment protocol (operator approval over IPC, TOFU host trust,
// agent-held keys), the registry the signer keeps, and revocation closing
// live tunnels.

func TestRequestEnrollmentHappyPathEnrollsKeyAndConnectWorks(t *testing.T) {
	env := prepareFreshEnrollmentEnv(t, false)

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	ipcClient := mustConnectIPCClient(t, signerd.GetWorkDir())
	defer ipcClient.Close()

	eng, err := engine.NewEngine(harness.IntegrationNetwork())
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	sshCfg := mustLoadClientSSHConfig(t)

	var (
		fingerprint string
		reqErr      error
		reqDone     sync.WaitGroup
		started     string
	)
	reqDone.Add(1)
	go func() {
		defer reqDone.Done()
		fingerprint, reqErr = eng.RequestEnrollmentWithContext(context.Background(),
			sshCfg.Host,
			sshCfg.Port,
			sshCfg.IdentityFile,
			sshCfg.KnownHostsPath,
			"ci-laptop",
			func(host, hostFingerprint string) (bool, error) {
				if host == "" || hostFingerprint == "" {
					t.Errorf("unexpected empty host-key approval values: host=%q fingerprint=%q", host, hostFingerprint)
				}
				return true, nil
			},
			func(fp string) { started = fp },
		)
	}()

	req := mustReadIPCEnrollmentRequest(t, ipcClient, 10*time.Second)
	if req.SSHFingerprint == "" {
		t.Fatal("expected SSH fingerprint in enrollment request")
	}
	if req.Label != "ci-laptop" {
		t.Fatalf("enrollment request label = %q, want ci-laptop", req.Label)
	}
	mustRespondIPCEnrollmentRequest(t, ipcClient, req.ID, true)
	reqDone.Wait()
	if reqErr != nil {
		t.Fatalf("engine request-enrollment failed unexpectedly: %v", reqErr)
	}
	want := mustClientKeyFingerprint(t, env.ClientPublicKeyPath)
	if fingerprint != want || req.SSHFingerprint != want || started != want {
		t.Fatalf("fingerprints: enrolled %q, requested %q, started %q, want %q", fingerprint, req.SSHFingerprint, started, want)
	}

	knownHostsData, err := os.ReadFile(env.KnownHostsPath)
	if err != nil {
		t.Fatalf("failed to read known_hosts: %v", err)
	}
	if !strings.Contains(string(knownHostsData), fmt.Sprintf("[%s]:%d", sshCfg.Host, sshCfg.Port)) {
		t.Fatalf("known_hosts does not contain expected host entry:\n%s", string(knownHostsData))
	}
	requireEnrolledKeys(t, env, 1)

	apshell := harness.NewApshellHarness(t)
	connectOutput, err := apshell.RunWithInput("quit\n")
	if err != nil {
		t.Fatalf("expected apshell startup auto-connect to succeed: %v\noutput:\n%s", err, connectOutput)
	}
	if !strings.Contains(connectOutput, "Signer verified via tunnel") {
		t.Fatalf("expected tunnel verification on follow-up start, got output:\n%s", connectOutput)
	}
}

func TestRequestEnrollmentTOFURejectsUnknownHost(t *testing.T) {
	env := prepareFreshEnrollmentEnv(t, false)

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	eng, err := engine.NewEngine(harness.IntegrationNetwork())
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	sshCfg := mustLoadClientSSHConfig(t)

	_, err = eng.RequestEnrollmentWithContext(context.Background(),
		sshCfg.Host,
		sshCfg.Port,
		sshCfg.IdentityFile,
		sshCfg.KnownHostsPath,
		"",
		func(host, fingerprint string) (bool, error) {
			if host == "" || fingerprint == "" {
				t.Errorf("unexpected empty host-key approval values: host=%q fingerprint=%q", host, fingerprint)
			}
			return false, nil
		},
		nil,
	)
	if err == nil {
		t.Fatal("expected request-enrollment to fail when TOFU approval is denied")
	}
	if !strings.Contains(err.Error(), "host key rejected by user") {
		t.Fatalf("expected TOFU rejection error, got: %v", err)
	}

	if data := readFileIfExists(t, env.KnownHostsPath); strings.TrimSpace(data) != "" {
		t.Fatalf("expected known_hosts to remain empty, got:\n%s", data)
	}
	requireEnrolledKeys(t, env, 0)
}

func TestRequestEnrollmentNoOperatorConnected(t *testing.T) {
	env := prepareFreshEnrollmentEnv(t, true)

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	apshell := harness.NewApshellHarness(t)
	output, err := apshell.RunWithInput("request-enrollment\nquit\n")
	if err != nil {
		t.Fatalf("request-enrollment command failed unexpectedly: %v\noutput:\n%s", err, output)
	}
	if !strings.Contains(output, "no operator (apadmin) connected") {
		t.Fatalf("expected no-operator error in output, got:\n%s", output)
	}
	requireEnrolledKeys(t, env, 0)
}

func TestRequestEnrollmentOperatorRejects(t *testing.T) {
	env := prepareFreshEnrollmentEnv(t, true)

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	ipcClient := mustConnectIPCClient(t, signerd.GetWorkDir())
	defer ipcClient.Close()

	apshell := harness.NewApshellHarness(t)
	output, err := runApshellAsyncWithInput(t, apshell, "request-enrollment\nquit\n", func() {
		req := mustReadIPCEnrollmentRequest(t, ipcClient, 10*time.Second)
		mustRespondIPCEnrollmentRequest(t, ipcClient, req.ID, false)
	})
	if err != nil {
		t.Fatalf("request-enrollment command failed unexpectedly: %v\noutput:\n%s", err, output)
	}
	if !strings.Contains(output, "enrollment rejected by operator") {
		t.Fatalf("expected operator rejection in output, got:\n%s", output)
	}
	requireEnrolledKeys(t, env, 0)
}

func TestRequestEnrollmentApprovalClientDisconnectsBeforeResponding(t *testing.T) {
	env := prepareFreshEnrollmentEnv(t, true)

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	ipcClient := mustConnectIPCClient(t, signerd.GetWorkDir())

	apshell := harness.NewApshellHarness(t)
	output, err := runApshellAsyncWithInput(t, apshell, "request-enrollment\nquit\n", func() {
		_ = mustReadIPCEnrollmentRequest(t, ipcClient, 10*time.Second)
		ipcClient.Close()
	})
	if err != nil {
		t.Fatalf("request-enrollment command failed unexpectedly: %v\noutput:\n%s", err, output)
	}
	if !strings.Contains(output, "enrollment rejected by operator") {
		t.Fatalf("expected disconnect-driven rejection in output, got:\n%s", output)
	}
	requireEnrolledKeys(t, env, 0)
}

func TestConnectKnownHostMismatchRejected(t *testing.T) {
	env := harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{})
	writeWrongKnownHosts(t, env.ClientDataDir)

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	apshell := harness.NewApshellHarness(t)
	output, err := apshell.RunWithInput("connect\nquit\n")
	if err != nil {
		t.Fatalf("connect command failed unexpectedly: %v\noutput:\n%s", err, output)
	}
	if !strings.Contains(output, "SSH host key mismatch") {
		t.Fatalf("expected host-key mismatch error, got output:\n%s", output)
	}
	if !strings.Contains(output, "possible MITM attack") {
		t.Fatalf("expected MITM warning, got output:\n%s", output)
	}
}

func TestConnectWithExistingTrustedHostSkipsTOFU(t *testing.T) {
	env := harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{})
	hostPublicKeyPath := filepath.Join(env.SignerDataDir, ".ssh", "ssh_host_key.pub")
	writeCurrentKnownHosts(t, env.ClientDataDir, hostPublicKeyPath)
	knownHostsPath := filepath.Join(env.ClientDataDir, ".ssh", "known_hosts")
	before := readFileIfExists(t, knownHostsPath)

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	apshell := harness.NewApshellHarness(t)
	output, err := apshell.RunWithInput("quit\n")
	if err != nil {
		t.Fatalf("expected trusted-host connect to succeed: %v\noutput:\n%s", err, output)
	}
	if !strings.Contains(output, "Signer verified via tunnel") {
		t.Fatalf("expected successful trusted-host connect, got output:\n%s", output)
	}
	if strings.Contains(output, "[SSH] Unknown host") {
		t.Fatalf("did not expect TOFU prompt on trusted host, got output:\n%s", output)
	}
	if strings.Contains(output, "Host key saved") {
		t.Fatalf("did not expect known_hosts rewrite on trusted host, got output:\n%s", output)
	}

	after := readFileIfExists(t, knownHostsPath)
	if after != before {
		t.Fatalf("expected trusted known_hosts entry to remain unchanged\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

func TestRequestEnrollmentAutoConfirmRejectsUnknownHost(t *testing.T) {
	env := prepareFreshEnrollmentEnv(t, false)

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	scriptPath := filepath.Join(t.TempDir(), "request_enrollment.ap")
	if err := os.WriteFile(scriptPath, []byte("request-enrollment\n"), 0o600); err != nil {
		t.Fatalf("failed to write script file: %v", err)
	}

	apshell := harness.NewApshellHarness(t)
	output, err := apshell.Run("-script", scriptPath)
	if err == nil {
		t.Fatalf("expected auto-confirm request-enrollment to fail, got output:\n%s", output)
	}
	if !strings.Contains(output, "unknown SSH host key") {
		t.Fatalf("expected unknown-host error, got output:\n%s", output)
	}
	if !strings.Contains(output, "interactive apshell first") {
		t.Fatalf("expected interactive trust guidance, got output:\n%s", output)
	}

	if data := readFileIfExists(t, env.KnownHostsPath); strings.TrimSpace(data) != "" {
		t.Fatalf("expected known_hosts to remain empty, got:\n%s", data)
	}
	requireEnrolledKeys(t, env, 0)
}

// Enrolling a key that is already enrolled is approved by the operator like
// any request, changes nothing in the registry, and needs no new host trust.
func TestRequestEnrollmentDuplicateIsIdempotent(t *testing.T) {
	env := prepareFreshEnrollmentEnv(t, false)

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	ipcClient := mustConnectIPCClient(t, signerd.GetWorkDir())
	defer ipcClient.Close()

	eng, err := engine.NewEngine(harness.IntegrationNetwork())
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	sshCfg := mustLoadClientSSHConfig(t)

	hostApprovals := 0
	first, err := requestEnrollmentViaEngine(t, eng, sshCfg, ipcClient, func(host, fingerprint string) (bool, error) {
		hostApprovals++
		return true, nil
	})
	if err != nil {
		t.Fatalf("first request-enrollment failed unexpectedly: %v", err)
	}
	if hostApprovals != 1 {
		t.Fatalf("first request should prompt exactly once for TOFU, got %d", hostApprovals)
	}

	secondHostApprovals := 0
	second, err := requestEnrollmentViaEngine(t, eng, sshCfg, ipcClient, func(host, fingerprint string) (bool, error) {
		secondHostApprovals++
		return true, nil
	})
	if err != nil {
		t.Fatalf("second request-enrollment failed unexpectedly: %v", err)
	}
	if second != first {
		t.Fatalf("expected repeated enrollment to report the same fingerprint, got %q want %q", second, first)
	}
	if secondHostApprovals != 0 {
		t.Fatalf("second request should not require TOFU, got %d approval prompts", secondHostApprovals)
	}
	requireEnrolledKeys(t, env, 1)

	knownHostsData, err := os.ReadFile(env.KnownHostsPath)
	if err != nil {
		t.Fatalf("failed to read known_hosts: %v", err)
	}
	hostEntry := fmt.Sprintf("[%s]:%d", sshCfg.Host, sshCfg.Port)
	if count := strings.Count(string(knownHostsData), hostEntry); count != 1 {
		t.Fatalf("expected exactly one known_hosts entry for %s, got %d in:\n%s", hostEntry, count, string(knownHostsData))
	}

	apshell := harness.NewApshellHarness(t)
	connectOutput, err := apshell.RunWithInput("quit\n")
	if err != nil {
		t.Fatalf("expected apshell startup auto-connect to succeed: %v\noutput:\n%s", err, connectOutput)
	}
	if !strings.Contains(connectOutput, "Signer verified via tunnel") {
		t.Fatalf("expected tunnel verification on follow-up start, got output:\n%s", connectOutput)
	}
}

// An approved request whose registry write fails is reported as a failure
// and leaves nothing enrolled.
func TestRequestEnrollmentRegistryWriteFailureIsReported(t *testing.T) {
	env := prepareFreshEnrollmentEnv(t, true)

	registryDir := filepath.Dir(env.AuthorizedKeysPath)
	if err := os.Chmod(registryDir, 0o500); err != nil {
		t.Fatalf("failed to chmod registry directory: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(registryDir, 0o700) })

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	ipcClient := mustConnectIPCClient(t, signerd.GetWorkDir())
	defer ipcClient.Close()

	apshell := harness.NewApshellHarness(t)
	output, err := runApshellAsyncWithInput(t, apshell, "request-enrollment\nquit\n", func() {
		req := mustReadIPCEnrollmentRequest(t, ipcClient, 10*time.Second)
		mustRespondIPCEnrollmentRequest(t, ipcClient, req.ID, true)
	})
	if err != nil {
		t.Fatalf("request-enrollment command failed unexpectedly: %v\noutput:\n%s", err, output)
	}
	if !strings.Contains(output, "failed to enroll SSH key") {
		t.Fatalf("expected key-enrollment failure, got output:\n%s", output)
	}
	requireEnrolledKeys(t, env, 0)
}

func TestConnectUsesSSHAgentWhenIdentityFileMissing(t *testing.T) {
	env := prepareFreshEnrollmentEnv(t, true)

	agentKeyPath := filepath.Join(t.TempDir(), "agent_id_ed25519")
	writeSSHIdentity(t, agentKeyPath, agentKeyPath+".pub")
	agentEnv := startSSHAgentWithKey(t, agentKeyPath)
	t.Setenv("SSH_AUTH_SOCK", agentEnv.sock)
	t.Setenv("SSH_AGENT_PID", agentEnv.pid)

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	ipcClient := mustConnectIPCClient(t, signerd.GetWorkDir())
	defer ipcClient.Close()

	_, clientCfg := mustLoadDefaultSignerEndpoint(t)
	eng, err := engine.NewEngine(harness.IntegrationNetwork())
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	fingerprint, err := requestEnrollmentViaEngineWithIdentity(t, eng, clientCfg, "", ipcClient, nil)
	if err != nil {
		t.Fatalf("agent-backed request-enrollment failed unexpectedly: %v", err)
	}
	if want := mustClientKeyFingerprint(t, agentKeyPath+".pub"); fingerprint != want {
		t.Fatalf("enrolled fingerprint = %q, want agent key %q", fingerprint, want)
	}
	if !strings.Contains(readFileIfExists(t, env.AuthorizedKeysPath), mustClientKeyBlob(t, agentKeyPath+".pub")) {
		t.Fatalf("authorized_keys does not contain agent key:\n%s", readFileIfExists(t, env.AuthorizedKeysPath))
	}

	localPort := mustAvailableLocalPort(t)
	result, err := eng.ConnectWithTunnel(
		fmt.Sprintf("%s:%d", clientCfg.Host, clientCfg.Port),
		clientCfg.Host,
		clientCfg.Port,
		localPort,
		"",
		clientCfg.KnownHostsPath,
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("agent-backed connect failed unexpectedly: %v", err)
	}
	if !result.Connected {
		t.Fatalf("expected connected result, got %+v", result)
	}
	if !eng.IsTunnelConnected() {
		t.Fatal("expected tunnel to be marked connected")
	}
	t.Cleanup(func() { _ = eng.Disconnect() })

	t.Setenv("SSH_AUTH_SOCK", "")
	t.Setenv("SSH_AGENT_PID", "")
	engNoAgent, err := engine.NewEngine(harness.IntegrationNetwork())
	if err != nil {
		t.Fatalf("failed to create engine for no-agent check: %v", err)
	}
	_, err = engNoAgent.RequestEnrollmentWithContext(context.Background(), clientCfg.Host, clientCfg.Port, "", clientCfg.KnownHostsPath, "", nil, nil)
	if err == nil {
		t.Fatal("expected missing-agent request-enrollment to fail")
	}
	if !strings.Contains(err.Error(), "SSH_AUTH_SOCK is not set") {
		t.Fatalf("expected missing SSH_AUTH_SOCK error, got: %v", err)
	}
}

// Revoking an enrolled key closes its live tunnel and refuses the next
// connection; the registry no longer lists it.
func TestActiveTunnelFailsCleanlyWhenKeyRevoked(t *testing.T) {
	env := prepareFreshEnrollmentEnv(t, false)

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	ipcClient := mustConnectIPCClient(t, signerd.GetWorkDir())
	defer ipcClient.Close()

	eng, err := engine.NewEngine(harness.IntegrationNetwork())
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	sshCfg := mustLoadClientSSHConfig(t)

	fingerprint, err := requestEnrollmentViaEngine(t, eng, sshCfg, ipcClient, func(host, hostFingerprint string) (bool, error) {
		return true, nil
	})
	if err != nil {
		t.Fatalf("request-enrollment failed unexpectedly: %v", err)
	}

	disconnectCh := make(chan struct{}, 1)
	onDisconnect := func() {
		select {
		case disconnectCh <- struct{}{}:
		default:
		}
	}
	localPort := mustAvailableLocalPort(t)
	result, err := eng.ConnectWithTunnel(
		fmt.Sprintf("%s:%d", sshCfg.Host, sshCfg.Port),
		sshCfg.Host,
		sshCfg.Port,
		localPort,
		sshCfg.IdentityFile,
		sshCfg.KnownHostsPath,
		nil,
		onDisconnect,
	)
	if err != nil {
		t.Fatalf("connect failed unexpectedly: %v", err)
	}
	if !result.Connected {
		t.Fatalf("expected connected result, got %+v", result)
	}

	closed := mustRevokeKeyViaIPC(t, ipcClient, fingerprint)
	if closed != 1 {
		t.Fatalf("revocation closed %d connections, want 1", closed)
	}

	select {
	case <-disconnectCh:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for tunnel disconnect after key revocation")
	}

	if eng.IsTunnelConnected() {
		t.Fatal("expected tunnel to be disconnected after key revocation")
	}
	if eng.IsConnected() {
		t.Fatal("expected engine to be disconnected after key revocation")
	}
	requireEnrolledKeys(t, env, 0)

	reconnectPort := mustAvailableLocalPort(t)
	if _, err := eng.ConnectWithTunnel(
		fmt.Sprintf("%s:%d", sshCfg.Host, sshCfg.Port),
		sshCfg.Host,
		sshCfg.Port,
		reconnectPort,
		sshCfg.IdentityFile,
		sshCfg.KnownHostsPath,
		nil,
		nil,
	); err == nil {
		_ = eng.Disconnect()
		t.Fatal("expected reconnect with the revoked key to fail")
	}
}

func TestServerRejectsUnsupportedEnrollmentUsername(t *testing.T) {
	env := prepareFreshEnrollmentEnv(t, true)

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	clientSigner := mustLoadSSHSigner(t, filepath.Join(env.ClientDataDir, ".ssh", "id_ed25519"))
	hostKey := mustLoadSSHPublicKey(t, filepath.Join(env.SignerDataDir, ".ssh", "ssh_host_key.pub"))
	sshCfg := mustLoadClientSSHConfig(t)

	_, err := dialEnrollmentClient(t, sshCfg.Host, sshCfg.Port, "request-enrollment:other", clientSigner, hostKey)
	if err == nil {
		t.Fatal("expected unsupported enrollment username handshake to fail")
	}
	if !strings.Contains(err.Error(), "authenticate") && !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("expected unsupported-username auth failure, got: %v", err)
	}
	requireEnrolledKeys(t, env, 0)
}

func TestEnrollmentRejectsUnknownExecCommand(t *testing.T) {
	env := prepareFreshEnrollmentEnv(t, true)

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	clientSigner := mustLoadSSHSigner(t, filepath.Join(env.ClientDataDir, ".ssh", "id_ed25519"))
	hostKey := mustLoadSSHPublicKey(t, filepath.Join(env.SignerDataDir, ".ssh", "ssh_host_key.pub"))
	sshCfg := mustLoadClientSSHConfig(t)

	client, err := dialEnrollmentClient(t, sshCfg.Host, sshCfg.Port, "request-enrollment", clientSigner, hostKey)
	if err != nil {
		t.Fatalf("failed to establish enrollment SSH client: %v", err)
	}
	defer func() { _ = client.Close() }()

	output, exitCode, err := runEnrollmentExec(t, client, "bogus")
	if err != nil {
		t.Fatalf("unexpected enrollment exec error: %v", err)
	}
	if exitCode == 0 {
		t.Fatalf("expected non-zero exit for unknown enrollment command, got output:\n%s", output)
	}
	logs, err := signerd.GetLogs()
	if err != nil {
		t.Fatalf("failed to read signer logs: %v", err)
	}
	if !strings.Contains(logs, "Unknown enrollment command from ") || !strings.Contains(logs, `"bogus"`) {
		t.Fatalf("expected unknown-command log entry, got logs:\n%s", logs)
	}
	requireEnrolledKeys(t, env, 0)
}

func TestConnectFailsWhenKnownHostsPathMissingOrUnwritable(t *testing.T) {
	env := prepareFreshEnrollmentEnv(t, false)

	nowriteDir := filepath.Join(env.ClientDataDir, "nowrite")
	if err := os.MkdirAll(nowriteDir, 0o700); err != nil {
		t.Fatalf("failed to create nowrite dir: %v", err)
	}
	if err := os.Chmod(nowriteDir, 0o500); err != nil {
		t.Fatalf("failed to chmod nowrite dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(nowriteDir, 0o700) })

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	eng, err := engine.NewEngine(harness.IntegrationNetwork())
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	sshCfg := mustLoadClientSSHConfig(t)
	badKnownHostsPath := filepath.Join(nowriteDir, "subdir", "known_hosts")

	_, err = eng.RequestEnrollmentWithContext(context.Background(),
		sshCfg.Host,
		sshCfg.Port,
		sshCfg.IdentityFile,
		badKnownHostsPath,
		"",
		func(host, fingerprint string) (bool, error) { return true, nil },
		nil,
	)
	if err == nil {
		t.Fatal("expected request-enrollment to fail with unwritable known_hosts path")
	}
	if !strings.Contains(err.Error(), "failed to save host key") {
		t.Fatalf("expected known_hosts save failure, got: %v", err)
	}
	requireEnrolledKeys(t, env, 0)
}

// A client that drops right after the operator approves leaves the server
// consistent: the registry holds at most that one key, and the server keeps
// serving enrollment and connections.
func TestEnrollmentConnectionDropAfterApprovalResponseIsHandledSafely(t *testing.T) {
	env := prepareFreshEnrollmentEnv(t, true)

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	ipcClient := mustConnectIPCClient(t, signerd.GetWorkDir())
	defer ipcClient.Close()

	clientSigner := mustLoadSSHSigner(t, filepath.Join(env.ClientDataDir, ".ssh", "id_ed25519"))
	hostKey := mustLoadSSHPublicKey(t, filepath.Join(env.SignerDataDir, ".ssh", "ssh_host_key.pub"))
	sshCfg := mustLoadClientSSHConfig(t)

	client, err := dialEnrollmentClient(t, sshCfg.Host, sshCfg.Port, "request-enrollment", clientSigner, hostKey)
	if err != nil {
		t.Fatalf("failed to establish enrollment SSH client: %v", err)
	}

	session, err := client.NewSession()
	if err != nil {
		_ = client.Close()
		t.Fatalf("failed to create enrollment session: %v", err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		_ = session.Close()
		_ = client.Close()
		t.Fatalf("failed to create enrollment stdout pipe: %v", err)
	}
	if err := session.Start("enroll"); err != nil {
		_ = session.Close()
		_ = client.Close()
		t.Fatalf("failed to start enrollment session: %v", err)
	}

	req := mustReadIPCEnrollmentRequest(t, ipcClient, 10*time.Second)
	mustRespondIPCEnrollmentRequest(t, ipcClient, req.ID, true)

	_ = client.Close()
	_ = session.Close()
	_, _ = io.ReadAll(stdout)

	time.Sleep(500 * time.Millisecond)

	blob := mustClientKeyBlob(t, env.ClientPublicKeyPath)
	if count := strings.Count(readFileIfExists(t, env.AuthorizedKeysPath), blob); count > 1 {
		t.Fatalf("expected at most one registry entry for the client key, got %d", count)
	}
	if err := signerd.WaitForReady(5 * time.Second); err != nil {
		t.Fatalf("signer not healthy after enrollment client drop: %v", err)
	}

	eng, err := engine.NewEngine(harness.IntegrationNetwork())
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	if _, err := requestEnrollmentViaEngine(t, eng, sshCfg, ipcClient, nil); err != nil {
		t.Fatalf("enrollment after a dropped request failed: %v", err)
	}
	requireEnrolledKeys(t, env, 1)
}

type sshEnrollmentEnv struct {
	SignerDataDir       string
	ClientDataDir       string
	KnownHostsPath      string
	ClientPublicKeyPath string
	AuthorizedKeysPath  string
	HostPublicKeyPath   string
}

// prepareFreshEnrollmentEnv clones the shared environment with a brand-new
// client key that the signer has not enrolled, and no host trust unless
// prepopulateKnownHosts is set.
func prepareFreshEnrollmentEnv(t *testing.T, prepopulateKnownHosts bool) *sshEnrollmentEnv {
	t.Helper()

	env := harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{})

	knownHostsPath := filepath.Join(env.ClientDataDir, ".ssh", "known_hosts")
	clientPrivateKeyPath := filepath.Join(env.ClientDataDir, ".ssh", "id_ed25519")
	clientPublicKeyPath := clientPrivateKeyPath + ".pub"
	authorizedKeysPath := filepath.Join(env.SignerDataDir, "identities", "default", ".ssh", "authorized_keys")
	legacyAuthorizedKeysPath := filepath.Join(env.SignerDataDir, ".ssh", "authorized_keys")
	hostPublicKeyPath := filepath.Join(env.SignerDataDir, ".ssh", "ssh_host_key.pub")

	removeIfExists(t, filepath.Join(env.ClientDataDir, "aplane.token"))
	removeIfExists(t, knownHostsPath)
	if err := os.WriteFile(authorizedKeysPath, nil, 0o600); err != nil {
		t.Fatalf("failed to clear authorized_keys: %v", err)
	}
	if err := os.WriteFile(legacyAuthorizedKeysPath, nil, 0o600); err != nil {
		t.Fatalf("failed to clear legacy authorized_keys: %v", err)
	}
	writeSSHIdentity(t, clientPrivateKeyPath, clientPublicKeyPath)

	if prepopulateKnownHosts {
		writeCurrentKnownHosts(t, env.ClientDataDir, hostPublicKeyPath)
	}

	return &sshEnrollmentEnv{
		SignerDataDir:       env.SignerDataDir,
		ClientDataDir:       env.ClientDataDir,
		KnownHostsPath:      knownHostsPath,
		ClientPublicKeyPath: clientPublicKeyPath,
		AuthorizedKeysPath:  authorizedKeysPath,
		HostPublicKeyPath:   hostPublicKeyPath,
	}
}

// requireEnrolledKeys asserts the registry holds exactly want entries for the
// environment's client key.
func requireEnrolledKeys(t *testing.T, env *sshEnrollmentEnv, want int) {
	t.Helper()
	data := readFileIfExists(t, env.AuthorizedKeysPath)
	blob := mustClientKeyBlob(t, env.ClientPublicKeyPath)
	if got := strings.Count(data, blob); got != want {
		t.Fatalf("authorized_keys lists the client key %d times, want %d:\n%s", got, want, data)
	}
}

func runApshellAsyncWithInput(t *testing.T, apshell *harness.ApshellHarness, input string, during func()) (string, error) {
	t.Helper()

	var (
		output string
		err    error
		wg     sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		output, err = apshell.RunWithInput(input)
	}()

	during()
	wg.Wait()
	return output, err
}

func writeCurrentKnownHosts(t *testing.T, clientDataDir, hostPublicKeyPath string) {
	t.Helper()

	pubKey, err := os.ReadFile(hostPublicKeyPath)
	if err != nil {
		t.Fatalf("failed to read signer host key: %v", err)
	}
	host, port := mustClientSSHHostPort(t)
	line := fmt.Sprintf("[%s]:%d %s\n", host, port, strings.TrimSpace(string(pubKey)))
	knownHostsPath := filepath.Join(clientDataDir, ".ssh", "known_hosts")
	if err := os.WriteFile(knownHostsPath, []byte(line), 0o600); err != nil {
		t.Fatalf("failed to write known_hosts: %v", err)
	}
}

func writeWrongKnownHosts(t *testing.T, clientDataDir string) {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate wrong host key: %v", err)
	}
	pubKey, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		t.Fatalf("failed to build wrong host public key: %v", err)
	}
	host, port := mustClientSSHHostPort(t)
	line := fmt.Sprintf("[%s]:%d %s", host, port, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pubKey))))
	knownHostsPath := filepath.Join(clientDataDir, ".ssh", "known_hosts")
	if err := os.WriteFile(knownHostsPath, []byte(line+"\n"), 0o600); err != nil {
		t.Fatalf("failed to write wrong known_hosts: %v", err)
	}
}

func writeSSHIdentity(t *testing.T, privateKeyPath, publicKeyPath string) {
	t.Helper()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate client SSH key: %v", err)
	}
	pemBlock, err := ssh.MarshalPrivateKey(privateKey, "")
	if err != nil {
		t.Fatalf("failed to encode client SSH private key: %v", err)
	}
	if err := os.WriteFile(privateKeyPath, pem.EncodeToMemory(pemBlock), 0o600); err != nil {
		t.Fatalf("failed to write client SSH private key: %v", err)
	}
	pubKey, err := ssh.NewPublicKey(privateKey.Public())
	if err != nil {
		t.Fatalf("failed to encode client SSH public key: %v", err)
	}
	if err := os.WriteFile(publicKeyPath, ssh.MarshalAuthorizedKey(pubKey), 0o644); err != nil {
		t.Fatalf("failed to write client SSH public key: %v", err)
	}
}

// mustClientKeyFingerprint returns the SHA256 fingerprint of the public key
// stored at publicKeyPath.
func mustClientKeyFingerprint(t *testing.T, publicKeyPath string) string {
	t.Helper()
	return ssh.FingerprintSHA256(mustLoadSSHPublicKey(t, publicKeyPath))
}

// mustClientKeyBlob returns the base64 key material of the public key at
// publicKeyPath, which every registry line for that key contains.
func mustClientKeyBlob(t *testing.T, publicKeyPath string) string {
	t.Helper()
	fields := strings.Fields(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(mustLoadSSHPublicKey(t, publicKeyPath)))))
	if len(fields) < 2 {
		t.Fatalf("unexpected public key encoding in %s", publicKeyPath)
	}
	return fields[1]
}

func mustClientSSHHostPort(t *testing.T) (string, int) {
	t.Helper()

	_, sshCfg := mustLoadDefaultSignerEndpoint(t)
	return sshCfg.Host, sshCfg.Port
}

func mustLoadClientSSHConfig(t *testing.T) config.ClientEndpointSSH {
	t.Helper()

	_, sshCfg := mustLoadDefaultSignerEndpoint(t)
	return sshCfg
}

func mustLoadDefaultSignerEndpoint(t *testing.T) (config.ClientEndpointConfig, config.ClientEndpointSSH) {
	t.Helper()

	cfg := mustLoadClientConfig(t)
	alias, endpoint, ok := cfg.Endpoints.DefaultEndpoint()
	if !ok {
		t.Fatal("client endpoint registry missing default signer endpoint")
	}
	if endpoint.Role != config.ClientEndpointRoleSigner {
		t.Fatalf("default endpoint %q role = %q, want signer", alias, endpoint.Role)
	}
	sshCfg, err := config.ResolveClientEndpointSSH(endpoint)
	if err != nil {
		t.Fatalf("default endpoint %q has invalid SSH URL: %v", alias, err)
	}
	return endpoint, sshCfg
}

func mustLoadClientConfig(t *testing.T) config.Config {
	t.Helper()

	cfg, err := config.LoadConfig(os.Getenv("APCLIENT_DATA"))
	if err != nil {
		t.Fatalf("failed to load client config: %v", err)
	}
	return cfg
}

func requestEnrollmentViaEngine(t *testing.T, eng *engine.Engine, sshCfg config.ClientEndpointSSH, ipcClient *transport.IPCClient, hostKeyApproval func(host string, fingerprint string) (bool, error)) (string, error) {
	t.Helper()
	return requestEnrollmentViaEngineWithIdentity(t, eng, sshCfg, sshCfg.IdentityFile, ipcClient, hostKeyApproval)
}

// requestEnrollmentViaEngineWithIdentity runs request-enrollment through the
// engine while approving the resulting operator prompt over IPC.
func requestEnrollmentViaEngineWithIdentity(t *testing.T, eng *engine.Engine, sshCfg config.ClientEndpointSSH, identityFile string, ipcClient *transport.IPCClient, hostKeyApproval func(host string, fingerprint string) (bool, error)) (string, error) {
	t.Helper()

	var (
		fingerprint string
		reqErr      error
		reqDone     sync.WaitGroup
	)
	reqDone.Add(1)
	go func() {
		defer reqDone.Done()
		fingerprint, reqErr = eng.RequestEnrollmentWithContext(context.Background(),
			sshCfg.Host,
			sshCfg.Port,
			identityFile,
			sshCfg.KnownHostsPath,
			"",
			hostKeyApproval,
			nil,
		)
	}()

	req := mustReadIPCEnrollmentRequest(t, ipcClient, 10*time.Second)
	mustRespondIPCEnrollmentRequest(t, ipcClient, req.ID, true)
	reqDone.Wait()
	return fingerprint, reqErr
}

type sshAgentEnv struct {
	sock string
	pid  string
}

func startSSHAgentWithKey(t *testing.T, keyPath string) sshAgentEnv {
	t.Helper()

	out, err := exec.Command("ssh-agent", "-s").CombinedOutput()
	if err != nil {
		t.Fatalf("failed to start ssh-agent: %v\noutput:\n%s", err, string(out))
	}

	env := parseSSHAgentEnv(t, string(out))
	addCmd := exec.Command("ssh-add", keyPath)
	addCmd.Env = append(os.Environ(),
		"SSH_AUTH_SOCK="+env.sock,
		"SSH_AGENT_PID="+env.pid,
	)
	if addOut, err := addCmd.CombinedOutput(); err != nil {
		_ = stopSSHAgent(env)
		t.Fatalf("failed to add key to ssh-agent: %v\noutput:\n%s", err, string(addOut))
	}

	t.Cleanup(func() {
		if err := stopSSHAgent(env); err != nil {
			t.Fatalf("failed to stop ssh-agent: %v", err)
		}
	})
	return env
}

func parseSSHAgentEnv(t *testing.T, output string) sshAgentEnv {
	t.Helper()

	var env sshAgentEnv
	for _, part := range strings.Split(output, ";") {
		part = strings.TrimSpace(part)
		switch {
		case strings.HasPrefix(part, "SSH_AUTH_SOCK="):
			env.sock = strings.TrimPrefix(part, "SSH_AUTH_SOCK=")
		case strings.HasPrefix(part, "SSH_AGENT_PID="):
			env.pid = strings.TrimPrefix(part, "SSH_AGENT_PID=")
		}
	}
	if env.sock == "" || env.pid == "" {
		t.Fatalf("failed to parse ssh-agent environment from output:\n%s", output)
	}
	return env
}

func stopSSHAgent(env sshAgentEnv) error {
	cmd := exec.Command("ssh-agent", "-k")
	cmd.Env = append(os.Environ(),
		"SSH_AUTH_SOCK="+env.sock,
		"SSH_AGENT_PID="+env.pid,
	)
	_, err := cmd.CombinedOutput()
	return err
}

func mustAvailableLocalPort(t *testing.T) int {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to allocate local port: %v", err)
	}
	defer func() { _ = listener.Close() }()
	return listener.Addr().(*net.TCPAddr).Port
}

func removeIfExists(t *testing.T, path string) {
	t.Helper()

	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		t.Fatalf("failed to remove %s: %v", path, err)
	}
}

func readFileIfExists(t *testing.T, path string) string {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ""
		}
		t.Fatalf("failed to read %s: %v", path, err)
	}
	return string(data)
}

func mustReadIPCEnrollmentRequest(t *testing.T, ipcClient *transport.IPCClient, timeout time.Duration) protocol.ClientEnrollmentRequestMessage {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ipcClient.SetReadDeadline(time.Until(deadline))
		message, err := ipcClient.ReadMessage()
		if err != nil {
			t.Fatalf("failed to read IPC message: %v", err)
		}

		var base protocol.BaseMessage
		if err := json.Unmarshal(message, &base); err != nil {
			t.Fatalf("failed to parse IPC base message: %v", err)
		}
		if base.Type != protocol.MsgTypeClientEnrollmentRequest {
			continue
		}

		var req protocol.ClientEnrollmentRequestMessage
		if err := json.Unmarshal(message, &req); err != nil {
			t.Fatalf("failed to parse enrollment request: %v", err)
		}
		return req
	}

	t.Fatalf("timed out waiting for enrollment request over IPC")
	return protocol.ClientEnrollmentRequestMessage{}
}

func mustRespondIPCEnrollmentRequest(t *testing.T, ipcClient *transport.IPCClient, requestID string, approved bool) {
	t.Helper()

	reason := ""
	if !approved {
		reason = "rejected by test"
	}
	if err := ipcClient.WriteJSON(protocol.ClientEnrollmentResponseMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeClientEnrollmentResponse,
			ID:   requestID,
		},
		Approved: approved,
		Reason:   reason,
	}); err != nil {
		t.Fatalf("failed to send enrollment response over IPC: %v", err)
	}
}

// mustRevokeKeyViaIPC revokes one enrolled key and returns how many live
// connections the signer closed for it.
func mustRevokeKeyViaIPC(t *testing.T, ipcClient *transport.IPCClient, fingerprint string) int {
	t.Helper()

	reqID := fmt.Sprintf("revoke-%d", time.Now().UnixNano())
	if err := ipcClient.WriteJSON(protocol.RevokeEnrolledKeyMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeRevokeEnrolledKey,
			ID:   reqID,
		},
		Fingerprint: fingerprint,
	}); err != nil {
		t.Fatalf("failed to send revoke-key IPC message: %v", err)
	}

	ipcClient.SetReadDeadline(10 * time.Second)
	for {
		message, err := ipcClient.ReadMessage()
		if err != nil {
			t.Fatalf("failed to read revoke-key response: %v", err)
		}

		var base protocol.BaseMessage
		if err := json.Unmarshal(message, &base); err != nil {
			t.Fatalf("failed to parse revoke-key base message: %v", err)
		}
		if base.Type != protocol.MsgTypeRevokeEnrolledKeyResult || base.ID != reqID {
			continue
		}

		var result protocol.RevokeEnrolledKeyResultMessage
		if err := json.Unmarshal(message, &result); err != nil {
			t.Fatalf("failed to parse revoke-key result: %v", err)
		}
		if !result.Success {
			t.Fatalf("revoke-key failed: %s", result.Error)
		}
		return result.ClosedConnections
	}
}

func mustLoadSSHSigner(t *testing.T, privateKeyPath string) ssh.Signer {
	t.Helper()

	keyData, err := os.ReadFile(privateKeyPath)
	if err != nil {
		t.Fatalf("failed to read SSH private key %s: %v", privateKeyPath, err)
	}
	signer, err := ssh.ParsePrivateKey(keyData)
	if err != nil {
		t.Fatalf("failed to parse SSH private key %s: %v", privateKeyPath, err)
	}
	return signer
}

func mustLoadSSHPublicKey(t *testing.T, publicKeyPath string) ssh.PublicKey {
	t.Helper()

	keyData, err := os.ReadFile(publicKeyPath)
	if err != nil {
		t.Fatalf("failed to read SSH public key %s: %v", publicKeyPath, err)
	}
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(keyData)
	if err != nil {
		t.Fatalf("failed to parse SSH public key %s: %v", publicKeyPath, err)
	}
	return pubKey
}

func dialEnrollmentClient(t *testing.T, host string, port int, user string, signer ssh.Signer, hostKey ssh.PublicKey) (*ssh.Client, error) {
	t.Helper()

	clientConfig := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(hostKey),
		Timeout:         10 * time.Second,
	}
	return ssh.Dial("tcp", fmt.Sprintf("%s:%d", host, port), clientConfig)
}

func runEnrollmentExec(t *testing.T, client *ssh.Client, command string) (string, int, error) {
	t.Helper()

	session, err := client.NewSession()
	if err != nil {
		return "", -1, fmt.Errorf("new session: %w", err)
	}
	defer func() { _ = session.Close() }()

	output, err := session.CombinedOutput(command)
	if err != nil {
		if exitErr, ok := err.(*ssh.ExitError); ok {
			return string(output), exitErr.ExitStatus(), nil
		}
		if strings.Contains(err.Error(), "ssh: command "+command+" failed") {
			return string(output), 1, nil
		}
		return string(output), -1, err
	}
	return string(output), 0, nil
}
