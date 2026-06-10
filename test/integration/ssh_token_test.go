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
	util "github.com/aplane-algo/aplane/internal/tokenfile"
	"github.com/aplane-algo/aplane/internal/transport"
	"github.com/aplane-algo/aplane/test/integration/harness"

	"golang.org/x/crypto/ssh"
)

func TestRequestTokenHappyPathEnrollsKeyAndConnectWorks(t *testing.T) {
	env := prepareFreshProvisioningEnv(t, false)

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
		token   string
		reqErr  error
		reqDone sync.WaitGroup
	)
	reqDone.Add(1)
	go func() {
		defer reqDone.Done()
		token, reqErr = eng.RequestTokenWithContext(context.Background(),
			sshCfg.Host,
			sshCfg.Port,
			sshCfg.IdentityFile,
			sshCfg.KnownHostsPath,
			func(host, fingerprint string) (bool, error) {
				if host == "" || fingerprint == "" {
					t.Errorf("unexpected empty host-key approval values: host=%q fingerprint=%q", host, fingerprint)
				}
				return true, nil
			},
			nil,
		)
	}()

	req := mustReadIPCTokenProvisioningRequest(t, ipcClient, 10*time.Second)
	if req.IdentityID != "default" {
		t.Fatalf("expected default identity, got %s", req.IdentityID)
	}
	if req.SSHFingerprint == "" {
		t.Fatal("expected SSH fingerprint in token provisioning request")
	}
	mustRespondIPCTokenProvisioningRequest(t, ipcClient, req.ID, true)
	reqDone.Wait()
	if reqErr != nil {
		t.Fatalf("engine request-token failed unexpectedly: %v", reqErr)
	}
	if token == "" {
		t.Fatal("expected non-empty token from request-token")
	}
	if err := util.WriteToken(env.ClientTokenPath, token); err != nil {
		t.Fatalf("failed to save provisioned token: %v", err)
	}

	clientToken, err := util.ReadToken(env.ClientTokenPath)
	if err != nil {
		t.Fatalf("failed to read client token: %v", err)
	}
	signerToken := readSignerToken(t, signerd)
	if clientToken != signerToken {
		t.Fatalf("client token mismatch: got %q want %q", clientToken, signerToken)
	}

	knownHostsData, err := os.ReadFile(env.KnownHostsPath)
	if err != nil {
		t.Fatalf("failed to read known_hosts: %v", err)
	}
	if !strings.Contains(string(knownHostsData), fmt.Sprintf("[%s]:%d", sshCfg.Host, sshCfg.Port)) {
		t.Fatalf("known_hosts does not contain expected host entry:\n%s", string(knownHostsData))
	}

	authKeysData, err := os.ReadFile(env.AuthorizedKeysPath)
	if err != nil {
		t.Fatalf("failed to read authorized_keys: %v", err)
	}
	clientPubKey, err := os.ReadFile(env.ClientPublicKeyPath)
	if err != nil {
		t.Fatalf("failed to read client public key: %v", err)
	}
	if !strings.Contains(string(authKeysData), strings.TrimSpace(string(clientPubKey))) {
		t.Fatalf("authorized_keys does not contain enrolled client key:\n%s", string(authKeysData))
	}

	apshell := harness.NewApshellHarness(t, signerd.GetURL())
	connectOutput, err := apshell.RunWithInput("quit\n")
	if err != nil {
		t.Fatalf("expected apshell startup auto-connect to succeed: %v\noutput:\n%s", err, connectOutput)
	}
	if !strings.Contains(connectOutput, "Signer verified via tunnel") {
		t.Fatalf("expected tunnel verification on follow-up start, got output:\n%s", connectOutput)
	}
}

func TestRequestTokenTOFURejectsUnknownHost(t *testing.T) {
	env := prepareFreshProvisioningEnv(t, false)

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

	_, err = eng.RequestTokenWithContext(context.Background(),
		sshCfg.Host,
		sshCfg.Port,
		sshCfg.IdentityFile,
		sshCfg.KnownHostsPath,
		func(host, fingerprint string) (bool, error) {
			if host == "" || fingerprint == "" {
				t.Errorf("unexpected empty host-key approval values: host=%q fingerprint=%q", host, fingerprint)
			}
			return false, nil
		},
		nil,
	)
	if err == nil {
		t.Fatal("expected request-token to fail when TOFU approval is denied")
	}
	if !strings.Contains(err.Error(), "host key rejected by user") {
		t.Fatalf("expected TOFU rejection error, got: %v", err)
	}

	clientToken, err := util.ReadToken(env.ClientTokenPath)
	if err != nil {
		t.Fatalf("failed to read client token: %v", err)
	}
	if clientToken != "" {
		t.Fatalf("expected no token to be saved, got %q", clientToken)
	}

	if data := readFileIfExists(t, env.KnownHostsPath); strings.TrimSpace(data) != "" {
		t.Fatalf("expected known_hosts to remain empty, got:\n%s", data)
	}
	if data := readFileIfExists(t, env.AuthorizedKeysPath); strings.TrimSpace(data) != "" {
		t.Fatalf("expected authorized_keys to remain empty, got:\n%s", data)
	}
}

func TestRequestTokenNoOperatorConnected(t *testing.T) {
	env := prepareFreshProvisioningEnv(t, true)

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	apshell := harness.NewApshellHarness(t, signerd.GetURL())
	output, err := apshell.RunWithInput("request-token\nquit\n")
	if err != nil {
		t.Fatalf("request-token command failed unexpectedly: %v\noutput:\n%s", err, output)
	}
	if !strings.Contains(output, "no operator (apadmin) connected") {
		t.Fatalf("expected no-operator error in output, got:\n%s", output)
	}

	clientToken, err := util.ReadToken(env.ClientTokenPath)
	if err != nil {
		t.Fatalf("failed to read client token: %v", err)
	}
	if clientToken != "" {
		t.Fatalf("expected no token to be saved, got %q", clientToken)
	}
	if data := readFileIfExists(t, env.AuthorizedKeysPath); strings.TrimSpace(data) != "" {
		t.Fatalf("expected authorized_keys to remain empty, got:\n%s", data)
	}
}

func TestRequestTokenOperatorRejects(t *testing.T) {
	env := prepareFreshProvisioningEnv(t, true)

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	ipcClient := mustConnectIPCClient(t, signerd.GetWorkDir())
	defer ipcClient.Close()

	apshell := harness.NewApshellHarness(t, signerd.GetURL())
	output, err := runApshellAsyncWithInput(t, apshell, "request-token\nquit\n", func() {
		req := mustReadIPCTokenProvisioningRequest(t, ipcClient, 10*time.Second)
		mustRespondIPCTokenProvisioningRequest(t, ipcClient, req.ID, false)
	})
	if err != nil {
		t.Fatalf("request-token command failed unexpectedly: %v\noutput:\n%s", err, output)
	}
	if !strings.Contains(output, "token provisioning rejected by operator") {
		t.Fatalf("expected operator rejection in output, got:\n%s", output)
	}

	clientToken, err := util.ReadToken(env.ClientTokenPath)
	if err != nil {
		t.Fatalf("failed to read client token: %v", err)
	}
	if clientToken != "" {
		t.Fatalf("expected no token to be saved, got %q", clientToken)
	}
	if data := readFileIfExists(t, env.AuthorizedKeysPath); strings.TrimSpace(data) != "" {
		t.Fatalf("expected authorized_keys to remain empty, got:\n%s", data)
	}
}

func TestRequestTokenApprovalClientDisconnectsBeforeResponding(t *testing.T) {
	env := prepareFreshProvisioningEnv(t, true)

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	ipcClient := mustConnectIPCClient(t, signerd.GetWorkDir())

	apshell := harness.NewApshellHarness(t, signerd.GetURL())
	output, err := runApshellAsyncWithInput(t, apshell, "request-token\nquit\n", func() {
		_ = mustReadIPCTokenProvisioningRequest(t, ipcClient, 10*time.Second)
		ipcClient.Close()
	})
	if err != nil {
		t.Fatalf("request-token command failed unexpectedly: %v\noutput:\n%s", err, output)
	}
	if !strings.Contains(output, "token provisioning rejected by operator") {
		t.Fatalf("expected disconnect-driven provisioning rejection in output, got:\n%s", output)
	}

	clientToken, err := util.ReadToken(env.ClientTokenPath)
	if err != nil {
		t.Fatalf("failed to read client token: %v", err)
	}
	if clientToken != "" {
		t.Fatalf("expected no token to be saved, got %q", clientToken)
	}
	if data := readFileIfExists(t, env.AuthorizedKeysPath); strings.TrimSpace(data) != "" {
		t.Fatalf("expected authorized_keys to remain empty, got:\n%s", data)
	}
}

func TestConnectKnownHostMismatchRejected(t *testing.T) {
	env := harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{})
	writeWrongKnownHosts(t, env.ClientDataDir)

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	apshell := harness.NewApshellHarness(t, signerd.GetURL())
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

	apshell := harness.NewApshellHarness(t, signerd.GetURL())
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

func TestRequestTokenAutoConfirmRejectsUnknownHost(t *testing.T) {
	env := prepareFreshProvisioningEnv(t, false)

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	scriptPath := filepath.Join(t.TempDir(), "request_token.ap")
	if err := os.WriteFile(scriptPath, []byte("request-token\n"), 0o600); err != nil {
		t.Fatalf("failed to write script file: %v", err)
	}

	apshell := harness.NewApshellHarness(t, signerd.GetURL())
	output, err := apshell.Run("-script", scriptPath)
	if err == nil {
		t.Fatalf("expected auto-confirm request-token to fail, got output:\n%s", output)
	}
	if !strings.Contains(output, "unknown SSH host key") {
		t.Fatalf("expected unknown-host error, got output:\n%s", output)
	}
	if !strings.Contains(output, "interactive apshell first") {
		t.Fatalf("expected interactive trust guidance, got output:\n%s", output)
	}

	clientToken, err := util.ReadToken(env.ClientTokenPath)
	if err != nil {
		t.Fatalf("failed to read client token: %v", err)
	}
	if clientToken != "" {
		t.Fatalf("expected no token to be saved, got %q", clientToken)
	}
	if data := readFileIfExists(t, env.KnownHostsPath); strings.TrimSpace(data) != "" {
		t.Fatalf("expected known_hosts to remain empty, got:\n%s", data)
	}
	if data := readFileIfExists(t, env.AuthorizedKeysPath); strings.TrimSpace(data) != "" {
		t.Fatalf("expected authorized_keys to remain empty, got:\n%s", data)
	}
}

func TestRequestTokenDuplicateProvisioningIsIdempotent(t *testing.T) {
	env := prepareFreshProvisioningEnv(t, false)

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
	token1, err := requestTokenViaEngine(t, eng, sshCfg, ipcClient, func(host, fingerprint string) (bool, error) {
		hostApprovals++
		return true, nil
	})
	if err != nil {
		t.Fatalf("first request-token failed unexpectedly: %v", err)
	}
	if err := util.WriteToken(env.ClientTokenPath, token1); err != nil {
		t.Fatalf("failed to save first token: %v", err)
	}
	if hostApprovals != 1 {
		t.Fatalf("first request should prompt exactly once for TOFU, got %d", hostApprovals)
	}

	secondHostApprovals := 0
	token2, err := requestTokenViaEngine(t, eng, sshCfg, ipcClient, func(host, fingerprint string) (bool, error) {
		secondHostApprovals++
		return true, nil
	})
	if err != nil {
		t.Fatalf("second request-token failed unexpectedly: %v", err)
	}
	if token2 != token1 {
		t.Fatalf("expected repeated provisioning to return same token, got %q want %q", token2, token1)
	}
	if secondHostApprovals != 0 {
		t.Fatalf("second request should not require TOFU, got %d approval prompts", secondHostApprovals)
	}

	authKeysData, err := os.ReadFile(env.AuthorizedKeysPath)
	if err != nil {
		t.Fatalf("failed to read authorized_keys: %v", err)
	}
	clientPubKey, err := os.ReadFile(env.ClientPublicKeyPath)
	if err != nil {
		t.Fatalf("failed to read client public key: %v", err)
	}
	pubKeyLine := strings.TrimSpace(string(clientPubKey))
	if count := strings.Count(string(authKeysData), pubKeyLine); count != 1 {
		t.Fatalf("expected exactly one enrolled key entry, got %d entries in:\n%s", count, string(authKeysData))
	}

	knownHostsData, err := os.ReadFile(env.KnownHostsPath)
	if err != nil {
		t.Fatalf("failed to read known_hosts: %v", err)
	}
	hostEntry := fmt.Sprintf("[%s]:%d", sshCfg.Host, sshCfg.Port)
	if count := strings.Count(string(knownHostsData), hostEntry); count != 1 {
		t.Fatalf("expected exactly one known_hosts entry for %s, got %d in:\n%s", hostEntry, count, string(knownHostsData))
	}

	apshell := harness.NewApshellHarness(t, signerd.GetURL())
	connectOutput, err := apshell.RunWithInput("quit\n")
	if err != nil {
		t.Fatalf("expected apshell startup auto-connect to succeed: %v\noutput:\n%s", err, connectOutput)
	}
	if !strings.Contains(connectOutput, "Signer verified via tunnel") {
		t.Fatalf("expected tunnel verification on follow-up start, got output:\n%s", connectOutput)
	}
}

func TestRequestTokenKeyEnrollmentFailureFailsBeforeTokenIssuance(t *testing.T) {
	env := prepareFreshProvisioningEnv(t, true)

	if err := os.Chmod(env.AuthorizedKeysPath, 0o400); err != nil {
		t.Fatalf("failed to chmod authorized_keys file: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(env.AuthorizedKeysPath, 0o600) })

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	ipcClient := mustConnectIPCClient(t, signerd.GetWorkDir())
	defer ipcClient.Close()

	apshell := harness.NewApshellHarness(t, signerd.GetURL())
	output, err := runApshellAsyncWithInput(t, apshell, "request-token\nquit\n", func() {
		req := mustReadIPCTokenProvisioningRequest(t, ipcClient, 10*time.Second)
		mustRespondIPCTokenProvisioningRequest(t, ipcClient, req.ID, true)
	})
	if err != nil {
		t.Fatalf("request-token command failed unexpectedly: %v\noutput:\n%s", err, output)
	}
	if !strings.Contains(output, "failed to enroll SSH key") {
		t.Fatalf("expected key-enrollment failure, got output:\n%s", output)
	}

	clientToken, err := util.ReadToken(env.ClientTokenPath)
	if err != nil {
		t.Fatalf("failed to read client token: %v", err)
	}
	if clientToken != "" {
		t.Fatalf("expected no token to be saved, got %q", clientToken)
	}
	if data := readFileIfExists(t, env.AuthorizedKeysPath); strings.TrimSpace(data) != "" {
		t.Fatalf("expected authorized_keys to remain empty, got:\n%s", data)
	}
}

func TestRequestTokenTokenIssuanceFailureAfterEnrollment(t *testing.T) {
	env := prepareFreshProvisioningEnv(t, true)

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	tokenPath := signerd.GetTokenPath()
	tokenDir := filepath.Dir(tokenPath)
	info, err := os.Stat(tokenDir)
	if err != nil {
		t.Fatalf("failed to stat token directory: %v", err)
	}
	if err := os.Remove(tokenPath); err != nil {
		t.Fatalf("failed to remove signer token: %v", err)
	}
	if err := os.Chmod(tokenDir, 0o500); err != nil {
		t.Fatalf("failed to chmod token directory: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(tokenDir, info.Mode().Perm()) })

	ipcClient := mustConnectIPCClient(t, signerd.GetWorkDir())
	defer ipcClient.Close()

	apshell := harness.NewApshellHarness(t, signerd.GetURL())
	output, err := runApshellAsyncWithInput(t, apshell, "request-token\nquit\n", func() {
		req := mustReadIPCTokenProvisioningRequest(t, ipcClient, 10*time.Second)
		mustRespondIPCTokenProvisioningRequest(t, ipcClient, req.ID, true)
	})
	if err != nil {
		t.Fatalf("request-token command failed unexpectedly: %v\noutput:\n%s", err, output)
	}
	if !strings.Contains(output, "failed to load token") {
		t.Fatalf("expected token-issuance failure, got output:\n%s", output)
	}

	clientToken, err := util.ReadToken(env.ClientTokenPath)
	if err != nil {
		t.Fatalf("failed to read client token: %v", err)
	}
	if clientToken != "" {
		t.Fatalf("expected no token to be saved, got %q", clientToken)
	}
	if _, err := os.Stat(tokenPath); !os.IsNotExist(err) {
		t.Fatalf("expected signer token file to remain absent, stat err=%v", err)
	}

	authKeysData, err := os.ReadFile(env.AuthorizedKeysPath)
	if err != nil {
		t.Fatalf("failed to read authorized_keys: %v", err)
	}
	clientPubKey, err := os.ReadFile(env.ClientPublicKeyPath)
	if err != nil {
		t.Fatalf("failed to read client public key: %v", err)
	}
	if !strings.Contains(string(authKeysData), strings.TrimSpace(string(clientPubKey))) {
		t.Fatalf("expected SSH key to remain enrolled after issuance failure, got:\n%s", string(authKeysData))
	}
}

func TestConnectUsesSSHAgentWhenIdentityFileMissing(t *testing.T) {
	env := prepareFreshProvisioningEnv(t, true)

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

	endpoint, clientCfg := mustLoadDefaultSignerEndpoint(t)
	eng, err := engine.NewEngine(harness.IntegrationNetwork())
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	token, err := requestTokenViaEngineWithIdentity(t, eng, clientCfg, "", ipcClient, nil)
	if err != nil {
		t.Fatalf("agent-backed request-token failed unexpectedly: %v", err)
	}
	if token == "" {
		t.Fatal("expected token from agent-backed request-token")
	}
	if err := util.WriteToken(env.ClientTokenPath, token); err != nil {
		t.Fatalf("failed to save agent-backed token: %v", err)
	}

	authKeysData, err := os.ReadFile(env.AuthorizedKeysPath)
	if err != nil {
		t.Fatalf("failed to read authorized_keys: %v", err)
	}
	agentPubKey, err := os.ReadFile(agentKeyPath + ".pub")
	if err != nil {
		t.Fatalf("failed to read agent public key: %v", err)
	}
	if !strings.Contains(string(authKeysData), strings.TrimSpace(string(agentPubKey))) {
		t.Fatalf("authorized_keys does not contain agent key:\n%s", string(authKeysData))
	}

	localPort := mustAvailableLocalPort(t)
	result, err := eng.ConnectWithTunnel(
		fmt.Sprintf("%s:%d", clientCfg.Host, clientCfg.Port),
		clientCfg.Host,
		clientCfg.Port,
		localPort,
		endpoint.SignerPort,
		token,
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
	_, err = engNoAgent.RequestTokenWithContext(context.Background(), clientCfg.Host, clientCfg.Port, "", clientCfg.KnownHostsPath, nil, nil)
	if err == nil {
		t.Fatal("expected missing-agent request-token to fail")
	}
	if !strings.Contains(err.Error(), "SSH_AUTH_SOCK is not set") {
		t.Fatalf("expected missing SSH_AUTH_SOCK error, got: %v", err)
	}
}

func TestActiveTunnelFailsCleanlyWhenTokenRevoked(t *testing.T) {
	env := prepareFreshProvisioningEnv(t, false)

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
	endpoint := mustLoadDefaultSignerEndpointOnly(t)

	token, err := requestTokenViaEngine(t, eng, sshCfg, ipcClient, func(host, fingerprint string) (bool, error) {
		return true, nil
	})
	if err != nil {
		t.Fatalf("request-token failed unexpectedly: %v", err)
	}
	if err := util.WriteToken(env.ClientTokenPath, token); err != nil {
		t.Fatalf("failed to save token: %v", err)
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
		endpoint.SignerPort,
		token,
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

	newToken := mustRevokeTokenViaIPC(t, ipcClient, signerd.GetTokenPath())
	if newToken == token {
		t.Fatalf("expected revoked token to change, still got %q", newToken)
	}

	select {
	case <-disconnectCh:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for tunnel disconnect after token revocation")
	}

	if eng.IsTunnelConnected() {
		t.Fatal("expected tunnel to be disconnected after token revocation")
	}
	if eng.IsConnected() {
		t.Fatal("expected engine to be disconnected after token revocation")
	}
}

func TestRequestTokenReplacesOldTokenAndReconnects(t *testing.T) {
	env := prepareFreshProvisioningEnv(t, false)

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	ipcClient := mustConnectIPCClient(t, signerd.GetWorkDir())
	defer ipcClient.Close()

	endpoint, sshCfg := mustLoadDefaultSignerEndpoint(t)
	eng, err := engine.NewEngine(harness.IntegrationNetwork())
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	firstToken, err := requestTokenViaEngine(t, eng, sshCfg, ipcClient, func(host, fingerprint string) (bool, error) {
		return true, nil
	})
	if err != nil {
		t.Fatalf("first request-token failed unexpectedly: %v", err)
	}
	if err := util.WriteToken(env.ClientTokenPath, firstToken); err != nil {
		t.Fatalf("failed to save first token: %v", err)
	}

	disconnectCh := make(chan struct{}, 1)
	onDisconnect := func() {
		select {
		case disconnectCh <- struct{}{}:
		default:
		}
	}
	localPort := mustAvailableLocalPort(t)
	if _, err := eng.ConnectWithTunnel(
		fmt.Sprintf("%s:%d", sshCfg.Host, sshCfg.Port),
		sshCfg.Host,
		sshCfg.Port,
		localPort,
		endpoint.SignerPort,
		firstToken,
		sshCfg.IdentityFile,
		sshCfg.KnownHostsPath,
		nil,
		onDisconnect,
	); err != nil {
		t.Fatalf("initial connect failed unexpectedly: %v", err)
	}

	revokedToken := mustRevokeTokenViaIPC(t, ipcClient, signerd.GetTokenPath())
	if revokedToken == firstToken {
		t.Fatalf("expected token to change on revoke, still got %q", revokedToken)
	}

	select {
	case <-disconnectCh:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for disconnect after token revocation")
	}

	secondToken, err := requestTokenViaEngine(t, eng, sshCfg, ipcClient, nil)
	if err != nil {
		t.Fatalf("second request-token failed unexpectedly: %v", err)
	}
	if secondToken != revokedToken {
		t.Fatalf("expected reprovisioned token %q, got %q", revokedToken, secondToken)
	}
	if secondToken == firstToken {
		t.Fatalf("expected reprovisioned token to differ from old token %q", firstToken)
	}
	if err := util.WriteToken(env.ClientTokenPath, secondToken); err != nil {
		t.Fatalf("failed to save second token: %v", err)
	}

	reconnectPort := mustAvailableLocalPort(t)
	result, err := eng.ConnectWithTunnel(
		fmt.Sprintf("%s:%d", sshCfg.Host, sshCfg.Port),
		sshCfg.Host,
		sshCfg.Port,
		reconnectPort,
		endpoint.SignerPort,
		secondToken,
		sshCfg.IdentityFile,
		sshCfg.KnownHostsPath,
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("reconnect failed unexpectedly: %v", err)
	}
	if !result.Connected {
		t.Fatalf("expected reconnect result to be connected, got %+v", result)
	}
	t.Cleanup(func() { _ = eng.Disconnect() })
}

func TestServerRejectsUnsupportedProvisioningIdentity(t *testing.T) {
	env := prepareFreshProvisioningEnv(t, true)

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	clientSigner := mustLoadSSHSigner(t, filepath.Join(env.ClientDataDir, ".ssh", "id_ed25519"))
	hostKey := mustLoadSSHPublicKey(t, filepath.Join(env.SignerDataDir, ".ssh", "ssh_host_key.pub"))
	sshCfg := mustLoadClientSSHConfig(t)

	_, err := dialProvisioningClient(t, sshCfg.Host, sshCfg.Port, "request-token:nondefault", clientSigner, hostKey)
	if err == nil {
		t.Fatal("expected unsupported identity provisioning handshake to fail")
	}
	if !strings.Contains(err.Error(), "authenticate") && !strings.Contains(err.Error(), "unsupported identity") {
		t.Fatalf("expected unsupported-identity auth failure, got: %v", err)
	}

	clientToken, err := util.ReadToken(env.ClientTokenPath)
	if err != nil {
		t.Fatalf("failed to read client token: %v", err)
	}
	if clientToken != "" {
		t.Fatalf("expected no client token to be saved, got %q", clientToken)
	}
	if data := readFileIfExists(t, env.AuthorizedKeysPath); strings.TrimSpace(data) != "" {
		t.Fatalf("expected authorized_keys to remain empty, got:\n%s", data)
	}
}

func TestProvisioningRejectsUnknownExecCommand(t *testing.T) {
	env := prepareFreshProvisioningEnv(t, true)

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	clientSigner := mustLoadSSHSigner(t, filepath.Join(env.ClientDataDir, ".ssh", "id_ed25519"))
	hostKey := mustLoadSSHPublicKey(t, filepath.Join(env.SignerDataDir, ".ssh", "ssh_host_key.pub"))
	sshCfg := mustLoadClientSSHConfig(t)

	client, err := dialProvisioningClient(t, sshCfg.Host, sshCfg.Port, "request-token:default", clientSigner, hostKey)
	if err != nil {
		t.Fatalf("failed to establish provisioning SSH client: %v", err)
	}
	defer func() { _ = client.Close() }()

	output, exitCode, err := runProvisioningExec(t, client, "bogus")
	if err != nil {
		t.Fatalf("unexpected provisioning exec error: %v", err)
	}
	if exitCode == 0 {
		t.Fatalf("expected non-zero exit for unknown provisioning command, got output:\n%s", output)
	}
	logs, err := signerd.GetLogs()
	if err != nil {
		t.Fatalf("failed to read signer logs: %v", err)
	}
	if !strings.Contains(logs, "Unknown provisioning command: bogus") {
		t.Fatalf("expected unknown-command log entry, got logs:\n%s", logs)
	}
	if data := readFileIfExists(t, env.AuthorizedKeysPath); strings.TrimSpace(data) != "" {
		t.Fatalf("expected authorized_keys to remain empty, got:\n%s", data)
	}
}

func TestConnectFailsWhenKnownHostsPathMissingOrUnwritable(t *testing.T) {
	env := prepareFreshProvisioningEnv(t, false)

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

	_, err = eng.RequestTokenWithContext(context.Background(),
		sshCfg.Host,
		sshCfg.Port,
		sshCfg.IdentityFile,
		badKnownHostsPath,
		func(host, fingerprint string) (bool, error) { return true, nil },
		nil,
	)
	if err == nil {
		t.Fatal("expected request-token to fail with unwritable known_hosts path")
	}
	if !strings.Contains(err.Error(), "failed to save host key") {
		t.Fatalf("expected known_hosts save failure, got: %v", err)
	}
	if data := readFileIfExists(t, env.AuthorizedKeysPath); strings.TrimSpace(data) != "" {
		t.Fatalf("expected authorized_keys to remain empty, got:\n%s", data)
	}
}

func TestProvisioningConnectionDropAfterApprovalResponseIsHandledSafely(t *testing.T) {
	env := prepareFreshProvisioningEnv(t, true)

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

	client, err := dialProvisioningClient(t, sshCfg.Host, sshCfg.Port, "request-token:default", clientSigner, hostKey)
	if err != nil {
		t.Fatalf("failed to establish provisioning SSH client: %v", err)
	}

	session, err := client.NewSession()
	if err != nil {
		_ = client.Close()
		t.Fatalf("failed to create provisioning session: %v", err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		_ = session.Close()
		_ = client.Close()
		t.Fatalf("failed to create provisioning stdout pipe: %v", err)
	}
	if err := session.Start("provision"); err != nil {
		_ = session.Close()
		_ = client.Close()
		t.Fatalf("failed to start provisioning session: %v", err)
	}

	req := mustReadIPCTokenProvisioningRequest(t, ipcClient, 10*time.Second)
	mustRespondIPCTokenProvisioningRequest(t, ipcClient, req.ID, true)

	_ = client.Close()
	_ = session.Close()
	_, _ = io.ReadAll(stdout)

	time.Sleep(500 * time.Millisecond)

	authKeysData, err := os.ReadFile(env.AuthorizedKeysPath)
	if err != nil {
		t.Fatalf("failed to read authorized_keys: %v", err)
	}
	clientPubKey, err := os.ReadFile(env.ClientPublicKeyPath)
	if err != nil {
		t.Fatalf("failed to read client public key: %v", err)
	}
	auditData := readFileIfExists(t, filepath.Join(env.SignerDataDir, "audit.log"))
	if strings.Contains(auditData, "token_provisioned") {
		t.Fatalf("did not expect token_provisioned audit entry after delivery failure:\n%s", auditData)
	}
	if !strings.Contains(string(authKeysData), strings.TrimSpace(string(clientPubKey))) {
		t.Log("client disconnected before server consumed approval response; key enrollment was correctly canceled")
		return
	}

	if _, err := os.Stat(signerd.GetTokenPath()); err != nil {
		t.Fatalf("expected signer token to exist after post-approval issuance path: %v", err)
	}
}

type sshProvisioningEnv struct {
	SignerDataDir       string
	ClientDataDir       string
	ClientTokenPath     string
	KnownHostsPath      string
	ClientPublicKeyPath string
	AuthorizedKeysPath  string
	HostPublicKeyPath   string
}

func prepareFreshProvisioningEnv(t *testing.T, prepopulateKnownHosts bool) *sshProvisioningEnv {
	t.Helper()

	env := harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{})

	clientTokenPath := filepath.Join(env.ClientDataDir, "aplane.token")
	knownHostsPath := filepath.Join(env.ClientDataDir, ".ssh", "known_hosts")
	clientPrivateKeyPath := filepath.Join(env.ClientDataDir, ".ssh", "id_ed25519")
	clientPublicKeyPath := clientPrivateKeyPath + ".pub"
	authorizedKeysPath := filepath.Join(env.SignerDataDir, "identities", "default", ".ssh", "authorized_keys")
	legacyAuthorizedKeysPath := filepath.Join(env.SignerDataDir, ".ssh", "authorized_keys")
	hostPublicKeyPath := filepath.Join(env.SignerDataDir, ".ssh", "ssh_host_key.pub")

	removeIfExists(t, clientTokenPath)
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

	return &sshProvisioningEnv{
		SignerDataDir:       env.SignerDataDir,
		ClientDataDir:       env.ClientDataDir,
		ClientTokenPath:     clientTokenPath,
		KnownHostsPath:      knownHostsPath,
		ClientPublicKeyPath: clientPublicKeyPath,
		AuthorizedKeysPath:  authorizedKeysPath,
		HostPublicKeyPath:   hostPublicKeyPath,
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

func mustClientSSHHostPort(t *testing.T) (string, int) {
	t.Helper()

	_, sshCfg := mustLoadDefaultSignerEndpoint(t)
	return sshCfg.Host, sshCfg.Port
}

func mustLoadClientSSHConfig(t *testing.T) config.SSHClientConfig {
	t.Helper()

	_, sshCfg := mustLoadDefaultSignerEndpoint(t)
	return sshCfg
}

func mustLoadDefaultSignerEndpointOnly(t *testing.T) config.ClientEndpointConfig {
	t.Helper()

	endpoint, _ := mustLoadDefaultSignerEndpoint(t)
	return endpoint
}

func mustLoadDefaultSignerEndpoint(t *testing.T) (config.ClientEndpointConfig, config.SSHClientConfig) {
	t.Helper()

	cfg := mustLoadClientConfig(t)
	alias, endpoint, ok := cfg.Endpoints.DefaultEndpoint()
	if !ok {
		t.Fatal("client endpoint registry missing default signer endpoint")
	}
	if endpoint.Role != config.ClientEndpointRoleSigner {
		t.Fatalf("default endpoint %q role = %q, want signer", alias, endpoint.Role)
	}
	host, port, err := config.ClientEndpointSSHHostPort(endpoint)
	if err != nil {
		t.Fatalf("default endpoint %q has invalid SSH URL: %v", alias, err)
	}
	sshCfg := config.SSHClientConfig{
		Host:           host,
		Port:           port,
		IdentityFile:   endpoint.IdentityFile,
		KnownHostsPath: endpoint.KnownHostsPath,
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

func requestTokenViaEngine(t *testing.T, eng *engine.Engine, sshCfg config.SSHClientConfig, ipcClient *transport.IPCClient, hostKeyApproval func(host string, fingerprint string) (bool, error)) (string, error) {
	t.Helper()
	return requestTokenViaEngineWithIdentity(t, eng, sshCfg, sshCfg.IdentityFile, ipcClient, hostKeyApproval)
}

func requestTokenViaEngineWithIdentity(t *testing.T, eng *engine.Engine, sshCfg config.SSHClientConfig, identityFile string, ipcClient *transport.IPCClient, hostKeyApproval func(host string, fingerprint string) (bool, error)) (string, error) {
	t.Helper()

	var (
		token   string
		reqErr  error
		reqDone sync.WaitGroup
	)
	reqDone.Add(1)
	go func() {
		defer reqDone.Done()
		token, reqErr = eng.RequestTokenWithContext(context.Background(),
			sshCfg.Host,
			sshCfg.Port,
			identityFile,
			sshCfg.KnownHostsPath,
			hostKeyApproval,
			nil,
		)
	}()

	req := mustReadIPCTokenProvisioningRequest(t, ipcClient, 10*time.Second)
	mustRespondIPCTokenProvisioningRequest(t, ipcClient, req.ID, true)
	reqDone.Wait()
	return token, reqErr
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

func mustReadIPCTokenProvisioningRequest(t *testing.T, ipcClient *transport.IPCClient, timeout time.Duration) protocol.TokenProvisioningRequestMessage {
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
		if base.Type != protocol.MsgTypeTokenProvisioningRequest {
			continue
		}

		var req protocol.TokenProvisioningRequestMessage
		if err := json.Unmarshal(message, &req); err != nil {
			t.Fatalf("failed to parse token provisioning request: %v", err)
		}
		return req
	}

	t.Fatalf("timed out waiting for token provisioning request over IPC")
	return protocol.TokenProvisioningRequestMessage{}
}

func mustRespondIPCTokenProvisioningRequest(t *testing.T, ipcClient *transport.IPCClient, requestID string, approved bool) {
	t.Helper()

	reason := ""
	if !approved {
		reason = "rejected by test"
	}
	if err := ipcClient.WriteJSON(protocol.TokenProvisioningResponseMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeTokenProvisioningResponse,
			ID:   requestID,
		},
		Approved: approved,
		Reason:   reason,
	}); err != nil {
		t.Fatalf("failed to send token provisioning response over IPC: %v", err)
	}
}

func mustRevokeTokenViaIPC(t *testing.T, ipcClient *transport.IPCClient, tokenPath string) string {
	t.Helper()

	reqID := fmt.Sprintf("revoke-%d", time.Now().UnixNano())
	if err := ipcClient.WriteJSON(protocol.RevokeTokenMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeRevokeToken,
			ID:   reqID,
		},
	}); err != nil {
		t.Fatalf("failed to send revoke-token IPC message: %v", err)
	}

	ipcClient.SetReadDeadline(10 * time.Second)
	for {
		message, err := ipcClient.ReadMessage()
		if err != nil {
			t.Fatalf("failed to read revoke-token response: %v", err)
		}

		var base protocol.BaseMessage
		if err := json.Unmarshal(message, &base); err != nil {
			t.Fatalf("failed to parse revoke-token base message: %v", err)
		}
		if base.Type != protocol.MsgTypeRevokeTokenResult || base.ID != reqID {
			continue
		}

		var result protocol.RevokeTokenResultMessage
		if err := json.Unmarshal(message, &result); err != nil {
			t.Fatalf("failed to parse revoke-token result: %v", err)
		}
		if !result.Success {
			t.Fatalf("revoke-token failed: %s", result.Error)
		}
		token, err := util.ReadToken(tokenPath)
		if err != nil {
			t.Fatalf("failed to read signer token after revoke: %v", err)
		}
		return token
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

func dialProvisioningClient(t *testing.T, host string, port int, user string, signer ssh.Signer, hostKey ssh.PublicKey) (*ssh.Client, error) {
	t.Helper()

	clientConfig := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(hostKey),
		Timeout:         10 * time.Second,
	}
	return ssh.Dial("tcp", fmt.Sprintf("%s:%d", host, port), clientConfig)
}

func runProvisioningExec(t *testing.T, client *ssh.Client, command string) (string, int, error) {
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
