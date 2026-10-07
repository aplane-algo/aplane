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
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/engine/connect"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/enrollqueue"
	"github.com/aplane-algo/aplane/internal/transport"
	"github.com/aplane-algo/aplane/test/integration/harness"

	"golang.org/x/crypto/ssh"
)

// The client's SSH key is its only credential. These tests cover the
// request-enrollment protocol: a request is queued for the operator and
// answered at once, the operator approves or rejects it over IPC (apadmin)
// at any later time, waiting requests survive a restart and are announced
// to an operator at login, a key can be pre-enrolled by import, and
// revocation closes live tunnels.

// A request is queued and announced to the connected operator; once the
// operator approves it the client connects with its key.
func TestRequestEnrollmentQueuesAndApprovalEnrolls(t *testing.T) {
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

	var started string
	result, err := eng.RequestEnrollmentWithContext(context.Background(),
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
	if err != nil {
		t.Fatalf("engine request-enrollment failed unexpectedly: %v", err)
	}
	want := mustClientKeyFingerprint(t, env.ClientPublicKeyPath)
	if !result.Pending || result.Fingerprint != want || started != want {
		t.Fatalf("result = %+v, started %q, want pending request for %q", result, started, want)
	}

	req := mustReadIPCEnrollmentRequest(t, ipcClient, 10*time.Second)
	if req.SSHFingerprint != want || req.Label != "ci-laptop" {
		t.Fatalf("enrollment request notification = %+v, want %s ci-laptop", req, want)
	}
	requireEnrolledKeys(t, env, 0)

	// Until the operator answers, the key is refused.
	apshell := harness.NewApshellHarness(t)
	output, err := apshell.RunWithInput("quit\n")
	if err != nil {
		t.Fatalf("apshell before approval: %v\noutput:\n%s", err, output)
	}
	if !strings.Contains(output, "not enrolled at the signer") {
		t.Fatalf("expected a refused connection before approval, got output:\n%s", output)
	}

	if label := mustApproveEnrollmentViaIPC(t, ipcClient, want, ""); label != "ci-laptop" {
		t.Fatalf("approval recorded label %q, want ci-laptop", label)
	}
	requireEnrolledKeys(t, env, 1)
	if pending := mustListPendingEnrollmentsViaIPC(t, ipcClient); len(pending) != 0 {
		t.Fatalf("pending after approval = %+v, want none", pending)
	}

	knownHostsData, err := os.ReadFile(env.KnownHostsPath)
	if err != nil {
		t.Fatalf("failed to read known_hosts: %v", err)
	}
	if !strings.Contains(string(knownHostsData), fmt.Sprintf("[%s]:%d", sshCfg.Host, sshCfg.Port)) {
		t.Fatalf("known_hosts does not contain expected host entry:\n%s", string(knownHostsData))
	}

	connectOutput, err := apshell.RunWithInput("quit\n")
	if err != nil {
		t.Fatalf("expected apshell startup auto-connect to succeed: %v\noutput:\n%s", err, connectOutput)
	}
	if !strings.Contains(connectOutput, "Signer verified via tunnel") {
		t.Fatalf("expected tunnel verification after approval, got output:\n%s", connectOutput)
	}

	// The audit trail records the request and the approval.
	audit := readFileIfExists(t, filepath.Join(env.SignerDataDir, "audit.log"))
	if !strings.Contains(audit, "CLIENT_ENROLLMENT_REQUESTED") || !strings.Contains(audit, "CLIENT_ENROLLED") {
		t.Fatalf("audit log lacks the enrollment events:\n%s", audit)
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
	if data := readFileIfExists(t, env.PendingPath); strings.Contains(data, mustClientKeyBlob(t, env.ClientPublicKeyPath)) {
		t.Fatalf("a request was queued without host trust:\n%s", data)
	}
}

// A request needs no operator to be present: it is queued, apshell reports
// it as waiting, and an operator who connects later sees it at login.
func TestRequestEnrollmentQueuesWithoutOperatorAndReplaysAtLogin(t *testing.T) {
	env := prepareFreshEnrollmentEnv(t, true)

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	apshell := harness.NewApshellHarness(t)
	output, err := apshell.RunWithInput("request-enrollment --label field-laptop\nquit\n")
	if err != nil {
		t.Fatalf("request-enrollment command failed unexpectedly: %v\noutput:\n%s", err, output)
	}
	if !strings.Contains(output, "waiting for the operator") {
		t.Fatalf("expected a pending request in output, got:\n%s", output)
	}
	requireEnrolledKeys(t, env, 0)
	want := mustClientKeyFingerprint(t, env.ClientPublicKeyPath)
	if data := readFileIfExists(t, env.PendingPath); !strings.Contains(data, mustClientKeyBlob(t, env.ClientPublicKeyPath)) {
		t.Fatalf("request was not persisted to %s:\n%s", env.PendingPath, data)
	}

	ipcClient := mustConnectIPCClient(t, signerd.GetWorkDir())
	defer ipcClient.Close()
	req := mustReadIPCEnrollmentRequest(t, ipcClient, 10*time.Second)
	if req.SSHFingerprint != want || req.Label != "field-laptop" {
		t.Fatalf("request announced at login = %+v, want %s field-laptop", req, want)
	}
	if pending := mustListPendingEnrollmentsViaIPC(t, ipcClient); len(pending) != 1 || pending[0].Fingerprint != want || pending[0].Label != "field-laptop" {
		t.Fatalf("pending list = %+v, want the one request", pending)
	}

	mustApproveEnrollmentViaIPC(t, ipcClient, want, "")
	connectOutput, err := apshell.RunWithInput("quit\n")
	if err != nil || !strings.Contains(connectOutput, "Signer verified via tunnel") {
		t.Fatalf("expected a connection after approval: %v\noutput:\n%s", err, connectOutput)
	}
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

	eng, err := engine.NewEngine(harness.IntegrationNetwork())
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	sshCfg := mustLoadClientSSHConfig(t)
	result, err := requestEnrollmentViaEngine(t, eng, sshCfg, nil)
	if err != nil || !result.Pending {
		t.Fatalf("request = %+v, %v, want pending", result, err)
	}
	_ = mustReadIPCEnrollmentRequest(t, ipcClient, 10*time.Second)

	mustRejectEnrollmentViaIPC(t, ipcClient, result.Fingerprint)
	requireEnrolledKeys(t, env, 0)
	if pending := mustListPendingEnrollmentsViaIPC(t, ipcClient); len(pending) != 0 {
		t.Fatalf("pending after rejection = %+v, want none", pending)
	}
	if errText := mustSendRejectEnrollmentViaIPC(t, ipcClient, result.Fingerprint); !strings.Contains(errText, "no enrollment request is waiting") {
		t.Fatalf("second rejection error = %q, want no request waiting", errText)
	}
	audit := readFileIfExists(t, filepath.Join(env.SignerDataDir, "audit.log"))
	if !strings.Contains(audit, "CLIENT_ENROLLMENT_REJECTED") {
		t.Fatalf("audit log lacks the rejection:\n%s", audit)
	}

	apshell := harness.NewApshellHarness(t)
	output, err := apshell.RunWithInput("quit\n")
	if err != nil || !strings.Contains(output, "not enrolled at the signer") {
		t.Fatalf("expected the key to stay refused after rejection: %v\noutput:\n%s", err, output)
	}
}

// A waiting request survives a daemon restart.
func TestRequestEnrollmentPersistsAcrossRestart(t *testing.T) {
	env := prepareFreshEnrollmentEnv(t, true)

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
	result, err := requestEnrollmentViaEngine(t, eng, sshCfg, nil)
	if err != nil || !result.Pending {
		t.Fatalf("request = %+v, %v, want pending", result, err)
	}

	if err := signerd.Stop(); err != nil {
		t.Fatalf("stop signer: %v", err)
	}
	if err := signerd.Start(); err != nil {
		t.Fatalf("restart signer: %v", err)
	}

	ipcClient := mustConnectIPCClient(t, signerd.GetWorkDir())
	defer ipcClient.Close()
	if pending := mustListPendingEnrollmentsViaIPC(t, ipcClient); len(pending) != 1 || pending[0].Fingerprint != result.Fingerprint {
		t.Fatalf("pending after restart = %+v, want the request", pending)
	}
	mustApproveEnrollmentViaIPC(t, ipcClient, result.Fingerprint, "after-restart")
	requireEnrolledKeys(t, env, 1)
	if !strings.Contains(readFileIfExists(t, env.AuthorizedKeysPath), "after-restart") {
		t.Fatal("the label given at approval was not recorded")
	}

	apshell := harness.NewApshellHarness(t)
	output, err := apshell.RunWithInput("quit\n")
	if err != nil || !strings.Contains(output, "Signer verified via tunnel") {
		t.Fatalf("expected a connection after approval: %v\noutput:\n%s", err, output)
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

// Repeated requests for one key refresh a single queue entry and need no new
// host trust; once the key is enrolled a further request says so.
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
	first, err := requestEnrollmentViaEngine(t, eng, sshCfg, func(host, fingerprint string) (bool, error) {
		hostApprovals++
		return true, nil
	})
	if err != nil || !first.Pending {
		t.Fatalf("first request = %+v, %v, want pending", first, err)
	}
	if hostApprovals != 1 {
		t.Fatalf("first request should prompt exactly once for TOFU, got %d", hostApprovals)
	}
	_ = mustReadIPCEnrollmentRequest(t, ipcClient, 10*time.Second)

	secondHostApprovals := 0
	second, err := requestEnrollmentViaEngine(t, eng, sshCfg, func(host, fingerprint string) (bool, error) {
		secondHostApprovals++
		return true, nil
	})
	if err != nil || !second.Pending || second.Fingerprint != first.Fingerprint {
		t.Fatalf("second request = %+v, %v, want the same pending request", second, err)
	}
	if secondHostApprovals != 0 {
		t.Fatalf("second request should not require TOFU, got %d approval prompts", secondHostApprovals)
	}
	if pending := mustListPendingEnrollmentsViaIPC(t, ipcClient); len(pending) != 1 {
		t.Fatalf("pending list = %+v, want one entry for the repeated request", pending)
	}

	knownHostsData, err := os.ReadFile(env.KnownHostsPath)
	if err != nil {
		t.Fatalf("failed to read known_hosts: %v", err)
	}
	hostEntry := fmt.Sprintf("[%s]:%d", sshCfg.Host, sshCfg.Port)
	if count := strings.Count(string(knownHostsData), hostEntry); count != 1 {
		t.Fatalf("expected exactly one known_hosts entry for %s, got %d in:\n%s", hostEntry, count, string(knownHostsData))
	}

	mustApproveEnrollmentViaIPC(t, ipcClient, first.Fingerprint, "")
	requireEnrolledKeys(t, env, 1)
	third, err := requestEnrollmentViaEngine(t, eng, sshCfg, nil)
	if err != nil || third.Pending || third.Fingerprint != first.Fingerprint {
		t.Fatalf("request after enrollment = %+v, %v, want already enrolled", third, err)
	}
	requireEnrolledKeys(t, env, 1)
}

// A request the signer cannot record is refused with a clear message and
// leaves nothing behind.
func TestRequestEnrollmentReportsQueueWriteFailure(t *testing.T) {
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

	apshell := harness.NewApshellHarness(t)
	output, err := apshell.RunWithInput("request-enrollment\nquit\n")
	if err != nil {
		t.Fatalf("request-enrollment command failed unexpectedly: %v\noutput:\n%s", err, output)
	}
	if !strings.Contains(output, "failed to record enrollment request") {
		t.Fatalf("expected the recording failure, got output:\n%s", output)
	}
	requireEnrolledKeys(t, env, 0)
}

// The queue is bounded: once MaxPending distinct keys are waiting, a further
// key is refused until the operator clears the queue.
func TestRequestEnrollmentQueueIsCapped(t *testing.T) {
	env := prepareFreshEnrollmentEnv(t, true)

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	hostKey := mustLoadSSHPublicKey(t, filepath.Join(env.SignerDataDir, ".ssh", "ssh_host_key.pub"))
	sshCfg := mustLoadClientSSHConfig(t)
	submit := func() (string, int) {
		keyPath := filepath.Join(t.TempDir(), "id_ed25519")
		writeSSHIdentity(t, keyPath, keyPath+".pub")
		client, err := dialEnrollmentClient(t, sshCfg.Host, sshCfg.Port, "request-enrollment", mustLoadSSHSigner(t, keyPath), hostKey)
		if err != nil {
			t.Fatalf("dial enrollment: %v", err)
		}
		defer func() { _ = client.Close() }()
		output, exitCode, err := runEnrollmentExec(t, client, "enroll")
		if err != nil {
			t.Fatalf("enrollment exec: %v", err)
		}
		return output, exitCode
	}
	for i := 0; i < enrollqueue.MaxPending; i++ {
		if output, exitCode := submit(); exitCode != 0 || !strings.HasPrefix(output, "pending ") {
			t.Fatalf("request %d = %d %q, want pending", i+1, exitCode, output)
		}
	}
	output, exitCode := submit()
	if exitCode == 0 || !strings.Contains(output, "enrollment queue is full") {
		t.Fatalf("request beyond the cap = %d %q, want the full-queue refusal", exitCode, output)
	}

	ipcClient := mustConnectIPCClient(t, signerd.GetWorkDir())
	defer ipcClient.Close()
	pending := mustListPendingEnrollmentsViaIPC(t, ipcClient)
	if len(pending) != enrollqueue.MaxPending {
		t.Fatalf("pending = %d, want %d", len(pending), enrollqueue.MaxPending)
	}
	mustRejectEnrollmentViaIPC(t, ipcClient, pending[0].Fingerprint)
	if output, exitCode := submit(); exitCode != 0 || !strings.HasPrefix(output, "pending ") {
		t.Fatalf("request after clearing one entry = %d %q, want pending", exitCode, output)
	}
}

// An operator can enroll a key without a request from the client.
func TestImportClientKeyPreEnrolls(t *testing.T) {
	env := prepareFreshEnrollmentEnv(t, true)

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	ipcClient := mustConnectIPCClient(t, signerd.GetWorkDir())
	defer ipcClient.Close()

	line := strings.TrimSpace(readFileIfExists(t, env.ClientPublicKeyPath))
	want := mustClientKeyFingerprint(t, env.ClientPublicKeyPath)
	fingerprint, label, added := mustImportClientKeyViaIPC(t, ipcClient, line, "imported-laptop")
	if fingerprint != want || label != "imported-laptop" || !added {
		t.Fatalf("import = %s %q %v, want %s imported-laptop added", fingerprint, label, added, want)
	}
	if _, _, added := mustImportClientKeyViaIPC(t, ipcClient, line, ""); added {
		t.Fatal("second import reported the key as new")
	}
	requireEnrolledKeys(t, env, 1)

	// The batch listing authenticates read-only, so the inventory requests
	// must be on the auth_only allowlist.
	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	listing, err := apadmin.RunWithInput(os.Getenv("TEST_PASSPHRASE")+"\n", "clients", "list")
	if err != nil || !strings.Contains(listing, "enrolled  "+want) || !strings.Contains(listing, "imported-laptop") {
		t.Fatalf("apadmin clients list: %v\noutput:\n%s", err, listing)
	}

	apshell := harness.NewApshellHarness(t)
	output, err := apshell.RunWithInput("quit\n")
	if err != nil || !strings.Contains(output, "Signer verified via tunnel") {
		t.Fatalf("expected a connection with the imported key: %v\noutput:\n%s", err, output)
	}
	eng, err := engine.NewEngine(harness.IntegrationNetwork())
	if err != nil {
		t.Fatal(err)
	}
	if result, err := requestEnrollmentViaEngine(t, eng, mustLoadClientSSHConfig(t), nil); err != nil || result.Pending {
		t.Fatalf("request for an imported key = %+v, %v, want already enrolled", result, err)
	}
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

	result, err := requestEnrollmentViaEngineWithIdentity(t, eng, clientCfg, "", nil)
	if err != nil || !result.Pending {
		t.Fatalf("agent-backed request = %+v, %v, want pending", result, err)
	}
	if want := mustClientKeyFingerprint(t, agentKeyPath+".pub"); result.Fingerprint != want {
		t.Fatalf("requested fingerprint = %q, want agent key %q", result.Fingerprint, want)
	}
	mustApproveEnrollmentViaIPC(t, ipcClient, result.Fingerprint, "")
	if !strings.Contains(readFileIfExists(t, env.AuthorizedKeysPath), mustClientKeyBlob(t, agentKeyPath+".pub")) {
		t.Fatalf("authorized_keys does not contain agent key:\n%s", readFileIfExists(t, env.AuthorizedKeysPath))
	}

	localPort := mustAvailableLocalPort(t)
	connected, err := eng.ConnectWithTunnel(
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
	if !connected.Connected {
		t.Fatalf("expected connected result, got %+v", connected)
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

	result, err := requestEnrollmentViaEngine(t, eng, sshCfg, func(host, hostFingerprint string) (bool, error) {
		return true, nil
	})
	if err != nil || !result.Pending {
		t.Fatalf("request = %+v, %v, want pending", result, err)
	}
	_ = mustReadIPCEnrollmentRequest(t, ipcClient, 10*time.Second)
	mustApproveEnrollmentViaIPC(t, ipcClient, result.Fingerprint, "")
	fingerprint := result.Fingerprint

	disconnectCh := make(chan struct{}, 1)
	onDisconnect := func() {
		select {
		case disconnectCh <- struct{}{}:
		default:
		}
	}
	localPort := mustAvailableLocalPort(t)
	connected, err := eng.ConnectWithTunnel(
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
	if !connected.Connected {
		t.Fatalf("expected connected result, got %+v", connected)
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
	if data := readFileIfExists(t, env.PendingPath); strings.Contains(data, mustClientKeyBlob(t, env.ClientPublicKeyPath)) {
		t.Fatalf("an unknown command queued a request:\n%s", data)
	}
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

// A client that drops as soon as it has submitted leaves its request queued
// for the operator; the server keeps serving.
func TestEnrollmentRequestOutlivesTheSubmittingConnection(t *testing.T) {
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
	session, err := client.NewSession()
	if err != nil {
		_ = client.Close()
		t.Fatalf("failed to create enrollment session: %v", err)
	}
	if err := session.Start("enroll dropped"); err != nil {
		_ = session.Close()
		_ = client.Close()
		t.Fatalf("failed to start enrollment session: %v", err)
	}
	_ = client.Close()
	_ = session.Close()

	if err := signerd.WaitForReady(5 * time.Second); err != nil {
		t.Fatalf("signer not healthy after the client dropped: %v", err)
	}
	ipcClient := mustConnectIPCClient(t, signerd.GetWorkDir())
	defer ipcClient.Close()
	deadline := time.Now().Add(5 * time.Second)
	want := mustClientKeyFingerprint(t, env.ClientPublicKeyPath)
	for {
		pending := mustListPendingEnrollmentsViaIPC(t, ipcClient)
		if len(pending) == 1 && pending[0].Fingerprint == want {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("pending = %+v, want the dropped client's request", pending)
		}
		time.Sleep(100 * time.Millisecond)
	}
	mustApproveEnrollmentViaIPC(t, ipcClient, want, "")
	requireEnrolledKeys(t, env, 1)
}

type sshEnrollmentEnv struct {
	SignerDataDir       string
	ClientDataDir       string
	KnownHostsPath      string
	ClientPublicKeyPath string
	AuthorizedKeysPath  string
	PendingPath         string
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
	pendingPath := filepath.Join(env.SignerDataDir, "identities", "default", ".ssh", enrollqueue.FileName)
	legacyAuthorizedKeysPath := filepath.Join(env.SignerDataDir, ".ssh", "authorized_keys")
	hostPublicKeyPath := filepath.Join(env.SignerDataDir, ".ssh", "ssh_host_key.pub")

	removeIfExists(t, knownHostsPath)
	removeIfExists(t, pendingPath)
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
		PendingPath:         pendingPath,
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

func requestEnrollmentViaEngine(t *testing.T, eng *engine.Engine, sshCfg config.ClientEndpointSSH, hostKeyApproval func(host string, fingerprint string) (bool, error)) (connect.EnrollmentResult, error) {
	t.Helper()
	return requestEnrollmentViaEngineWithIdentity(t, eng, sshCfg, sshCfg.IdentityFile, hostKeyApproval)
}

// requestEnrollmentViaEngineWithIdentity submits a request through the
// engine; a nil host-key approval trusts the host on first use.
func requestEnrollmentViaEngineWithIdentity(t *testing.T, eng *engine.Engine, sshCfg config.ClientEndpointSSH, identityFile string, hostKeyApproval func(host string, fingerprint string) (bool, error)) (connect.EnrollmentResult, error) {
	t.Helper()
	if hostKeyApproval == nil {
		hostKeyApproval = func(string, string) (bool, error) { return true, nil }
	}
	return eng.RequestEnrollmentWithContext(context.Background(),
		sshCfg.Host,
		sshCfg.Port,
		identityFile,
		sshCfg.KnownHostsPath,
		"",
		hostKeyApproval,
		nil,
	)
}

// ipcRequest sends an admin message and decodes the response of the given
// type that carries the same ID, skipping notifications.
func ipcRequest(t *testing.T, ipcClient *transport.IPCClient, msg interface{}, id, wantType string, out interface{}) {
	t.Helper()
	if err := ipcClient.WriteJSON(msg); err != nil {
		t.Fatalf("failed to send %s over IPC: %v", wantType, err)
	}
	ipcClient.SetReadDeadline(10 * time.Second)
	for {
		message, err := ipcClient.ReadMessage()
		if err != nil {
			t.Fatalf("failed to read %s response: %v", wantType, err)
		}
		var base protocol.BaseMessage
		if err := json.Unmarshal(message, &base); err != nil {
			t.Fatalf("failed to parse IPC base message: %v", err)
		}
		if base.Type != wantType || base.ID != id {
			continue
		}
		if err := json.Unmarshal(message, out); err != nil {
			t.Fatalf("failed to parse %s: %v", wantType, err)
		}
		return
	}
}

func mustListPendingEnrollmentsViaIPC(t *testing.T, ipcClient *transport.IPCClient) []protocol.PendingEnrollmentInfo {
	t.Helper()
	id := fmt.Sprintf("pending-%d", time.Now().UnixNano())
	var result protocol.PendingEnrollmentsListMessage
	ipcRequest(t, ipcClient, protocol.ListPendingEnrollmentsMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeListPendingEnrollments, ID: id},
	}, id, protocol.MsgTypePendingEnrollmentsList, &result)
	return result.Requests
}

// mustApproveEnrollmentViaIPC approves a waiting request and returns the
// label recorded.
func mustApproveEnrollmentViaIPC(t *testing.T, ipcClient *transport.IPCClient, fingerprint, label string) string {
	t.Helper()
	id := fmt.Sprintf("approve-%d", time.Now().UnixNano())
	var result protocol.ApproveEnrollmentResultMessage
	ipcRequest(t, ipcClient, protocol.ApproveEnrollmentMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeApproveEnrollment, ID: id},
		Fingerprint: fingerprint, Label: label,
	}, id, protocol.MsgTypeApproveEnrollmentResult, &result)
	if !result.Success {
		t.Fatalf("approve-enrollment failed: %s", result.Error)
	}
	return result.Label
}

// mustSendRejectEnrollmentViaIPC rejects a request and returns the error
// text, empty on success.
func mustSendRejectEnrollmentViaIPC(t *testing.T, ipcClient *transport.IPCClient, fingerprint string) string {
	t.Helper()
	id := fmt.Sprintf("reject-%d", time.Now().UnixNano())
	var result protocol.RejectEnrollmentResultMessage
	ipcRequest(t, ipcClient, protocol.RejectEnrollmentMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeRejectEnrollment, ID: id},
		Fingerprint: fingerprint,
	}, id, protocol.MsgTypeRejectEnrollmentResult, &result)
	if result.Success {
		return ""
	}
	return result.Error
}

func mustRejectEnrollmentViaIPC(t *testing.T, ipcClient *transport.IPCClient, fingerprint string) {
	t.Helper()
	if errText := mustSendRejectEnrollmentViaIPC(t, ipcClient, fingerprint); errText != "" {
		t.Fatalf("reject-enrollment failed: %s", errText)
	}
}

func mustImportClientKeyViaIPC(t *testing.T, ipcClient *transport.IPCClient, publicKey, label string) (fingerprint, recordedLabel string, added bool) {
	t.Helper()
	id := fmt.Sprintf("import-%d", time.Now().UnixNano())
	var result protocol.ImportClientKeyResultMessage
	ipcRequest(t, ipcClient, protocol.ImportClientKeyMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeImportClientKey, ID: id},
		PublicKey:   publicKey, Label: label,
	}, id, protocol.MsgTypeImportClientKeyResult, &result)
	if !result.Success {
		t.Fatalf("import-client-key failed: %s", result.Error)
	}
	return result.Fingerprint, result.Label, result.Added
}

// mustRevokeKeyViaIPC revokes one enrolled key and returns how many live
// connections the signer closed for it.
func mustRevokeKeyViaIPC(t *testing.T, ipcClient *transport.IPCClient, fingerprint string) int {
	t.Helper()
	id := fmt.Sprintf("revoke-%d", time.Now().UnixNano())
	var result protocol.RevokeEnrolledKeyResultMessage
	ipcRequest(t, ipcClient, protocol.RevokeEnrolledKeyMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeRevokeEnrolledKey, ID: id},
		Fingerprint: fingerprint,
	}, id, protocol.MsgTypeRevokeEnrolledKeyResult, &result)
	if !result.Success {
		t.Fatalf("revoke-key failed: %s", result.Error)
	}
	return result.ClosedConnections
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
