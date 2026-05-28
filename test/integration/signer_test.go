// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integration_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signerclient"
	utilkeys "github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/transport"
	"github.com/aplane-algo/aplane/test/integration/harness"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/mnemonic"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
	"gopkg.in/yaml.v3"
)

const integrationBurnAddress = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
const integrationTemplatePublisher = "test"

func integrationTemplateKeyType(family string) string {
	return fmt.Sprintf("%s.%s.v1", integrationTemplatePublisher, family)
}

func installTemplateLibraryFile(t *testing.T, signerDataDir, filename, description string) {
	t.Helper()

	t.Setenv("APSIGNER_PASSPHRASE", mustReadPassphrase(t, signerDataDir))
	apstore := harness.NewApStoreHarness(t, signerDataDir)
	templatePath := syncTemplateLibraryFile(t, signerDataDir, filename)
	runWithTempSigner(t, func() {
		if output, err := apstore.Run("template", "import", templatePath); err != nil {
			t.Fatalf("failed to add %s template: %v\noutput:\n%s", description, err, output)
		}
	})
}

func runWithTempSigner(t *testing.T, fn func()) {
	t.Helper()

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	defer func() {
		if err := signerd.Stop(); err != nil {
			t.Fatalf("failed to stop signer: %v", err)
		}
	}()
	fn()
}

func mustImportTemplateViaApstore(t *testing.T, signerDataDir string, apstore *harness.ApStoreHarness, templatePath, description string) {
	t.Helper()

	t.Setenv("APSIGNER_PASSPHRASE", mustReadPassphrase(t, signerDataDir))
	runWithTempSigner(t, func() {
		if output, err := apstore.Run("template", "import", templatePath); err != nil {
			t.Fatalf("failed to add %s template: %v\noutput:\n%s", description, err, output)
		}
	})
}

func syncTemplateLibraryFile(t *testing.T, signerDataDir, filename string) string {
	t.Helper()

	srcPath, err := filepath.Abs(filepath.Join("..", "..", "library", "templates", filename))
	if err != nil {
		t.Fatalf("failed to resolve template path %s: %v", filename, err)
	}
	data, err := os.ReadFile(srcPath)
	if err != nil {
		t.Fatalf("failed to read template %s: %v", filename, err)
	}
	paths := utilkeys.NewPaths(signerDataDir)
	if err := os.MkdirAll(paths.TemplateLibraryDir(), 0o755); err != nil {
		t.Fatalf("failed to create signer-data library dir: %v", err)
	}
	destPath := filepath.Join(paths.TemplateLibraryDir(), filename)
	if err := os.WriteFile(destPath, data, 0o644); err != nil {
		t.Fatalf("failed to sync signer-data library template %s: %v", filename, err)
	}
	return destPath
}

func installHTLCTemplate(t *testing.T, signerDataDir string) {
	t.Helper()
	installTemplateLibraryFile(t, signerDataDir, "aplane.htlc.v1.yaml", "HTLC")
}

func installWhitelistTemplate(t *testing.T, signerDataDir string) {
	t.Helper()
	installTemplateLibraryFile(t, signerDataDir, "aplane.whitelist.v1.yaml", "whitelist")
}

func installFalconHashlockTemplate(t *testing.T, signerDataDir string) {
	t.Helper()
	installTemplateLibraryFile(t, signerDataDir, "aplane.falcon1024-hashlock.v1.yaml", "Falcon hashlock")
}

func installFalconWhitelistTemplate(t *testing.T, signerDataDir string) {
	t.Helper()
	installTemplateLibraryFile(t, signerDataDir, "aplane.falcon1024-whitelist.v1.yaml", "Falcon whitelist")
}

func TestSignerRejectsWhenLocked(t *testing.T) {
	lockOnDisconnect := true
	harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{LockOnDisconnect: &lockOnDisconnect})

	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("failed to connect to testnet: %v", err)
	}

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	t.Cleanup(apadmin.Cleanup)

	address, err := apadmin.GenerateKeyWithType("ed25519")
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	sp, err := testnet.GetSuggestedParams()
	if err != nil {
		t.Fatalf("failed to get suggested params: %v", err)
	}

	token := readSignerToken(t, signerd)
	signReq := signerapi.GroupSignRequest{
		Requests: []signerapi.SignRequest{{
			AuthAddress: address,
			TxnBytesHex: mustUnsignedPaymentTxnHex(t, sp, address, integrationBurnAddress, 0, "locked-test"),
		}},
	}

	status, body := postSignRequest(t, signerd.GetURL(), "aplane "+token, signReq)
	if status != http.StatusForbidden {
		t.Fatalf("expected 403 when signer is locked, got %d: %s", status, string(body))
	}
	if !strings.Contains(string(body), "signer is locked") {
		t.Fatalf("expected locked error, got %s", string(body))
	}
}

func TestLockOnDisconnectControlsPostDisconnectSigningState(t *testing.T) {
	cases := []struct {
		name             string
		lockOnDisconnect bool
		wantStatus       int
		wantErrSubstring string
		wantSignedCount  int
	}{
		{
			name:             "enabled relocks after admin disconnect",
			lockOnDisconnect: true,
			wantStatus:       http.StatusForbidden,
			wantErrSubstring: "signer is locked",
			wantSignedCount:  0,
		},
		{
			name:             "disabled stays unlocked after admin disconnect",
			lockOnDisconnect: false,
			wantStatus:       http.StatusOK,
			wantErrSubstring: "",
			wantSignedCount:  1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			userAutoApprove := true
			harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{
				UserAutoApprove:  &userAutoApprove,
				LockOnDisconnect: &tc.lockOnDisconnect,
			})

			testnet, err := harness.NewTestnetConfig()
			if err != nil {
				t.Fatalf("failed to connect to testnet: %v", err)
			}

			signerd := harness.NewSignerHarness(t)
			if err := signerd.Start(); err != nil {
				t.Fatalf("failed to start signer: %v", err)
			}
			t.Cleanup(func() { _ = signerd.Stop() })

			apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
			t.Cleanup(apadmin.Cleanup)

			address, err := apadmin.GenerateKeyWithType("ed25519")
			if err != nil {
				t.Fatalf("failed to generate key: %v", err)
			}

			token := readSignerToken(t, signerd)
			if !tc.lockOnDisconnect && !waitForKey(t, signerd.GetURL(), token, address, 10*time.Second) {
				t.Fatalf("signer did not reload generated key %s", address)
			}

			if tc.lockOnDisconnect {
				time.Sleep(250 * time.Millisecond)
			} else {
				ipcClient := mustConnectIPCClient(t, signerd.GetWorkDir())
				ipcClient.Close()
				time.Sleep(250 * time.Millisecond)
			}

			sp, err := testnet.GetSuggestedParams()
			if err != nil {
				t.Fatalf("failed to get suggested params: %v", err)
			}

			req := signerapi.GroupSignRequest{
				Requests: []signerapi.SignRequest{{
					AuthAddress: address,
					TxnBytesHex: mustUnsignedPaymentTxnHex(t, sp, address, integrationBurnAddress, 0, "lock-on-disconnect"),
				}},
			}
			status, body := postSignRequest(t, signerd.GetURL(), "aplane "+token, req)
			if status != tc.wantStatus {
				t.Fatalf("expected status %d, got %d: %s", tc.wantStatus, status, string(body))
			}

			var resp signerapi.GroupSignResponse
			if err := json.Unmarshal(body, &resp); err != nil {
				t.Fatalf("failed to decode sign response: %v", err)
			}
			if tc.wantErrSubstring != "" && !strings.Contains(resp.Error, tc.wantErrSubstring) {
				t.Fatalf("expected error containing %q, got %q", tc.wantErrSubstring, resp.Error)
			}
			if len(resp.Signed) != tc.wantSignedCount {
				t.Fatalf("expected %d signed transaction(s), got %d", tc.wantSignedCount, len(resp.Signed))
			}
		})
	}
}

func TestSignerRejectsUnauthorizedRequest(t *testing.T) {
	harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{})

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	reqBody := signerapi.GroupSignRequest{}

	cases := []struct {
		name       string
		authHeader string
	}{
		{name: "missing auth", authHeader: ""},
		{name: "malformed auth", authHeader: "Bearer wrong"},
		{name: "wrong token", authHeader: "aplane wrong-token"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, body := postSignRequest(t, signerd.GetURL(), tc.authHeader, reqBody)
			if status != http.StatusUnauthorized {
				t.Fatalf("expected 401, got %d: %s", status, string(body))
			}
			if !strings.Contains(string(body), "Authorization header required") {
				t.Fatalf("expected auth failure body, got %s", string(body))
			}
		})
	}
}

func TestPolicyApprovalRejection(t *testing.T) {
	userAutoApprove := false
	harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{UserAutoApprove: &userAutoApprove})

	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("failed to connect to testnet: %v", err)
	}

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	t.Cleanup(apadmin.Cleanup)

	address, err := apadmin.GenerateKeyWithType("ed25519")
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	if err := apadmin.UnlockSigner(); err != nil {
		t.Fatalf("failed to unlock signer: %v", err)
	}

	sp, err := testnet.GetSuggestedParams()
	if err != nil {
		t.Fatalf("failed to get suggested params: %v", err)
	}

	token := readSignerToken(t, signerd)
	if !waitForKey(t, signerd.GetURL(), token, address, 10*time.Second) {
		t.Fatalf("signer did not reload generated key %s", address)
	}
	signReq := signerapi.GroupSignRequest{
		Requests: []signerapi.SignRequest{{
			AuthAddress: address,
			TxnBytesHex: mustUnsignedPaymentTxnHex(t, sp, address, integrationBurnAddress, 0, "approval-test"),
		}},
	}

	status, body := postSignRequest(t, signerd.GetURL(), "aplane "+token, signReq)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when approval client is absent, got %d: %s", status, string(body))
	}
	if !strings.Contains(string(body), "no apadmin connected") {
		t.Fatalf("expected approval rejection body, got %s", string(body))
	}
}

func TestOperatorApprovalRejectionReturnsForbiddenWithNoSignedOutput(t *testing.T) {
	userAutoApprove := false
	harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{UserAutoApprove: &userAutoApprove})

	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("failed to connect to testnet: %v", err)
	}

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	t.Cleanup(apadmin.Cleanup)

	address, err := apadmin.GenerateKeyWithType("ed25519")
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	token := readSignerToken(t, signerd)
	ipcClient := mustConnectIPCClient(t, signerd.GetWorkDir())
	defer ipcClient.Close()
	mustUpdateIPCPolicySetting(t, ipcClient, "reject_asset_close", "false")

	if !waitForKey(t, signerd.GetURL(), token, address, 10*time.Second) {
		t.Fatalf("signer did not reload generated key %s", address)
	}

	sp, err := testnet.GetSuggestedParams()
	if err != nil {
		t.Fatalf("failed to get suggested params: %v", err)
	}
	req := signerapi.GroupSignRequest{
		Requests: []signerapi.SignRequest{{
			AuthAddress: address,
			TxnBytesHex: mustUnsignedPaymentTxnHex(t, sp, address, integrationBurnAddress, 0, "approval-reject"),
		}},
	}

	var (
		status int
		body   []byte
		wg     sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		status, body = postSignRequest(t, signerd.GetURL(), "aplane "+token, req)
	}()

	signReq := mustReadIPCSignRequest(t, ipcClient, 10*time.Second)
	if signReq.Address != address {
		t.Fatalf("expected approval request for %s, got %s", address, signReq.Address)
	}
	mustRejectIPCSignRequest(t, ipcClient, signReq.ID)
	wg.Wait()

	if status != http.StatusForbidden {
		t.Fatalf("expected 403 when operator rejects request, got %d: %s", status, string(body))
	}

	var signResp signerapi.GroupSignResponse
	if err := json.Unmarshal(body, &signResp); err != nil {
		t.Fatalf("failed to decode rejection response: %v", err)
	}
	if !strings.Contains(signResp.Error, "rejected by operator") {
		t.Fatalf("expected operator rejection message, got %q", signResp.Error)
	}
	if len(signResp.Signed) != 0 {
		t.Fatalf("expected no signed transactions after operator rejection, got %d", len(signResp.Signed))
	}
}

func TestPolicyHardRejectSkipsApprovalAndReturnsForbidden(t *testing.T) {
	userAutoApprove := false
	harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{UserAutoApprove: &userAutoApprove})

	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("failed to connect to testnet: %v", err)
	}

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	t.Cleanup(apadmin.Cleanup)

	address, err := apadmin.GenerateKeyWithType("ed25519")
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	if err := apadmin.UnlockSigner(); err != nil {
		t.Fatalf("failed to unlock signer: %v", err)
	}

	token := readSignerToken(t, signerd)
	if !waitForKey(t, signerd.GetURL(), token, address, 10*time.Second) {
		t.Fatalf("signer did not reload generated key %s", address)
	}

	policyClient := mustConnectIPCClient(t, signerd.GetWorkDir())
	defer policyClient.Close()
	mustUpdateIPCPolicySetting(t, policyClient, "reject_foreign_rekey", "true")

	approvalClient := mustConnectIPCClient(t, signerd.GetWorkDir())
	defer approvalClient.Close()

	sp, err := testnet.GetSuggestedParams()
	if err != nil {
		t.Fatalf("failed to get suggested params: %v", err)
	}
	rekeyTarget := crypto.GenerateAccount().Address.String()

	req := signerapi.GroupSignRequest{
		Requests: []signerapi.SignRequest{{
			AuthAddress: address,
			TxnBytesHex: mustUnsignedPaymentTxnHexWithRekey(
				t,
				sp,
				address,
				integrationBurnAddress,
				0,
				"policy-hard-reject",
				rekeyTarget,
			),
		}},
	}

	status, body := postSignRequest(t, signerd.GetURL(), "aplane "+token, req)
	if status != http.StatusForbidden {
		t.Fatalf("expected 403 for policy hard reject, got %d: %s", status, string(body))
	}

	var resp signerapi.GroupSignResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("failed to decode policy reject response: %v", err)
	}
	if !strings.Contains(resp.Error, "policy engine rejected request") || !strings.Contains(resp.Error, "reject_foreign_rekey") {
		t.Fatalf("expected policy reject response to mention reject_foreign_rekey, got %q", resp.Error)
	}
	if len(resp.Signed) != 0 {
		t.Fatalf("expected no signed transactions on policy reject, got %d", len(resp.Signed))
	}

	mustNotReceiveIPCSignRequest(t, approvalClient, 750*time.Millisecond)
}

func TestPolicyHardRejectCloseRemainderSkipsApprovalAndReturnsForbidden(t *testing.T) {
	userAutoApprove := false
	harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{UserAutoApprove: &userAutoApprove})

	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("failed to connect to testnet: %v", err)
	}

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	t.Cleanup(apadmin.Cleanup)

	address, err := apadmin.GenerateKeyWithType("ed25519")
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	if err := apadmin.UnlockSigner(); err != nil {
		t.Fatalf("failed to unlock signer: %v", err)
	}

	token := readSignerToken(t, signerd)
	if !waitForKey(t, signerd.GetURL(), token, address, 10*time.Second) {
		t.Fatalf("signer did not reload generated key %s", address)
	}

	policyClient := mustConnectIPCClient(t, signerd.GetWorkDir())
	defer policyClient.Close()
	mustUpdateIPCPolicySetting(t, policyClient, "reject_close_remainder", "true")

	approvalClient := mustConnectIPCClient(t, signerd.GetWorkDir())
	defer approvalClient.Close()

	sp, err := testnet.GetSuggestedParams()
	if err != nil {
		t.Fatalf("failed to get suggested params: %v", err)
	}
	closeTarget := crypto.GenerateAccount().Address.String()

	req := signerapi.GroupSignRequest{
		Requests: []signerapi.SignRequest{{
			AuthAddress: address,
			TxnBytesHex: mustUnsignedPaymentTxnHexWithClose(
				t,
				sp,
				address,
				integrationBurnAddress,
				0,
				"policy-hard-reject-close",
				closeTarget,
			),
		}},
	}

	status, body := postSignRequest(t, signerd.GetURL(), "aplane "+token, req)
	if status != http.StatusForbidden {
		t.Fatalf("expected 403 for close remainder policy hard reject, got %d: %s", status, string(body))
	}

	var resp signerapi.GroupSignResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("failed to decode policy reject response: %v", err)
	}
	if !strings.Contains(resp.Error, "policy engine rejected request") ||
		!strings.Contains(resp.Error, "reject_close_remainder") {
		t.Fatalf("expected policy reject response to mention reject_close_remainder, got %q", resp.Error)
	}
	if len(resp.Signed) != 0 {
		t.Fatalf("expected no signed transactions on close remainder policy reject, got %d", len(resp.Signed))
	}

	mustNotReceiveIPCSignRequest(t, approvalClient, 750*time.Millisecond)
}

func TestHiddenRekeyPaymentEmitsCriticalAlertAndChangesAuthAddr(t *testing.T) {
	if os.Getenv("TEST_FUNDING_MNEMONIC") == "" {
		t.Skip("TEST_FUNDING_MNEMONIC not set, skipping funding-backed hidden rekey test")
	}

	userAutoApprove := false
	harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{UserAutoApprove: &userAutoApprove})

	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("failed to connect to testnet: %v", err)
	}
	funder, err := harness.NewFundTestAccount(testnet.Client)
	if err != nil {
		t.Fatalf("failed to load funding account: %v", err)
	}

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	t.Cleanup(apadmin.Cleanup)

	sourceAccount := crypto.GenerateAccount()
	sourceMnemonic, err := mnemonic.FromPrivateKey(sourceAccount.PrivateKey)
	if err != nil {
		t.Fatalf("failed to encode source account mnemonic: %v", err)
	}
	sourceAddr, err := apadmin.ImportKey(sourceMnemonic)
	if err != nil {
		t.Fatalf("failed to import source account into signer: %v", err)
	}
	stealthAuthAccount := crypto.GenerateAccount()

	token := readSignerToken(t, signerd)
	if !waitForKey(t, signerd.GetURL(), token, sourceAddr, 10*time.Second) {
		t.Fatalf("signer did not reload imported source key %s", sourceAddr)
	}

	ipcClient := mustConnectIPCClient(t, signerd.GetWorkDir())
	defer ipcClient.Close()

	if err := funder.FundMicroAlgosAndWait(sourceAddr, 250_000); err != nil {
		t.Fatalf("failed to fund source account: %v", err)
	}

	rekeyConfirmed := false
	t.Cleanup(func() {
		signingKey := sourceAccount.PrivateKey
		if rekeyConfirmed {
			signingKey = stealthAuthAccount.PrivateKey
		}
		closeAccountWithSigningKey(t, testnet, sourceAddr, funder.GetAddress(), signingKey)
	})

	sp, err := testnet.GetSuggestedParams()
	if err != nil {
		t.Fatalf("failed to get suggested params: %v", err)
	}

	signReqBody := signerapi.GroupSignRequest{
		Requests: []signerapi.SignRequest{{
			AuthAddress: sourceAddr,
			TxnBytesHex: mustUnsignedPaymentTxnHexWithRekey(
				t,
				sp,
				sourceAddr,
				integrationBurnAddress,
				1_000,
				"hidden-rekey-test",
				stealthAuthAccount.Address.String(),
			),
		}},
	}

	var (
		status int
		body   []byte
		wg     sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		status, body = postSignRequest(t, signerd.GetURL(), "aplane "+token, signReqBody)
	}()

	signReq := mustReadIPCSignRequest(t, ipcClient, 10*time.Second)
	if signReq.Address != sourceAddr {
		t.Fatalf("expected approval request for %s, got %s", sourceAddr, signReq.Address)
	}
	if signReq.TxnSender != sourceAddr {
		t.Fatalf("expected sender %s, got %s", sourceAddr, signReq.TxnSender)
	}
	if !strings.Contains(signReq.Description, "Payment: 0.001000 ALGO") {
		t.Fatalf("expected payment summary in approval description, got:\n%s", signReq.Description)
	}
	if !strings.Contains(signReq.Description, "REKEY TO: "+stealthAuthAccount.Address.String()) {
		t.Fatalf("expected rekey warning in approval description, got:\n%s", signReq.Description)
	}

	var rekeyViolation *protocol.PolicyViolation
	for i := range signReq.Violations {
		if signReq.Violations[i].Field == "RekeyTo" {
			rekeyViolation = &signReq.Violations[i]
			break
		}
	}
	switch {
	case rekeyViolation == nil:
		t.Fatalf("expected RekeyTo violation, got %#v", signReq.Violations)
	case rekeyViolation.Severity != "critical":
		t.Fatalf("expected critical RekeyTo violation, got %q", rekeyViolation.Severity)
	case rekeyViolation.Value != stealthAuthAccount.Address.String():
		t.Fatalf("expected RekeyTo value %s, got %s", stealthAuthAccount.Address.String(), rekeyViolation.Value)
	case !strings.Contains(rekeyViolation.Message, "LOSE CONTROL"):
		t.Fatalf("expected RekeyTo warning to mention loss of control, got %q", rekeyViolation.Message)
	}

	mustApproveIPCSignRequest(t, ipcClient, signReq.ID)
	wg.Wait()

	if status != http.StatusOK {
		t.Fatalf("expected sign request to succeed after approval, got %d: %s", status, string(body))
	}

	var signResp signerapi.GroupSignResponse
	if err := json.Unmarshal(body, &signResp); err != nil {
		t.Fatalf("failed to decode sign response: %v", err)
	}
	if signResp.Error != "" {
		t.Fatalf("unexpected sign error: %s", signResp.Error)
	}
	if len(signResp.Signed) != 1 {
		t.Fatalf("expected one signed transaction, got %d", len(signResp.Signed))
	}

	stxn := decodeSignedTxnHex(t, signResp.Signed[0])
	txid, err := testnet.SubmitTransaction(stxn)
	if err != nil {
		t.Fatalf("failed to submit signed hidden rekey transaction: %v", err)
	}
	if _, err := testnet.WaitForConfirmation(txid, 10); err != nil {
		t.Fatalf("hidden rekey transaction failed to confirm: %v", err)
	}
	rekeyConfirmed = true

	accountInfo, err := testnet.Client.AccountInformation(sourceAddr).Do(context.Background())
	if err != nil {
		t.Fatalf("failed to read source account info: %v", err)
	}
	if accountInfo.AuthAddr != stealthAuthAccount.Address.String() {
		t.Fatalf(
			"expected account %s to be rekeyed to %s, got %s",
			sourceAddr,
			stealthAuthAccount.Address.String(),
			accountInfo.AuthAddr,
		)
	}
}

func TestHiddenCloseRemainderPaymentEmitsCriticalAlertAndClosesAccount(t *testing.T) {
	if os.Getenv("TEST_FUNDING_MNEMONIC") == "" {
		t.Skip("TEST_FUNDING_MNEMONIC not set, skipping funding-backed hidden close test")
	}

	userAutoApprove := false
	harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{UserAutoApprove: &userAutoApprove})

	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("failed to connect to testnet: %v", err)
	}
	funder, err := harness.NewFundTestAccount(testnet.Client)
	if err != nil {
		t.Fatalf("failed to load funding account: %v", err)
	}

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	t.Cleanup(apadmin.Cleanup)

	sourceAccount := crypto.GenerateAccount()
	sourceMnemonic, err := mnemonic.FromPrivateKey(sourceAccount.PrivateKey)
	if err != nil {
		t.Fatalf("failed to encode source account mnemonic: %v", err)
	}
	sourceAddr, err := apadmin.ImportKey(sourceMnemonic)
	if err != nil {
		t.Fatalf("failed to import source account into signer: %v", err)
	}

	token := readSignerToken(t, signerd)
	if !waitForKey(t, signerd.GetURL(), token, sourceAddr, 10*time.Second) {
		t.Fatalf("signer did not reload imported source key %s", sourceAddr)
	}

	ipcClient := mustConnectIPCClient(t, signerd.GetWorkDir())
	defer ipcClient.Close()

	if err := funder.FundMicroAlgosAndWait(sourceAddr, 250_000); err != nil {
		t.Fatalf("failed to fund source account: %v", err)
	}

	sp, err := testnet.GetSuggestedParams()
	if err != nil {
		t.Fatalf("failed to get suggested params: %v", err)
	}

	txn, err := transaction.MakePaymentTxn(sourceAddr, integrationBurnAddress, 1_000, []byte("hidden-close-test"), "", sp)
	if err != nil {
		t.Fatalf("failed to build payment txn: %v", err)
	}
	closeAddr, err := types.DecodeAddress(funder.GetAddress())
	if err != nil {
		t.Fatalf("failed to decode close address: %v", err)
	}
	txn.CloseRemainderTo = closeAddr
	signReqBody := signerapi.GroupSignRequest{
		Requests: []signerapi.SignRequest{{
			AuthAddress: sourceAddr,
			TxnBytesHex: hex.EncodeToString(append([]byte("TX"), msgpack.Encode(txn)...)),
		}},
	}

	var (
		status int
		body   []byte
		wg     sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		status, body = postSignRequest(t, signerd.GetURL(), "aplane "+token, signReqBody)
	}()

	signReq := mustReadIPCSignRequest(t, ipcClient, 10*time.Second)
	if signReq.Address != sourceAddr {
		t.Fatalf("expected approval request for %s, got %s", sourceAddr, signReq.Address)
	}
	if signReq.TxnSender != sourceAddr {
		t.Fatalf("expected sender %s, got %s", sourceAddr, signReq.TxnSender)
	}
	if !strings.Contains(signReq.Description, "Payment: 0.001000 ALGO") {
		t.Fatalf("expected payment summary in approval description, got:\n%s", signReq.Description)
	}
	if !strings.Contains(signReq.Description, "Close remainder to: "+funder.GetAddress()) {
		t.Fatalf("expected close remainder warning in approval description, got:\n%s", signReq.Description)
	}

	var closeViolation *protocol.PolicyViolation
	for i := range signReq.Violations {
		if signReq.Violations[i].Field == "CloseRemainderTo" {
			closeViolation = &signReq.Violations[i]
			break
		}
	}
	switch {
	case closeViolation == nil:
		t.Fatalf("expected CloseRemainderTo violation, got %#v", signReq.Violations)
	case closeViolation.Severity != "critical":
		t.Fatalf("expected critical CloseRemainderTo violation, got %q", closeViolation.Severity)
	case closeViolation.Value != funder.GetAddress():
		t.Fatalf("expected CloseRemainderTo value %s, got %s", funder.GetAddress(), closeViolation.Value)
	case !strings.Contains(closeViolation.Message, "ALL remaining ALGO") && !strings.Contains(closeViolation.Message, "close your account"):
		t.Fatalf("expected CloseRemainderTo warning to mention account closure, got %q", closeViolation.Message)
	}

	mustApproveIPCSignRequest(t, ipcClient, signReq.ID)
	wg.Wait()

	if status != http.StatusOK {
		t.Fatalf("expected sign request to succeed after approval, got %d: %s", status, string(body))
	}

	var signResp signerapi.GroupSignResponse
	if err := json.Unmarshal(body, &signResp); err != nil {
		t.Fatalf("failed to decode sign response: %v", err)
	}
	if signResp.Error != "" {
		t.Fatalf("unexpected sign error: %s", signResp.Error)
	}
	if len(signResp.Signed) != 1 {
		t.Fatalf("expected one signed transaction, got %d", len(signResp.Signed))
	}

	stxn := decodeSignedTxnHex(t, signResp.Signed[0])
	txid, err := testnet.SubmitTransaction(stxn)
	if err != nil {
		t.Fatalf("failed to submit signed hidden close transaction: %v", err)
	}
	if _, err := testnet.WaitForConfirmation(txid, 10); err != nil {
		t.Fatalf("hidden close transaction failed to confirm: %v", err)
	}

	accountInfo, err := testnet.Client.AccountInformation(sourceAddr).Do(context.Background())
	if err != nil {
		t.Fatalf("failed to read source account info: %v", err)
	}
	if accountInfo.Amount != 0 {
		t.Fatalf("expected account %s to be emptied by close remainder, got balance %d", sourceAddr, accountInfo.Amount)
	}
}

func TestAssetCloseTransferEmitsWarningAndSignsAfterApproval(t *testing.T) {
	userAutoApprove := false
	harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{UserAutoApprove: &userAutoApprove})

	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("failed to connect to testnet: %v", err)
	}

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	t.Cleanup(apadmin.Cleanup)

	address, err := apadmin.GenerateKeyWithType("ed25519")
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	if err := apadmin.UnlockSigner(); err != nil {
		t.Fatalf("failed to unlock signer: %v", err)
	}

	token := readSignerToken(t, signerd)
	if !waitForKey(t, signerd.GetURL(), token, address, 10*time.Second) {
		t.Fatalf("signer did not reload generated key %s", address)
	}

	ipcClient := mustConnectIPCClient(t, signerd.GetWorkDir())
	defer ipcClient.Close()
	mustUpdateIPCPolicySetting(t, ipcClient, "reject_asset_close", "false")

	sp, err := testnet.GetSuggestedParams()
	if err != nil {
		t.Fatalf("failed to get suggested params: %v", err)
	}
	closeTarget := crypto.GenerateAccount().Address.String()

	reqBody := signerapi.GroupSignRequest{
		Requests: []signerapi.SignRequest{{
			AuthAddress: address,
			TxnBytesHex: mustUnsignedAssetTransferTxnHexWithClose(
				t,
				sp,
				address,
				integrationBurnAddress,
				7,
				12345,
				closeTarget,
				"asset-close-test",
			),
		}},
	}

	var (
		status int
		body   []byte
		wg     sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		status, body = postSignRequest(t, signerd.GetURL(), "aplane "+token, reqBody)
	}()

	signReq := mustReadIPCSignRequest(t, ipcClient, 10*time.Second)
	if signReq.Address != address {
		t.Fatalf("expected approval request for %s, got %s", address, signReq.Address)
	}
	if !strings.Contains(signReq.Description, "ASA Transfer: 7 units of asset #12345") {
		t.Fatalf("expected ASA transfer summary in approval description, got:\n%s", signReq.Description)
	}
	if !strings.Contains(signReq.Description, "Close remainder to: "+closeTarget) {
		t.Fatalf("expected asset close warning in approval description, got:\n%s", signReq.Description)
	}

	var closeViolation *protocol.PolicyViolation
	for i := range signReq.Violations {
		if signReq.Violations[i].Field == "AssetCloseTo" {
			closeViolation = &signReq.Violations[i]
			break
		}
	}
	switch {
	case closeViolation == nil:
		t.Fatalf("expected AssetCloseTo violation, got %#v", signReq.Violations)
	case closeViolation.Severity != "warning":
		t.Fatalf("expected warning AssetCloseTo violation, got %q", closeViolation.Severity)
	case closeViolation.Value != closeTarget:
		t.Fatalf("expected AssetCloseTo value %s, got %s", closeTarget, closeViolation.Value)
	case !strings.Contains(closeViolation.Message, "ENTIRE balance of this asset"):
		t.Fatalf("expected AssetCloseTo warning to mention entire asset balance, got %q", closeViolation.Message)
	}

	mustApproveIPCSignRequest(t, ipcClient, signReq.ID)
	wg.Wait()

	if status != http.StatusOK {
		t.Fatalf("expected asset close sign request to succeed after approval, got %d: %s", status, string(body))
	}

	var signResp signerapi.GroupSignResponse
	if err := json.Unmarshal(body, &signResp); err != nil {
		t.Fatalf("failed to decode asset close sign response: %v", err)
	}
	if signResp.Error != "" {
		t.Fatalf("unexpected asset close sign error: %s", signResp.Error)
	}
	if len(signResp.Signed) != 1 {
		t.Fatalf("expected one signed asset close transaction, got %d", len(signResp.Signed))
	}
}

func TestClawbackTransferEmitsWarningAndSignsAfterApproval(t *testing.T) {
	userAutoApprove := false
	harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{UserAutoApprove: &userAutoApprove})

	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("failed to connect to testnet: %v", err)
	}

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	t.Cleanup(apadmin.Cleanup)

	address, err := apadmin.GenerateKeyWithType("ed25519")
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	if err := apadmin.UnlockSigner(); err != nil {
		t.Fatalf("failed to unlock signer: %v", err)
	}

	token := readSignerToken(t, signerd)
	if !waitForKey(t, signerd.GetURL(), token, address, 10*time.Second) {
		t.Fatalf("signer did not reload generated key %s", address)
	}

	ipcClient := mustConnectIPCClient(t, signerd.GetWorkDir())
	defer ipcClient.Close()

	sp, err := testnet.GetSuggestedParams()
	if err != nil {
		t.Fatalf("failed to get suggested params: %v", err)
	}
	clawbackTarget := crypto.GenerateAccount().Address.String()

	reqBody := signerapi.GroupSignRequest{
		Requests: []signerapi.SignRequest{{
			AuthAddress: address,
			TxnBytesHex: mustUnsignedAssetTransferTxnHexWithClawback(
				t,
				sp,
				address,
				integrationBurnAddress,
				9,
				54321,
				clawbackTarget,
				"clawback-test",
			),
		}},
	}

	var (
		status int
		body   []byte
		wg     sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		status, body = postSignRequest(t, signerd.GetURL(), "aplane "+token, reqBody)
	}()

	signReq := mustReadIPCSignRequest(t, ipcClient, 10*time.Second)
	if signReq.Address != address {
		t.Fatalf("expected approval request for %s, got %s", address, signReq.Address)
	}
	if !strings.Contains(signReq.Description, "ASA Transfer: 9 units of asset #54321") {
		t.Fatalf("expected ASA transfer summary in approval description, got:\n%s", signReq.Description)
	}
	if !strings.Contains(signReq.Description, "CLAWBACK FROM: "+clawbackTarget) {
		t.Fatalf("expected clawback warning in approval description, got:\n%s", signReq.Description)
	}

	var clawbackViolation *protocol.PolicyViolation
	for i := range signReq.Violations {
		if signReq.Violations[i].Field == "AssetSender" {
			clawbackViolation = &signReq.Violations[i]
			break
		}
	}
	switch {
	case clawbackViolation == nil:
		t.Fatalf("expected AssetSender violation, got %#v", signReq.Violations)
	case clawbackViolation.Severity != "warning":
		t.Fatalf("expected warning AssetSender violation, got %q", clawbackViolation.Severity)
	case clawbackViolation.Value != clawbackTarget:
		t.Fatalf("expected AssetSender value %s, got %s", clawbackTarget, clawbackViolation.Value)
	case !strings.Contains(clawbackViolation.Message, "CLAWBACK") || !strings.Contains(clawbackViolation.Message, "clawback authority"):
		t.Fatalf("expected clawback warning message, got %q", clawbackViolation.Message)
	}

	mustApproveIPCSignRequest(t, ipcClient, signReq.ID)
	wg.Wait()

	if status != http.StatusOK {
		t.Fatalf("expected clawback sign request to succeed after approval, got %d: %s", status, string(body))
	}

	var signResp signerapi.GroupSignResponse
	if err := json.Unmarshal(body, &signResp); err != nil {
		t.Fatalf("failed to decode clawback sign response: %v", err)
	}
	if signResp.Error != "" {
		t.Fatalf("unexpected clawback sign error: %s", signResp.Error)
	}
	if len(signResp.Signed) != 1 {
		t.Fatalf("expected one signed clawback transaction, got %d", len(signResp.Signed))
	}
}

func TestPolicyHardRejectAssetCloseSkipsApprovalAndReturnsForbidden(t *testing.T) {
	userAutoApprove := false
	harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{UserAutoApprove: &userAutoApprove})

	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("failed to connect to testnet: %v", err)
	}

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	t.Cleanup(apadmin.Cleanup)

	address, err := apadmin.GenerateKeyWithType("ed25519")
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	if err := apadmin.UnlockSigner(); err != nil {
		t.Fatalf("failed to unlock signer: %v", err)
	}

	token := readSignerToken(t, signerd)
	if !waitForKey(t, signerd.GetURL(), token, address, 10*time.Second) {
		t.Fatalf("signer did not reload generated key %s", address)
	}

	policyClient := mustConnectIPCClient(t, signerd.GetWorkDir())
	defer policyClient.Close()
	mustUpdateIPCPolicySetting(t, policyClient, "reject_asset_close", "true")

	approvalClient := mustConnectIPCClient(t, signerd.GetWorkDir())
	defer approvalClient.Close()

	sp, err := testnet.GetSuggestedParams()
	if err != nil {
		t.Fatalf("failed to get suggested params: %v", err)
	}
	closeTarget := crypto.GenerateAccount().Address.String()

	req := signerapi.GroupSignRequest{
		Requests: []signerapi.SignRequest{{
			AuthAddress: address,
			TxnBytesHex: mustUnsignedAssetTransferTxnHexWithClose(
				t,
				sp,
				address,
				integrationBurnAddress,
				1,
				12345,
				closeTarget,
				"policy-hard-reject-asset-close",
			),
		}},
	}

	status, body := postSignRequest(t, signerd.GetURL(), "aplane "+token, req)
	if status != http.StatusForbidden {
		t.Fatalf("expected 403 for asset close policy hard reject, got %d: %s", status, string(body))
	}

	var resp signerapi.GroupSignResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("failed to decode asset close reject response: %v", err)
	}
	if !strings.Contains(resp.Error, "policy engine rejected request") || !strings.Contains(resp.Error, "reject_asset_close") {
		t.Fatalf("expected policy reject response to mention reject_asset_close, got %q", resp.Error)
	}
	if len(resp.Signed) != 0 {
		t.Fatalf("expected no signed transactions on asset close policy reject, got %d", len(resp.Signed))
	}

	mustNotReceiveIPCSignRequest(t, approvalClient, 750*time.Millisecond)
}

func TestPolicyHardRejectClawbackSkipsApprovalAndReturnsForbidden(t *testing.T) {
	userAutoApprove := false
	harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{UserAutoApprove: &userAutoApprove})

	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("failed to connect to testnet: %v", err)
	}

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	t.Cleanup(apadmin.Cleanup)

	address, err := apadmin.GenerateKeyWithType("ed25519")
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	if err := apadmin.UnlockSigner(); err != nil {
		t.Fatalf("failed to unlock signer: %v", err)
	}

	token := readSignerToken(t, signerd)
	if !waitForKey(t, signerd.GetURL(), token, address, 10*time.Second) {
		t.Fatalf("signer did not reload generated key %s", address)
	}

	policyClient := mustConnectIPCClient(t, signerd.GetWorkDir())
	defer policyClient.Close()
	mustUpdateIPCPolicySetting(t, policyClient, "reject_clawback", "true")

	approvalClient := mustConnectIPCClient(t, signerd.GetWorkDir())
	defer approvalClient.Close()

	sp, err := testnet.GetSuggestedParams()
	if err != nil {
		t.Fatalf("failed to get suggested params: %v", err)
	}
	clawbackTarget := crypto.GenerateAccount().Address.String()

	req := signerapi.GroupSignRequest{
		Requests: []signerapi.SignRequest{{
			AuthAddress: address,
			TxnBytesHex: mustUnsignedAssetTransferTxnHexWithClawback(
				t,
				sp,
				address,
				integrationBurnAddress,
				1,
				54321,
				clawbackTarget,
				"policy-hard-reject-clawback",
			),
		}},
	}

	status, body := postSignRequest(t, signerd.GetURL(), "aplane "+token, req)
	if status != http.StatusForbidden {
		t.Fatalf("expected 403 for clawback policy hard reject, got %d: %s", status, string(body))
	}

	var resp signerapi.GroupSignResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("failed to decode clawback reject response: %v", err)
	}
	if !strings.Contains(resp.Error, "policy engine rejected request") || !strings.Contains(resp.Error, "reject_clawback") {
		t.Fatalf("expected policy reject response to mention reject_clawback, got %q", resp.Error)
	}
	if len(resp.Signed) != 0 {
		t.Fatalf("expected no signed transactions on clawback policy reject, got %d", len(resp.Signed))
	}

	mustNotReceiveIPCSignRequest(t, approvalClient, 750*time.Millisecond)
}

func TestRekeyedAccountSignsViaAuthAddress(t *testing.T) {
	if os.Getenv("TEST_FUNDING_MNEMONIC") == "" {
		t.Skip("TEST_FUNDING_MNEMONIC not set, skipping funding-backed rekey integration test")
	}

	harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{})

	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("failed to connect to testnet: %v", err)
	}
	funder, err := harness.NewFundTestAccount(testnet.Client)
	if err != nil {
		t.Fatalf("failed to load funding account: %v", err)
	}

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	t.Cleanup(apadmin.Cleanup)

	fundingAddr, err := apadmin.ImportKey(os.Getenv("TEST_FUNDING_MNEMONIC"))
	if err != nil {
		t.Fatalf("failed to import funding account into signer: %v", err)
	}
	rekeyedAddr, err := apadmin.GenerateKeyWithType("ed25519")
	if err != nil {
		t.Fatalf("failed to generate rekeyed account: %v", err)
	}

	apshell := harness.NewApshellHarness(t, signerd.GetURL())
	if err := apshell.CopyTokenFrom(signerd.GetWorkDir()); err != nil {
		t.Fatalf("failed to copy signer token to apshell: %v", err)
	}

	if err := apadmin.StartUnlockBackground(); err != nil {
		t.Fatalf("failed to keep signer unlocked: %v", err)
	}
	t.Cleanup(apadmin.StopUnlockBackground)

	if err := funder.FundMicroAlgosAndWait(rekeyedAddr, 250_000); err != nil {
		t.Fatalf("failed to fund rekeyed account: %v", err)
	}

	t.Cleanup(func() {
		closeAccountToFunding(t, apshell, testnet, rekeyedAddr, fundingAddr)
	})

	rekeyOutput, err := apshell.RunWithInput(fmt.Sprintf("rekey %s to %s\nquit\n", rekeyedAddr, fundingAddr))
	if err != nil {
		t.Fatalf("failed to rekey account: %v\noutput:\n%s", err, rekeyOutput)
	}

	accountInfo, err := testnet.Client.AccountInformation(rekeyedAddr).Do(context.Background())
	if err != nil {
		t.Fatalf("failed to read rekeyed account info: %v", err)
	}
	if accountInfo.AuthAddr != fundingAddr {
		t.Fatalf("expected account %s to be rekeyed to %s, got %s", rekeyedAddr, fundingAddr, accountInfo.AuthAddr)
	}

	txid, err := apshell.SendTransaction(rekeyedAddr, integrationBurnAddress, 0.01)
	if err != nil {
		t.Fatalf("failed to send from rekeyed account: %v", err)
	}
	if _, err := testnet.WaitForConfirmation(txid, 10); err != nil {
		t.Fatalf("rekeyed payment failed to confirm: %v", err)
	}
}

func TestRekeyedAccountRejectsMissingAuthAddress(t *testing.T) {
	if os.Getenv("TEST_FUNDING_MNEMONIC") == "" {
		t.Skip("TEST_FUNDING_MNEMONIC not set, skipping funding-backed rekey failure test")
	}

	harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{})

	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("failed to connect to testnet: %v", err)
	}
	funder, err := harness.NewFundTestAccount(testnet.Client)
	if err != nil {
		t.Fatalf("failed to load funding account: %v", err)
	}

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	t.Cleanup(apadmin.Cleanup)

	authAccount := crypto.GenerateAccount()
	authMnemonic, err := mnemonic.FromPrivateKey(authAccount.PrivateKey)
	if err != nil {
		t.Fatalf("failed to encode auth account mnemonic: %v", err)
	}
	authAddr, err := apadmin.ImportKey(authMnemonic)
	if err != nil {
		t.Fatalf("failed to import auth account into signer: %v", err)
	}
	rekeyedAddr, err := apadmin.GenerateKeyWithType("ed25519")
	if err != nil {
		t.Fatalf("failed to generate rekeyed account: %v", err)
	}

	apshell := harness.NewApshellHarness(t, signerd.GetURL())
	if err := apshell.CopyTokenFrom(signerd.GetWorkDir()); err != nil {
		t.Fatalf("failed to copy signer token to apshell: %v", err)
	}

	if err := apadmin.StartUnlockBackground(); err != nil {
		t.Fatalf("failed to keep signer unlocked: %v", err)
	}
	t.Cleanup(apadmin.StopUnlockBackground)

	if err := funder.FundMicroAlgosAndWait(rekeyedAddr, 250_000); err != nil {
		t.Fatalf("failed to fund rekeyed account: %v", err)
	}

	t.Cleanup(func() {
		apadmin.StopUnlockBackground()
		if _, err := apadmin.ImportKey(authMnemonic); err != nil {
			t.Fatalf("failed to restore auth account for cleanup: %v", err)
		}
		token := readSignerToken(t, signerd)
		if !waitForKey(t, signerd.GetURL(), token, authAddr, 10*time.Second) {
			t.Fatalf("signer did not reload restored auth key %s", authAddr)
		}
		unrekeyOutput, err := apshell.RunWithInput(fmt.Sprintf("unrekey %s\nquit\n", rekeyedAddr))
		if err != nil {
			t.Fatalf("failed to unrekey account during cleanup: %v\noutput:\n%s", err, unrekeyOutput)
		}
		closeAccountToFunding(t, apshell, testnet, rekeyedAddr, funder.GetAddress())
		if err := apadmin.DeleteKey(authAddr); err != nil {
			t.Fatalf("failed to delete restored auth account during cleanup: %v", err)
		}
	})

	rekeyOutput, err := apshell.RunWithInput(fmt.Sprintf("rekey %s to %s\nquit\n", rekeyedAddr, authAddr))
	if err != nil {
		t.Fatalf("failed to rekey account: %v\noutput:\n%s", err, rekeyOutput)
	}

	accountInfo, err := testnet.Client.AccountInformation(rekeyedAddr).Do(context.Background())
	if err != nil {
		t.Fatalf("failed to read rekeyed account info: %v", err)
	}
	if accountInfo.AuthAddr != authAddr {
		t.Fatalf("expected account %s to be rekeyed to %s, got %s", rekeyedAddr, authAddr, accountInfo.AuthAddr)
	}

	apadmin.StopUnlockBackground()
	if err := apadmin.DeleteKey(authAddr); err != nil {
		t.Fatalf("failed to delete auth key from signer: %v", err)
	}
	token := readSignerToken(t, signerd)
	if !waitForKeyMissing(t, signerd.GetURL(), token, authAddr, 10*time.Second) {
		t.Fatalf("signer still reports deleted auth key %s", authAddr)
	}

	sendOutput, err := apshell.RunWithInput(
		fmt.Sprintf("send 0.010000 algo from %s to %s\nquit\n", rekeyedAddr, integrationBurnAddress),
	)
	if err != nil {
		t.Fatalf("apshell send command failed unexpectedly: %v\noutput:\n%s", err, sendOutput)
	}
	if !strings.Contains(sendOutput, "not signable") {
		t.Fatalf("expected missing auth signer error, got output:\n%s", sendOutput)
	}
	if strings.Contains(strings.ToLower(sendOutput), "transaction submitted:") {
		t.Fatalf("expected failed send not to submit a transaction, output:\n%s", sendOutput)
	}
}

func TestRekeyRejectsTargetThatIsItselfRekeyed(t *testing.T) {
	if os.Getenv("TEST_FUNDING_MNEMONIC") == "" {
		t.Skip("TEST_FUNDING_MNEMONIC not set, skipping funding-backed rekey chain rejection test")
	}

	harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{})

	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("failed to connect to testnet: %v", err)
	}
	funder, err := harness.NewFundTestAccount(testnet.Client)
	if err != nil {
		t.Fatalf("failed to load funding account: %v", err)
	}

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	t.Cleanup(apadmin.Cleanup)

	accountA := crypto.GenerateAccount()
	accountB := crypto.GenerateAccount()
	accountC := crypto.GenerateAccount()

	mnemonicA, err := mnemonic.FromPrivateKey(accountA.PrivateKey)
	if err != nil {
		t.Fatalf("failed to encode account A mnemonic: %v", err)
	}
	mnemonicB, err := mnemonic.FromPrivateKey(accountB.PrivateKey)
	if err != nil {
		t.Fatalf("failed to encode account B mnemonic: %v", err)
	}
	mnemonicC, err := mnemonic.FromPrivateKey(accountC.PrivateKey)
	if err != nil {
		t.Fatalf("failed to encode account C mnemonic: %v", err)
	}

	addrA, err := apadmin.ImportKey(mnemonicA)
	if err != nil {
		t.Fatalf("failed to import account A: %v", err)
	}
	addrB, err := apadmin.ImportKey(mnemonicB)
	if err != nil {
		t.Fatalf("failed to import account B: %v", err)
	}
	addrC, err := apadmin.ImportKey(mnemonicC)
	if err != nil {
		t.Fatalf("failed to import account C: %v", err)
	}

	token := readSignerToken(t, signerd)
	if !waitForKey(t, signerd.GetURL(), token, addrA, 10*time.Second) {
		t.Fatalf("signer did not reload account A %s", addrA)
	}
	if !waitForKey(t, signerd.GetURL(), token, addrB, 10*time.Second) {
		t.Fatalf("signer did not reload account B %s", addrB)
	}
	if !waitForKey(t, signerd.GetURL(), token, addrC, 10*time.Second) {
		t.Fatalf("signer did not reload account C %s", addrC)
	}

	apshell := harness.NewApshellHarness(t, signerd.GetURL())
	if err := apshell.CopyTokenFrom(signerd.GetWorkDir()); err != nil {
		t.Fatalf("failed to copy signer token to apshell: %v", err)
	}

	if err := apadmin.StartUnlockBackground(); err != nil {
		t.Fatalf("failed to keep signer unlocked: %v", err)
	}
	t.Cleanup(apadmin.StopUnlockBackground)

	if err := funder.FundMicroAlgosAndWait(addrA, 250_000); err != nil {
		t.Fatalf("failed to fund account A: %v", err)
	}
	if err := funder.FundMicroAlgosAndWait(addrB, 200_000); err != nil {
		t.Fatalf("failed to fund account B: %v", err)
	}

	t.Cleanup(func() {
		closeAccountWithSigningKey(t, testnet, addrA, funder.GetAddress(), accountA.PrivateKey)
		closeAccountWithSigningKey(t, testnet, addrB, funder.GetAddress(), accountC.PrivateKey)
	})

	rekeyBOutput, err := apshell.RunWithInput(fmt.Sprintf("rekey %s to %s\nquit\n", addrB, addrC))
	if err != nil {
		t.Fatalf("failed to rekey account B to C: %v\noutput:\n%s", err, rekeyBOutput)
	}
	rekeyAOutput, err := apshell.RunWithInput(fmt.Sprintf("rekey %s to %s\nquit\n", addrA, addrB))
	if err != nil {
		t.Fatalf("apshell rekey command failed unexpectedly: %v\noutput:\n%s", err, rekeyAOutput)
	}
	if !strings.Contains(rekeyAOutput, "policy rejection: cannot rekey to "+addrB+" because it is itself rekeyed to "+addrC) {
		t.Fatalf("expected chained rekey rejection, got output:\n%s", rekeyAOutput)
	}
	if strings.Contains(strings.ToLower(rekeyAOutput), "rekey transaction submitted:") {
		t.Fatalf("expected chained rekey to be rejected before submission, output:\n%s", rekeyAOutput)
	}

	accountAInfo, err := testnet.Client.AccountInformation(addrA).Do(context.Background())
	if err != nil {
		t.Fatalf("failed to read account A info: %v", err)
	}
	if accountAInfo.AuthAddr != "" {
		t.Fatalf("expected account A to remain unrekeyed, got auth address %s", accountAInfo.AuthAddr)
	}
	accountBInfo, err := testnet.Client.AccountInformation(addrB).Do(context.Background())
	if err != nil {
		t.Fatalf("failed to read account B info: %v", err)
	}
	if accountBInfo.AuthAddr != addrC {
		t.Fatalf("expected account B auth address %s, got %s", addrC, accountBInfo.AuthAddr)
	}
}

// --- Priority 1 Tests ---

func TestFalconPassphraseSigning(t *testing.T) {
	if os.Getenv("TEST_FUNDING_MNEMONIC") == "" {
		t.Skip("TEST_FUNDING_MNEMONIC not set, skipping funding-backed Falcon passphrase test")
	}

	lockOnDisconnect := true
	harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{LockOnDisconnect: &lockOnDisconnect})

	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("failed to connect to testnet: %v", err)
	}
	funder, err := harness.NewFundTestAccount(testnet.Client)
	if err != nil {
		t.Fatalf("failed to load funding account: %v", err)
	}

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	t.Cleanup(apadmin.Cleanup)

	falconAddr, err := apadmin.GenerateKey("falcon passphrase test")
	if err != nil {
		t.Fatalf("failed to generate Falcon key: %v", err)
	}

	token := readSignerToken(t, signerd)
	if !waitForSignerLocked(t, signerd.GetURL(), token, 10*time.Second) {
		t.Fatal("signer did not lock after apadmin key generation session disconnected")
	}

	sp, err := testnet.GetSuggestedParams()
	if err != nil {
		t.Fatalf("failed to get suggested params: %v", err)
	}

	signReq := signerapi.GroupSignRequest{
		Requests: []signerapi.SignRequest{{
			AuthAddress: falconAddr,
			TxnBytesHex: mustUnsignedPaymentTxnHex(t, sp, falconAddr, integrationBurnAddress, 0, "passphrase-locked"),
		}},
	}

	// Step 1: signing must fail while signer is locked
	status, body := postSignRequest(t, signerd.GetURL(), "aplane "+token, signReq)
	if status != http.StatusForbidden {
		t.Fatalf("expected 403 when locked, got %d: %s", status, string(body))
	}
	if !strings.Contains(string(body), "signer is locked") {
		t.Fatalf("expected locked error, got %s", string(body))
	}
	t.Log("Step 1: correctly rejected while locked")

	// Step 2: unlock and sign successfully
	if err := apadmin.StartUnlockBackground(); err != nil {
		t.Fatalf("failed to start background unlock: %v", err)
	}
	t.Cleanup(apadmin.StopUnlockBackground)

	if !waitForKey(t, signerd.GetURL(), token, falconAddr, 10*time.Second) {
		t.Fatalf("signer did not reload Falcon key %s after unlock", falconAddr)
	}

	apshell := harness.NewApshellHarness(t, signerd.GetURL())
	if err := apshell.CopyTokenFrom(signerd.GetWorkDir()); err != nil {
		t.Fatalf("failed to copy token: %v", err)
	}

	if err := funder.FundMicroAlgosAndWait(falconAddr, 300_000); err != nil {
		t.Fatalf("failed to fund Falcon account: %v", err)
	}
	t.Cleanup(func() {
		closeAccountToFunding(t, apshell, testnet, falconAddr, funder.GetAddress())
	})

	txid, err := apshell.SendTransaction(falconAddr, integrationBurnAddress, 0.01)
	if err != nil {
		t.Fatalf("failed to send Falcon transaction after unlock: %v", err)
	}
	if _, err := testnet.WaitForConfirmation(txid, 10); err != nil {
		t.Fatalf("Falcon transaction failed to confirm: %v", err)
	}
	t.Log("Step 2: Falcon transaction confirmed after passphrase unlock")
}

func TestSignerRejectsUnknownSigningAddress(t *testing.T) {
	harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{})

	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("failed to connect to testnet: %v", err)
	}

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	t.Cleanup(apadmin.Cleanup)

	// Generate one key so the signer has something — but we'll sign for a different address
	_, err = apadmin.GenerateKeyWithType("ed25519")
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	if err := apadmin.UnlockSigner(); err != nil {
		t.Fatalf("failed to unlock signer: %v", err)
	}

	sp, err := testnet.GetSuggestedParams()
	if err != nil {
		t.Fatalf("failed to get suggested params: %v", err)
	}

	// Use a well-known address that the signer does not hold
	unknownAddr := integrationBurnAddress
	token := readSignerToken(t, signerd)
	signReq := signerapi.GroupSignRequest{
		Requests: []signerapi.SignRequest{{
			AuthAddress: unknownAddr,
			TxnBytesHex: mustUnsignedPaymentTxnHex(t, sp, unknownAddr, unknownAddr, 0, "unknown-addr-test"),
		}},
	}

	status, body := postSignRequest(t, signerd.GetURL(), "aplane "+token, signReq)
	if status == http.StatusOK {
		t.Fatalf("expected failure for unknown signing address, got 200")
	}
	bodyStr := string(body)
	// The error should reference the missing key, not a network or auth issue
	if strings.Contains(bodyStr, "Authorization") || strings.Contains(bodyStr, "signer is locked") {
		t.Fatalf("error should be about missing key, not auth/lock: %s", bodyStr)
	}
	t.Logf("correctly rejected unknown address with status %d: %s", status, bodyStr)
}

func TestSignerRestartPreservesUsableKeys(t *testing.T) {
	if os.Getenv("TEST_FUNDING_MNEMONIC") == "" {
		t.Skip("TEST_FUNDING_MNEMONIC not set, skipping restart+sign integration test")
	}

	harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{})

	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("failed to connect to testnet: %v", err)
	}
	funder, err := harness.NewFundTestAccount(testnet.Client)
	if err != nil {
		t.Fatalf("failed to load funding account: %v", err)
	}

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	t.Cleanup(apadmin.Cleanup)

	addr, err := apadmin.GenerateKeyWithType("ed25519")
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	apshell := harness.NewApshellHarness(t, signerd.GetURL())
	if err := apshell.CopyTokenFrom(signerd.GetWorkDir()); err != nil {
		t.Fatalf("failed to copy token: %v", err)
	}

	if err := apadmin.StartUnlockBackground(); err != nil {
		t.Fatalf("failed to unlock signer: %v", err)
	}

	if err := funder.FundMicroAlgosAndWait(addr, 250_000); err != nil {
		t.Fatalf("failed to fund test account: %v", err)
	}
	t.Cleanup(func() {
		closeAccountToFunding(t, apshell, testnet, addr, funder.GetAddress())
	})

	// Step 1: sign and confirm before restart
	txid1, err := apshell.SendTransaction(addr, integrationBurnAddress, 0.01)
	if err != nil {
		t.Fatalf("pre-restart transaction failed: %v", err)
	}
	if _, err := testnet.WaitForConfirmation(txid1, 10); err != nil {
		t.Fatalf("pre-restart transaction failed to confirm: %v", err)
	}
	t.Logf("Step 1: pre-restart transaction confirmed: %s", txid1)

	// Stop unlock and signer
	apadmin.StopUnlockBackground()
	if err := signerd.Stop(); err != nil {
		t.Fatalf("failed to stop signer: %v", err)
	}

	// Step 2: restart and sign again
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to restart signer: %v", err)
	}

	if err := apadmin.StartUnlockBackground(); err != nil {
		t.Fatalf("failed to re-unlock signer after restart: %v", err)
	}
	t.Cleanup(apadmin.StopUnlockBackground)

	token := readSignerToken(t, signerd)
	if !waitForKey(t, signerd.GetURL(), token, addr, 10*time.Second) {
		t.Fatalf("key %s not available after restart", addr)
	}

	txid2, err := apshell.SendTransaction(addr, integrationBurnAddress, 0.01)
	if err != nil {
		t.Fatalf("post-restart transaction failed: %v", err)
	}
	if _, err := testnet.WaitForConfirmation(txid2, 10); err != nil {
		t.Fatalf("post-restart transaction failed to confirm: %v", err)
	}
	t.Logf("Step 2: post-restart transaction confirmed: %s", txid2)
}

func TestPolicyValidationRejectsInvalidTxn(t *testing.T) {
	harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{})

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	t.Cleanup(apadmin.Cleanup)

	addr, err := apadmin.GenerateKeyWithType("ed25519")
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	if err := apadmin.UnlockSigner(); err != nil {
		t.Fatalf("failed to unlock signer: %v", err)
	}

	token := readSignerToken(t, signerd)
	if !waitForKey(t, signerd.GetURL(), token, addr, 10*time.Second) {
		t.Fatalf("signer did not reload key %s", addr)
	}
	auth := "aplane " + token

	t.Run("empty request body", func(t *testing.T) {
		status, body := postSignRequest(t, signerd.GetURL(), auth, signerapi.GroupSignRequest{})
		if status == http.StatusOK {
			t.Fatalf("expected rejection for empty request, got 200: %s", string(body))
		}
		t.Logf("rejected empty request: %d %s", status, string(body))
	})

	t.Run("malformed transaction bytes", func(t *testing.T) {
		signReq := signerapi.GroupSignRequest{
			Requests: []signerapi.SignRequest{{
				AuthAddress: addr,
				TxnBytesHex: "deadbeef",
			}},
		}
		status, body := postSignRequest(t, signerd.GetURL(), auth, signReq)
		if status == http.StatusOK {
			t.Fatalf("expected rejection for malformed txn, got 200: %s", string(body))
		}
		t.Logf("rejected malformed txn: %d %s", status, string(body))
	})

	t.Run("invalid hex encoding", func(t *testing.T) {
		signReq := signerapi.GroupSignRequest{
			Requests: []signerapi.SignRequest{{
				AuthAddress: addr,
				TxnBytesHex: "not-valid-hex!",
			}},
		}
		status, body := postSignRequest(t, signerd.GetURL(), auth, signReq)
		if status == http.StatusOK {
			t.Fatalf("expected rejection for invalid hex, got 200: %s", string(body))
		}
		t.Logf("rejected invalid hex: %d %s", status, string(body))
	})

	t.Run("sign request with neither txn nor signed_txn", func(t *testing.T) {
		signReq := signerapi.GroupSignRequest{
			Requests: []signerapi.SignRequest{{
				AuthAddress: addr,
			}},
		}
		status, body := postSignRequest(t, signerd.GetURL(), auth, signReq)
		if status == http.StatusOK {
			t.Fatalf("expected rejection for empty sign request, got 200: %s", string(body))
		}
		t.Logf("rejected empty sign entry: %d %s", status, string(body))
	})
}

// --- Priority 2 Tests ---

func TestLSigSigningFlow(t *testing.T) {
	if os.Getenv("TEST_FUNDING_MNEMONIC") == "" {
		t.Skip("TEST_FUNDING_MNEMONIC not set, skipping funding-backed generic LSig test")
	}

	lockOnDisconnect := false
	harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{LockOnDisconnect: &lockOnDisconnect})

	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("failed to connect to testnet: %v", err)
	}
	funder, err := harness.NewFundTestAccount(testnet.Client)
	if err != nil {
		t.Fatalf("failed to load funding account: %v", err)
	}

	signerd := harness.NewSignerHarness(t)
	installHTLCTemplate(t, signerd.GetWorkDir())
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	t.Cleanup(apadmin.Cleanup)
	if err := apadmin.UnlockSigner(); err != nil {
		t.Fatalf("failed to unlock signer: %v", err)
	}

	token := readSignerToken(t, signerd)
	signerClient := signerclient.NewSignerClientWithToken(signerd.GetURL(), token)

	status, err := testnet.Client.Status().Do(context.Background())
	if err != nil {
		t.Fatalf("failed to get algod status: %v", err)
	}

	preimage := bytes.Repeat([]byte("p"), 32)
	preimageHash := sha256.Sum256(preimage)
	params := map[string]string{
		"hash":           hex.EncodeToString(preimageHash[:]),
		"recipient":      funder.GetAddress(),
		"refund_address": funder.GetAddress(),
		"timeout_round":  fmt.Sprintf("%d", status.LastRound+1_000),
	}

	lsigAddr := mustAdminGenerateKey(t, signerClient, signerd, "aplane.htlc.v1", params)

	apshell := harness.NewApshellHarness(t, signerd.GetURL())
	if err := apshell.CopyTokenFrom(signerd.GetWorkDir()); err != nil {
		t.Fatalf("failed to copy token: %v", err)
	}

	if err := funder.FundMicroAlgosAndWait(lsigAddr, 300_000); err != nil {
		t.Fatalf("failed to fund generic LSig account: %v", err)
	}

	claimOutput, err := apshell.RunWithInput(
		fmt.Sprintf("close %s to %s arg:preimage=0x%s\nquit\n", lsigAddr, funder.GetAddress(), hex.EncodeToString(preimage)),
	)
	if err != nil {
		t.Fatalf("failed to submit generic LSig claim path: %v\noutput:\n%s", err, claimOutput)
	}
	claimTxID := mustExtractTxID(t, claimOutput)
	if _, err := testnet.WaitForConfirmation(claimTxID, 10); err != nil {
		t.Fatalf("generic LSig claim transaction failed to confirm: %v", err)
	}
}

func TestLSigRuntimeArgValidation(t *testing.T) {
	lockOnDisconnect := false
	harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{LockOnDisconnect: &lockOnDisconnect})

	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("failed to connect to testnet: %v", err)
	}

	signerd := harness.NewSignerHarness(t)
	installHTLCTemplate(t, signerd.GetWorkDir())
	installFalconHashlockTemplate(t, signerd.GetWorkDir())
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	t.Cleanup(apadmin.Cleanup)
	if err := apadmin.UnlockSigner(); err != nil {
		t.Fatalf("failed to unlock signer: %v", err)
	}

	token := readSignerToken(t, signerd)
	signerClient := signerclient.NewSignerClientWithToken(signerd.GetURL(), token)

	hashlockPreimage := []byte("falcon-hashlock-secret")
	hashlockPreimageHash := sha256.Sum256(hashlockPreimage)
	falconAddr := mustAdminGenerateKey(t, signerClient, signerd, "aplane.falcon1024-hashlock.v1", map[string]string{
		"hash": hex.EncodeToString(hashlockPreimageHash[:]),
	})
	genericPreimage := bytes.Repeat([]byte("g"), 32)
	genericPreimageHash := sha256.Sum256(genericPreimage)
	genericAddr := mustAdminGenerateKey(t, signerClient, signerd, "aplane.htlc.v1", map[string]string{
		"hash":           hex.EncodeToString(genericPreimageHash[:]),
		"recipient":      integrationBurnAddress,
		"refund_address": integrationBurnAddress,
		"timeout_round":  "999999999",
	})

	sp, err := testnet.GetSuggestedParams()
	if err != nil {
		t.Fatalf("failed to get suggested params: %v", err)
	}

	t.Run("missing required arg", func(t *testing.T) {
		req := signerapi.GroupSignRequest{
			Requests: []signerapi.SignRequest{{
				AuthAddress: falconAddr,
				TxnBytesHex: mustUnsignedPaymentTxnHex(t, sp, falconAddr, integrationBurnAddress, 0, "lsig-missing-arg"),
			}},
		}
		status, body := postSignRequest(t, signerd.GetURL(), "aplane "+token, req)
		if status != http.StatusBadRequest {
			t.Fatalf("expected 400 for missing required arg, got %d: %s", status, string(body))
		}
		if !strings.Contains(string(body), "missing required arg: preimage") {
			t.Fatalf("expected missing required preimage error, got %s", string(body))
		}
	})

	t.Run("invalid arg length", func(t *testing.T) {
		req := signerapi.GroupSignRequest{
			Requests: []signerapi.SignRequest{{
				AuthAddress: genericAddr,
				TxnBytesHex: mustUnsignedPaymentTxnHex(t, sp, genericAddr, integrationBurnAddress, 0, "lsig-invalid-len"),
				LsigArgs: map[string]string{
					"preimage": hex.EncodeToString([]byte("short")),
				},
			}},
		}
		status, body := postSignRequest(t, signerd.GetURL(), "aplane "+token, req)
		if status != http.StatusBadRequest {
			t.Fatalf("expected 400 for invalid preimage length, got %d: %s", status, string(body))
		}
		if !strings.Contains(string(body), "expected 32 bytes") {
			t.Fatalf("expected byte-length validation error, got %s", string(body))
		}
	})

	t.Run("valid arg set", func(t *testing.T) {
		req := signerapi.GroupSignRequest{
			Requests: []signerapi.SignRequest{{
				AuthAddress: genericAddr,
				TxnBytesHex: mustUnsignedPaymentTxnHex(t, sp, genericAddr, integrationBurnAddress, 0, "lsig-valid-args"),
				LsigArgs: map[string]string{
					"preimage": hex.EncodeToString(genericPreimage),
				},
			}},
		}
		status, body := postSignRequest(t, signerd.GetURL(), "aplane "+token, req)
		if status != http.StatusOK {
			t.Fatalf("expected 200 for valid arg set, got %d: %s", status, string(body))
		}
		var resp signerapi.GroupSignResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			t.Fatalf("failed to parse valid arg response: %v", err)
		}
		if resp.Error != "" {
			t.Fatalf("unexpected sign error for valid arg set: %s", resp.Error)
		}
		if len(resp.Signed) != 1 {
			t.Fatalf("expected one signed transaction, got %d", len(resp.Signed))
		}
		stxn := decodeSignedTxnHex(t, resp.Signed[0])
		if len(stxn.Lsig.Args) != 1 || !bytes.Equal(stxn.Lsig.Args[0], genericPreimage) {
			t.Fatalf("expected ordered preimage arg in LogicSig, got %d args", len(stxn.Lsig.Args))
		}
	})

	t.Run("mixed generic and falcon lsig group", func(t *testing.T) {
		req := signerapi.GroupSignRequest{
			Requests: []signerapi.SignRequest{
				{
					AuthAddress: genericAddr,
					TxnBytesHex: mustUnsignedPaymentTxnHex(t, sp, genericAddr, integrationBurnAddress, 0, "lsig-mixed-generic"),
					LsigArgs: map[string]string{
						"preimage": hex.EncodeToString(genericPreimage),
					},
				},
				{
					AuthAddress: falconAddr,
					TxnBytesHex: mustUnsignedPaymentTxnHex(t, sp, falconAddr, integrationBurnAddress, 0, "lsig-mixed-falcon"),
					LsigArgs: map[string]string{
						"preimage": hex.EncodeToString(hashlockPreimage),
					},
				},
			},
		}
		status, body := postSignRequest(t, signerd.GetURL(), "aplane "+token, req)
		if status != http.StatusOK {
			t.Fatalf("expected 200 for mixed generic+falcon lsig group, got %d: %s", status, string(body))
		}

		var resp signerapi.GroupSignResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			t.Fatalf("failed to parse mixed lsig response: %v", err)
		}
		if resp.Error != "" {
			t.Fatalf("unexpected sign error for mixed lsig group: %s", resp.Error)
		}
		if len(resp.Signed) < 2 {
			t.Fatalf("expected at least two signed transactions, got %d", len(resp.Signed))
		}

		genericStxn := decodeSignedTxnHex(t, resp.Signed[0])
		if len(genericStxn.Lsig.Args) != 1 || !bytes.Equal(genericStxn.Lsig.Args[0], genericPreimage) {
			t.Fatalf("expected generic preimage arg in LogicSig, got %d args", len(genericStxn.Lsig.Args))
		}

		falconStxn := decodeSignedTxnHex(t, resp.Signed[1])
		if len(falconStxn.Lsig.Args) != 2 {
			t.Fatalf("expected falcon hashlock args [signature, preimage], got %d args", len(falconStxn.Lsig.Args))
		}
		if !bytes.Equal(falconStxn.Lsig.Args[1], hashlockPreimage) {
			t.Fatal("expected falcon hashlock preimage as second LogicSig arg")
		}
		if len(falconStxn.Lsig.Args[0]) == 0 {
			t.Fatal("expected falcon signature bytes as first LogicSig arg")
		}
	})
}

func TestApprovalTimeoutOrClientDisconnect(t *testing.T) {
	userAutoApprove := false
	lockOnDisconnect := false
	harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{
		UserAutoApprove:  &userAutoApprove,
		LockOnDisconnect: &lockOnDisconnect,
	})

	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("failed to connect to testnet: %v", err)
	}

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	t.Cleanup(apadmin.Cleanup)
	address, err := apadmin.GenerateKeyWithType("ed25519")
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	token := readSignerToken(t, signerd)
	ipcClient := mustConnectIPCClient(t, signerd.GetWorkDir())
	defer ipcClient.Close()

	if !waitForKey(t, signerd.GetURL(), token, address, 10*time.Second) {
		t.Fatalf("signer did not reload generated key %s", address)
	}

	sp, err := testnet.GetSuggestedParams()
	if err != nil {
		t.Fatalf("failed to get suggested params: %v", err)
	}
	req := signerapi.GroupSignRequest{
		Requests: []signerapi.SignRequest{{
			AuthAddress: address,
			TxnBytesHex: mustUnsignedPaymentTxnHex(t, sp, address, integrationBurnAddress, 0, "approval-disconnect"),
		}},
	}

	var (
		firstStatus int
		firstBody   []byte
		wg          sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		firstStatus, firstBody = postSignRequest(t, signerd.GetURL(), "aplane "+token, req)
	}()

	signReq := mustReadIPCSignRequest(t, ipcClient, 10*time.Second)
	if signReq.Address != address {
		t.Fatalf("expected approval request for %s, got %s", address, signReq.Address)
	}
	ipcClient.Close()
	wg.Wait()

	if firstStatus != http.StatusForbidden {
		t.Fatalf("expected 403 when approval client disconnects, got %d: %s", firstStatus, string(firstBody))
	}
	if !strings.Contains(string(firstBody), "rejected by operator") {
		t.Fatalf("expected disconnect to fail request without signing, got %s", string(firstBody))
	}

	secondClient := mustConnectIPCClient(t, signerd.GetWorkDir())
	defer secondClient.Close()

	var (
		secondStatus int
		secondBody   []byte
		secondWG     sync.WaitGroup
	)
	secondWG.Add(1)
	go func() {
		defer secondWG.Done()
		secondStatus, secondBody = postSignRequest(t, signerd.GetURL(), "aplane "+token, req)
	}()

	secondReq := mustReadIPCSignRequest(t, secondClient, 10*time.Second)
	mustApproveIPCSignRequest(t, secondClient, secondReq.ID)
	secondWG.Wait()

	if secondStatus != http.StatusOK {
		t.Fatalf("expected follow-up request to succeed after reconnect, got %d: %s", secondStatus, string(secondBody))
	}
	var signResp signerapi.GroupSignResponse
	if err := json.Unmarshal(secondBody, &signResp); err != nil {
		t.Fatalf("failed to decode follow-up sign response: %v", err)
	}
	if signResp.Error != "" {
		t.Fatalf("unexpected follow-up sign error: %s", signResp.Error)
	}
	if len(signResp.Signed) != 1 {
		t.Fatalf("expected one signed txn after reconnect, got %d", len(signResp.Signed))
	}
}

func readSignerToken(t *testing.T, signerd *harness.SignerHarness) string {
	t.Helper()

	data, err := os.ReadFile(signerd.GetTokenPath())
	if err != nil {
		t.Fatalf("failed to read signer token: %v", err)
	}
	return strings.TrimSpace(string(data))
}

func mustUnsignedPaymentTxnHex(t *testing.T, sp types.SuggestedParams, from, to string, amount uint64, note string) string {
	t.Helper()

	txn, err := transaction.MakePaymentTxn(from, to, amount, []byte(note), "", sp)
	if err != nil {
		t.Fatalf("failed to build payment txn: %v", err)
	}
	return hex.EncodeToString(append([]byte("TX"), msgpack.Encode(txn)...))
}

func mustUnsignedPaymentTxnHexWithRekey(
	t *testing.T,
	sp types.SuggestedParams,
	from, to string,
	amount uint64,
	note string,
	rekeyTo string,
) string {
	t.Helper()

	txn, err := transaction.MakePaymentTxn(from, to, amount, []byte(note), "", sp)
	if err != nil {
		t.Fatalf("failed to build payment txn: %v", err)
	}
	rekeyAddr, err := types.DecodeAddress(rekeyTo)
	if err != nil {
		t.Fatalf("failed to decode rekey address %s: %v", rekeyTo, err)
	}
	txn.RekeyTo = rekeyAddr
	return hex.EncodeToString(append([]byte("TX"), msgpack.Encode(txn)...))
}

func mustUnsignedPaymentTxnHexWithClose(
	t *testing.T,
	sp types.SuggestedParams,
	from, to string,
	amount uint64,
	note string,
	closeTo string,
) string {
	t.Helper()

	txn, err := transaction.MakePaymentTxn(from, to, amount, []byte(note), "", sp)
	if err != nil {
		t.Fatalf("failed to build payment txn: %v", err)
	}
	closeAddr, err := types.DecodeAddress(closeTo)
	if err != nil {
		t.Fatalf("failed to decode close address %s: %v", closeTo, err)
	}
	txn.CloseRemainderTo = closeAddr
	return hex.EncodeToString(append([]byte("TX"), msgpack.Encode(txn)...))
}

func mustUnsignedAssetTransferTxnHexWithClose(
	t *testing.T,
	sp types.SuggestedParams,
	from, to string,
	amount uint64,
	assetID uint64,
	closeTo string,
	note string,
) string {
	t.Helper()

	txn, err := transaction.MakeAssetTransferTxn(from, to, amount, []byte(note), sp, "", assetID)
	if err != nil {
		t.Fatalf("failed to build asset transfer txn: %v", err)
	}
	closeAddr, err := types.DecodeAddress(closeTo)
	if err != nil {
		t.Fatalf("failed to decode asset close address %s: %v", closeTo, err)
	}
	txn.AssetCloseTo = closeAddr
	return hex.EncodeToString(append([]byte("TX"), msgpack.Encode(txn)...))
}

func mustUnsignedAssetTransferTxnHexWithClawback(
	t *testing.T,
	sp types.SuggestedParams,
	from, to string,
	amount uint64,
	assetID uint64,
	assetSender string,
	note string,
) string {
	t.Helper()

	txn, err := transaction.MakeAssetTransferTxn(from, to, amount, []byte(note), sp, "", assetID)
	if err != nil {
		t.Fatalf("failed to build asset transfer txn: %v", err)
	}
	assetSenderAddr, err := types.DecodeAddress(assetSender)
	if err != nil {
		t.Fatalf("failed to decode asset sender %s: %v", assetSender, err)
	}
	txn.AssetSender = assetSenderAddr
	return hex.EncodeToString(append([]byte("TX"), msgpack.Encode(txn)...))
}

func postSignRequest(t *testing.T, signerURL, authHeader string, reqBody signerapi.GroupSignRequest) (int, []byte) {
	t.Helper()

	body, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("failed to marshal sign request: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, signerURL+"/sign", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("failed to build sign request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatalf("failed to submit sign request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read sign response: %v", err)
	}
	return resp.StatusCode, respBody
}

func waitForSignerLocked(t *testing.T, baseURL, token string, timeout time.Duration) bool {
	t.Helper()

	deadline := time.Now().Add(timeout)
	client := &http.Client{}
	for time.Now().Before(deadline) {
		req, _ := http.NewRequest("GET", baseURL+"/status", nil)
		req.Header.Set("Authorization", "aplane "+token)
		resp, err := client.Do(req)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			var status signerapi.StatusResponse
			if resp.StatusCode == http.StatusOK && json.Unmarshal(body, &status) == nil && status.SignerLocked {
				return true
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	return false
}

func waitForKeyMissing(t *testing.T, baseURL, token, address string, timeout time.Duration) bool {
	t.Helper()

	deadline := time.Now().Add(timeout)
	client := &http.Client{}
	for time.Now().Before(deadline) {
		req, _ := http.NewRequest("GET", baseURL+"/keys", nil)
		req.Header.Set("Authorization", "aplane "+token)
		resp, err := client.Do(req)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if !bytes.Contains(body, []byte(address)) {
				return true
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

func decodeSignedTxnHex(t *testing.T, signedHex string) types.SignedTxn {
	t.Helper()

	signedBytes, err := hex.DecodeString(signedHex)
	if err != nil {
		t.Fatalf("failed to decode signed txn hex: %v", err)
	}

	var stxn types.SignedTxn
	if err := msgpack.Decode(signedBytes, &stxn); err != nil {
		t.Fatalf("failed to decode signed txn msgpack: %v", err)
	}
	return stxn
}

func submitSignedTxnGroup(t *testing.T, testnet *harness.TestnetConfig, signedHexes []string) []string {
	t.Helper()

	rawGroup := make([]byte, 0)
	txids := make([]string, 0, len(signedHexes))
	for _, signedHex := range signedHexes {
		signedBytes, err := hex.DecodeString(signedHex)
		if err != nil {
			t.Fatalf("failed to decode signed group txn: %v", err)
		}
		var stxn types.SignedTxn
		if err := msgpack.Decode(signedBytes, &stxn); err != nil {
			t.Fatalf("failed to decode signed group txn: %v", err)
		}
		rawGroup = append(rawGroup, signedBytes...)
		txids = append(txids, crypto.GetTxID(stxn.Txn))
	}

	if _, err := testnet.Client.SendRawTransaction(rawGroup).Do(context.Background()); err != nil {
		t.Fatalf("failed to submit signed txn group: %v", err)
	}
	return txids
}

func closeAccountToFunding(t *testing.T, apshell *harness.ApshellHarness, testnet *harness.TestnetConfig, account, destination string) {
	t.Helper()

	amount, err := testnet.GetAccountInfo(account)
	if err != nil {
		t.Fatalf("failed to inspect account %s for cleanup: %v", account, err)
	}
	if amount == 0 {
		return
	}

	txid, err := apshell.CloseAccount(account, destination)
	if err != nil {
		t.Fatalf("failed to close account %s back to funding source %s: %v", account, destination, err)
	}
	if _, err := testnet.WaitForConfirmation(txid, 10); err != nil {
		t.Fatalf("close transaction for %s failed to confirm: %v", account, err)
	}
}

func closeAccountWithSigningKey(
	t *testing.T,
	testnet *harness.TestnetConfig,
	account, destination string,
	signingKey []byte,
) {
	t.Helper()

	amount, err := testnet.GetAccountInfo(account)
	if err != nil {
		t.Fatalf("failed to inspect account %s for cleanup: %v", account, err)
	}
	if amount == 0 {
		return
	}

	sp, err := testnet.GetSuggestedParams()
	if err != nil {
		t.Fatalf("failed to get suggested params for cleanup: %v", err)
	}
	txn, err := transaction.MakePaymentTxn(account, destination, 0, []byte("cleanup-close"), "", sp)
	if err != nil {
		t.Fatalf("failed to build cleanup close transaction: %v", err)
	}
	closeAddr, err := types.DecodeAddress(destination)
	if err != nil {
		t.Fatalf("failed to decode cleanup destination %s: %v", destination, err)
	}
	txn.CloseRemainderTo = closeAddr

	txid, signedBytes, err := crypto.SignTransaction(signingKey, txn)
	if err != nil {
		t.Fatalf("failed to sign cleanup close transaction for %s: %v", account, err)
	}
	if _, err := testnet.Client.SendRawTransaction(signedBytes).Do(context.Background()); err != nil {
		t.Fatalf("failed to submit cleanup close transaction for %s: %v", account, err)
	}
	if _, err := testnet.WaitForConfirmation(txid, 10); err != nil {
		t.Fatalf("close transaction for %s failed to confirm: %v", account, err)
	}
}

func mustAdminGenerateKey(t *testing.T, signerClient *signerclient.Client, signerd *harness.SignerHarness, keyType string, params map[string]string) string {
	t.Helper()

	resp, err := signerClient.AdminGenerate(keyType, params)
	if err != nil {
		t.Fatalf("failed to generate %s via admin API: %v", keyType, err)
	}
	if resp.Address == "" {
		t.Fatalf("admin generate for %s returned empty address", keyType)
	}
	t.Cleanup(func() {
		if _, err := signerClient.AdminDeleteKey(resp.Address); err != nil {
			t.Fatalf("failed to delete generated key %s: %v", resp.Address, err)
		}
	})
	token := readSignerToken(t, signerd)
	if !waitForKey(t, signerd.GetURL(), token, resp.Address, 10*time.Second) {
		t.Fatalf("signer did not reload generated key %s", resp.Address)
	}
	return resp.Address
}

func mustExtractTxID(t *testing.T, output string) string {
	t.Helper()

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "transaction id:") || strings.Contains(lower, "transaction submitted:") {
			for _, part := range strings.Fields(line) {
				if len(part) == 52 && !strings.Contains(part, ":") {
					return part
				}
			}
		}
	}
	t.Fatalf("could not find transaction ID in output: %s", output)
	return ""
}

func mustConnectIPCClient(t *testing.T, signerWorkDir string) *transport.IPCClient {
	t.Helper()

	passphrase := os.Getenv("TEST_PASSPHRASE")
	if passphrase == "" {
		t.Fatal("TEST_PASSPHRASE not set")
	}

	ipcClient := transport.NewIPC(mustSignerIPCPath(t, signerWorkDir))
	if err := ipcClient.Dial(); err != nil {
		t.Fatalf("failed to dial signer IPC: %v", err)
	}
	if err := authenticateOrDisplaceIPCClient(ipcClient, passphrase, 10*time.Second); err != nil {
		t.Fatalf("failed to authenticate IPC client: %v", err)
	}
	status, err := ipcClient.WaitForStatus(10 * time.Second)
	if err != nil {
		t.Fatalf("failed to receive signer status over IPC: %v", err)
	}
	if status.State == "locked" {
		result, err := ipcClient.Unlock(passphrase, 30*time.Second)
		if err != nil {
			t.Fatalf("failed to unlock signer over IPC: %v", err)
		}
		if !result.Success {
			t.Fatalf("failed to unlock signer over IPC: %s", result.Error)
		}
	}
	return ipcClient
}

func mustSignerIPCPath(t *testing.T, signerWorkDir string) string {
	t.Helper()

	configPath := filepath.Join(signerWorkDir, "config.yaml")
	var cfg struct {
		IPCPath string `yaml:"ipc_path"`
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("failed to read signer config %s: %v", configPath, err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("failed to parse signer config %s: %v", configPath, err)
	}
	if cfg.IPCPath == "" {
		return filepath.Join(signerWorkDir, "aplane.sock")
	}
	if filepath.IsAbs(cfg.IPCPath) {
		return cfg.IPCPath
	}
	return filepath.Join(signerWorkDir, cfg.IPCPath)
}

func authenticateOrDisplaceIPCClient(ipcClient *transport.IPCClient, passphrase string, timeout time.Duration) error {
	ipcClient.SetReadDeadline(timeout)
	defer ipcClient.ClearReadDeadline()

	for {
		message, err := ipcClient.ReadMessage()
		if err != nil {
			return fmt.Errorf("failed to receive auth handshake: %w", err)
		}

		var base protocol.BaseMessage
		if err := json.Unmarshal(message, &base); err != nil {
			return fmt.Errorf("failed to parse auth handshake: %w", err)
		}

		switch base.Type {
		case protocol.MsgTypeAuthRequired:
			authMsg := protocol.AuthMessage{
				BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeAuth},
				Passphrase:  protocol.NewSensitiveBytes(passphrase),
			}
			if err := ipcClient.WriteJSON(authMsg); err != nil {
				return fmt.Errorf("failed to send auth message: %w", err)
			}

			resultMsg, err := ipcClient.ReadMessage()
			if err != nil {
				return fmt.Errorf("failed to receive auth_result: %w", err)
			}

			var resultBase protocol.BaseMessage
			if err := json.Unmarshal(resultMsg, &resultBase); err != nil {
				return fmt.Errorf("failed to parse auth_result: %w", err)
			}
			if resultBase.Type != protocol.MsgTypeAuthResult {
				return fmt.Errorf("expected auth_result message, got: %s", resultBase.Type)
			}

			var authResult protocol.AuthResultMessage
			if err := json.Unmarshal(resultMsg, &authResult); err != nil {
				return fmt.Errorf("failed to parse auth_result: %w", err)
			}
			if !authResult.Success {
				return fmt.Errorf("authentication failed: %s", authResult.Error)
			}
			return nil
		case protocol.MsgTypeClientExists:
			if err := ipcClient.WriteJSON(protocol.DisplaceConfirmMessage{
				BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeDisplaceConfirm},
			}); err != nil {
				return fmt.Errorf("failed to confirm client displacement: %w", err)
			}
		default:
			return fmt.Errorf("expected auth_required or client_exists message, got: %s", base.Type)
		}
	}
}

func mustReadIPCSignRequest(t *testing.T, ipcClient *transport.IPCClient, timeout time.Duration) protocol.SignRequestMessage {
	t.Helper()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	notifications := ipcClient.Notifications()
	for {
		select {
		case notification := <-notifications:
			if notification.Base.Type != protocol.MsgTypeSignRequest {
				continue
			}

			var req protocol.SignRequestMessage
			if err := json.Unmarshal(notification.Raw, &req); err != nil {
				t.Fatalf("failed to parse sign request message: %v", err)
			}
			return req
		case <-timer.C:
			t.Fatalf("timed out waiting for sign request over IPC")
		}
	}
}

func mustApproveIPCSignRequest(t *testing.T, ipcClient *transport.IPCClient, requestID string) {
	t.Helper()

	if err := ipcClient.WriteJSON(protocol.SignResponseMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeSignResponse,
			ID:   requestID,
		},
		Approved: true,
	}); err != nil {
		t.Fatalf("failed to send sign approval over IPC: %v", err)
	}
}

func mustRejectIPCSignRequest(t *testing.T, ipcClient *transport.IPCClient, requestID string) {
	t.Helper()

	if err := ipcClient.WriteJSON(protocol.SignResponseMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeSignResponse,
			ID:   requestID,
		},
		Approved: false,
	}); err != nil {
		t.Fatalf("failed to send sign rejection over IPC: %v", err)
	}
}

func mustUpdateIPCPolicySetting(t *testing.T, ipcClient *transport.IPCClient, key, value string) {
	t.Helper()

	respBytes, err := ipcClient.SendAndReceive(protocol.UpdatePolicySettingMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeUpdatePolicySetting,
			ID:   fmt.Sprintf("policy-%d", time.Now().UnixNano()),
		},
		Key:   key,
		Value: value,
	}, 10*time.Second)
	if err != nil {
		t.Fatalf("failed to update policy setting %s: %v", key, err)
	}

	var result protocol.UpdatePolicySettingResultMessage
	if err := json.Unmarshal(respBytes, &result); err != nil {
		t.Fatalf("failed to parse policy-setting result: %v", err)
	}
	if !result.Success {
		t.Fatalf("policy update %s=%s failed: %s", key, value, result.Error)
	}
	if result.Key != key || result.Value != value {
		t.Fatalf("policy update echoed key/value = %s/%s, want %s/%s", result.Key, result.Value, key, value)
	}
}

func mustNotReceiveIPCSignRequest(t *testing.T, ipcClient *transport.IPCClient, timeout time.Duration) {
	t.Helper()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	notifications := ipcClient.Notifications()
	for {
		select {
		case notification := <-notifications:
			if notification.Base.Type != protocol.MsgTypeSignRequest {
				continue
			}
			t.Fatalf("unexpected sign request over IPC: %s", string(notification.Raw))
		case <-timer.C:
			return
		}
	}
}
