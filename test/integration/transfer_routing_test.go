// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integration_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/transport"
	"github.com/aplane-algo/aplane/test/integration/harness"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
)

const transferRoutingIntegrationAssetID = 12345

type transferRoutingTestAddresses struct {
	source       string
	other        string
	authority    string
	allowed      string
	review       string
	reject       string
	blocked      string
	denied       string
	networkLimit string
	closeTo      string
	owner        string
	otherOwner   string
	recovery     string
}

func TestTransferRoutingIntegrationExercisesRoutes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping transfer routing integration test in short mode")
	}

	userAutoApprove := true
	lockOnDisconnect := false
	env := harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{
		UserAutoApprove:  &userAutoApprove,
		LockOnDisconnect: &lockOnDisconnect,
	})

	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("failed to connect to integration network: %v", err)
	}

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	t.Cleanup(apadmin.Cleanup)

	addresses := generateTransferRoutingTestAddresses(t, apadmin)

	if err := apadmin.UnlockSigner(); err != nil {
		t.Fatalf("failed to unlock signer: %v", err)
	}

	token := readSignerToken(t, signerd)
	requirePolicyTestKeyLoaded(t, signerd, token, addresses.source)
	requirePolicyTestKeyLoaded(t, signerd, token, addresses.other)
	requirePolicyTestKeyLoaded(t, signerd, token, addresses.authority)

	apstore := harness.NewApStoreHarness(t, env.SignerDataDir)
	passphrase := os.Getenv("TEST_PASSPHRASE")
	if passphrase == "" {
		t.Fatal("TEST_PASSPHRASE not set")
	}

	stopSigner(t, signerd)
	writeAndSignIntegrationPolicy(
		t,
		apstore,
		env.SignerDataDir,
		passphrase,
		transferRoutingIntegrationPolicy(testnet.Network, addresses),
	)
	startSignerAndLoadKey(t, signerd, apadmin, token, addresses.source)
	requirePolicyTestKeyLoaded(t, signerd, token, addresses.other)
	requirePolicyTestKeyLoaded(t, signerd, token, addresses.authority)

	sp, err := testnet.GetSuggestedParams()
	if err != nil {
		t.Fatalf("failed to get suggested params: %v", err)
	}

	authHeader := "aplane " + token
	ipcClient := mustConnectIPCClient(t, signerd.GetWorkDir())
	defer ipcClient.Close()

	t.Run("allowed_route_signs", func(t *testing.T) {
		req := transferRoutingSignRequest(
			addresses.source,
			mustUnsignedPaymentTxnHex(t, sp, addresses.source, addresses.allowed, 1, "routing-allowed"),
		)
		expectTransferRoutingSignOK(t, signerd.GetURL(), authHeader, req)
	})

	t.Run("self_destination_term_signs", func(t *testing.T) {
		req := transferRoutingSignRequest(
			addresses.source,
			mustUnsignedPaymentTxnHex(t, sp, addresses.source, addresses.source, 1, "routing-self"),
		)
		expectTransferRoutingSignOK(t, signerd.GetURL(), authHeader, req)
	})

	t.Run("route_miss_rejects_without_operator_prompt", func(t *testing.T) {
		req := transferRoutingSignRequest(
			addresses.source,
			mustUnsignedPaymentTxnHex(t, sp, addresses.source, addresses.blocked, 1, "routing-miss"),
		)
		expectTransferRoutingReject(t, signerd.GetURL(), authHeader, req, "transfer_policy:route_miss")
		mustNotReceiveIPCSignRequest(t, ipcClient, 500*time.Millisecond)
	})

	t.Run("unknown_genesis_rejects_without_operator_prompt", func(t *testing.T) {
		unknownGenesisSP := sp
		unknownGenesisSP.GenesisHash = make([]byte, 32)
		unknownGenesisSP.GenesisHash[0] = 99
		req := transferRoutingSignRequest(
			addresses.source,
			mustUnsignedPaymentTxnHex(t, unknownGenesisSP, addresses.source, addresses.allowed, 1, "routing-unknown-genesis"),
		)
		expectTransferRoutingBadRequest(t, signerd.GetURL(), authHeader, req, "unrecognized genesis hash")
		mustNotReceiveIPCSignRequest(t, ipcClient, 500*time.Millisecond)
	})

	t.Run("reject_threshold_rejects_without_operator_prompt", func(t *testing.T) {
		req := transferRoutingSignRequest(
			addresses.source,
			mustUnsignedPaymentTxnHex(t, sp, addresses.source, addresses.reject, 6, "routing-reject-threshold"),
		)
		expectTransferRoutingReject(t, signerd.GetURL(), authHeader, req, "transfer_policy:reject_payee:reject_above")
		mustNotReceiveIPCSignRequest(t, ipcClient, 500*time.Millisecond)
	})

	t.Run("limits_by_network_rejects_without_operator_prompt", func(t *testing.T) {
		req := transferRoutingSignRequest(
			addresses.source,
			mustUnsignedPaymentTxnHex(t, sp, addresses.source, addresses.networkLimit, 5, "routing-network-limit"),
		)
		expectTransferRoutingReject(t, signerd.GetURL(), authHeader, req, "transfer_policy:network_limit_payee:reject_above")
		mustNotReceiveIPCSignRequest(t, ipcClient, 500*time.Millisecond)
	})

	t.Run("wildcard_passthrough_route_signs", func(t *testing.T) {
		req := transferRoutingSignRequest(
			addresses.other,
			mustUnsignedPaymentTxnHex(t, sp, addresses.other, addresses.blocked, 1, "routing-other"),
		)
		expectTransferRoutingSignOK(t, signerd.GetURL(), authHeader, req)
	})

	t.Run("blocked_destination_rejects_before_wildcard_route", func(t *testing.T) {
		req := transferRoutingSignRequest(
			addresses.other,
			mustUnsignedPaymentTxnHex(t, sp, addresses.other, addresses.denied, 1, "routing-blocked"),
		)
		expectTransferRoutingReject(t, signerd.GetURL(), authHeader, req, "transfer_policy:blocked_destination")
		mustNotReceiveIPCSignRequest(t, ipcClient, 500*time.Millisecond)
	})

	t.Run("review_threshold_forces_operator_approval", func(t *testing.T) {
		req := transferRoutingSignRequest(
			addresses.source,
			mustUnsignedPaymentTxnHex(t, sp, addresses.source, addresses.review, 11, "routing-review-threshold"),
		)
		expectTransferRoutingManualApproval(t, signerd.GetURL(), authHeader, req, ipcClient, addresses.source)
	})

	t.Run("allowed_close_route_signs", func(t *testing.T) {
		req := transferRoutingSignRequest(
			addresses.source,
			mustUnsignedPaymentTxnHexWithClose(
				t,
				sp,
				addresses.source,
				addresses.allowed,
				1,
				"routing-close-allowed",
				addresses.closeTo,
			),
		)
		expectTransferRoutingSignOK(t, signerd.GetURL(), authHeader, req)
	})

	t.Run("close_without_close_route_rejects", func(t *testing.T) {
		req := transferRoutingSignRequest(
			addresses.source,
			mustUnsignedPaymentTxnHexWithClose(
				t,
				sp,
				addresses.source,
				addresses.allowed,
				1,
				"routing-close-denied",
				addresses.blocked,
			),
		)
		expectTransferRoutingReject(t, signerd.GetURL(), authHeader, req, "transfer_policy:close_rejected")
	})

	t.Run("allowed_clawback_route_signs", func(t *testing.T) {
		req := transferRoutingSignRequest(
			addresses.authority,
			mustUnsignedAssetTransferTxnHexWithClawback(
				t,
				sp,
				addresses.authority,
				addresses.recovery,
				1,
				transferRoutingIntegrationAssetID,
				addresses.owner,
				"routing-clawback-allowed",
			),
		)
		expectTransferRoutingSignOK(t, signerd.GetURL(), authHeader, req)
	})

	t.Run("clawback_without_matching_asset_source_rejects", func(t *testing.T) {
		req := transferRoutingSignRequest(
			addresses.authority,
			mustUnsignedAssetTransferTxnHexWithClawback(
				t,
				sp,
				addresses.authority,
				addresses.recovery,
				1,
				transferRoutingIntegrationAssetID,
				addresses.otherOwner,
				"routing-clawback-denied",
			),
		)
		expectTransferRoutingReject(t, signerd.GetURL(), authHeader, req, "transfer_policy:clawback_rejected")
	})
}

func generateTransferRoutingTestAddresses(t *testing.T, apadmin *harness.ApAdminHarness) transferRoutingTestAddresses {
	t.Helper()

	source, err := apadmin.GenerateKeyWithType("ed25519")
	if err != nil {
		t.Fatalf("failed to generate routing source key: %v", err)
	}
	other, err := apadmin.GenerateKeyWithType("ed25519")
	if err != nil {
		t.Fatalf("failed to generate routing passthrough key: %v", err)
	}
	authority, err := apadmin.GenerateKeyWithType("ed25519")
	if err != nil {
		t.Fatalf("failed to generate routing clawback authority key: %v", err)
	}

	return transferRoutingTestAddresses{
		source:       source,
		other:        other,
		authority:    authority,
		allowed:      randomTransferRoutingAddress(),
		review:       randomTransferRoutingAddress(),
		reject:       randomTransferRoutingAddress(),
		blocked:      randomTransferRoutingAddress(),
		denied:       randomTransferRoutingAddress(),
		networkLimit: randomTransferRoutingAddress(),
		closeTo:      randomTransferRoutingAddress(),
		owner:        randomTransferRoutingAddress(),
		otherOwner:   randomTransferRoutingAddress(),
		recovery:     randomTransferRoutingAddress(),
	}
}

func randomTransferRoutingAddress() string {
	return algocrypto.GenerateAccount().Address.String()
}

func transferRoutingIntegrationPolicy(network string, addr transferRoutingTestAddresses) string {
	return fmt.Sprintf(`reject_foreign_rekey: false
reject_close_remainder: false
reject_asset_close: false
reject_clawback: false
always_review_warnings: false
auto_approve_self_noop_transfer: false
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  blocked_destinations:
    - %q
  address_sets:
    source_accounts:
      %q:
        - %q
    normal_receivers:
      - %q
    recovery_receivers:
      %q:
        - %q
        - %q
  asset_sets:
    clawback_assets:
      %q: [%d]
  routes:
    - id: normal_payee
      networks: [%q]
      sources: ["@source_accounts"]
      assets: ["algo"]
      destinations: ["@normal_receivers", "self"]
    - id: review_payee
      networks: [%q]
      sources: [%q]
      assets: ["algo"]
      destinations: [%q]
      limits:
        review_above: 10
    - id: reject_payee
      networks: [%q]
      sources: [%q]
      assets: ["algo"]
      destinations: [%q]
      limits:
        reject_above: 5
    - id: network_limit_payee
      networks: [%q]
      sources: [%q]
      assets: ["algo"]
      destinations: [%q]
      limits:
        reject_above: 100
      limits_by_network:
        %q:
          review_above: 2
          reject_above: 4
    - id: other_passthrough
      networks: [%q]
      sources: [%q]
      assets: ["algo"]
      destinations: ["*"]
    - id: close_recovery
      networks: [%q]
      sources: [%q]
      assets: ["algo"]
      destinations: ["@recovery_receivers"]
      close:
        allow: true
    - id: clawback_recovery
      networks: [%q]
      sources: [%q]
      asset_sources: [%q]
      assets: ["@clawback_assets"]
      destinations: ["@recovery_receivers"]
      clawback:
        allow: true
`,
		addr.denied,
		network,
		addr.source,
		addr.allowed,
		network,
		addr.closeTo,
		addr.recovery,
		network,
		transferRoutingIntegrationAssetID,
		network,
		network,
		addr.source,
		addr.review,
		network,
		addr.source,
		addr.reject,
		network,
		addr.source,
		addr.networkLimit,
		network,
		network,
		addr.other,
		network,
		addr.source,
		network,
		addr.authority,
		addr.owner,
	)
}

func transferRoutingSignRequest(authAddress, txnHex string) signerapi.GroupSignRequest {
	return signerapi.GroupSignRequest{
		Requests: []signerapi.SignRequest{{
			AuthAddress: authAddress,
			TxnBytesHex: txnHex,
		}},
	}
}

func expectTransferRoutingSignOK(t *testing.T, signerURL, authHeader string, req signerapi.GroupSignRequest) signerapi.GroupSignResponse {
	t.Helper()

	status, body := postSignRequest(t, signerURL, authHeader, req)
	resp := decodeTransferRoutingSignResponse(t, body)
	if status != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", status, string(body))
	}
	if resp.Error != "" {
		t.Fatalf("signer returned unexpected error: %s", resp.Error)
	}
	if got := len(resp.Signed); got != 1 {
		t.Fatalf("signed transaction count = %d, want 1", got)
	}
	return resp
}

func expectTransferRoutingReject(t *testing.T, signerURL, authHeader string, req signerapi.GroupSignRequest, wantRuleID string) signerapi.GroupSignResponse {
	t.Helper()

	status, body := postSignRequest(t, signerURL, authHeader, req)
	resp := decodeTransferRoutingSignResponse(t, body)
	if status != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden, got %d: %s", status, string(body))
	}
	if !strings.Contains(resp.Error, "policy engine rejected request") {
		t.Fatalf("expected policy rejection, got %q", resp.Error)
	}
	if !strings.Contains(resp.Error, wantRuleID) {
		t.Fatalf("expected rejection rule %q, got %q", wantRuleID, resp.Error)
	}
	if len(resp.Signed) != 0 {
		t.Fatalf("signed transaction count = %d, want 0", len(resp.Signed))
	}
	return resp
}

func expectTransferRoutingBadRequest(t *testing.T, signerURL, authHeader string, req signerapi.GroupSignRequest, wantError string) signerapi.GroupSignResponse {
	t.Helper()

	status, body := postSignRequest(t, signerURL, authHeader, req)
	resp := decodeTransferRoutingSignResponse(t, body)
	if status != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request, got %d: %s", status, string(body))
	}
	if !strings.Contains(resp.Error, wantError) {
		t.Fatalf("expected error containing %q, got %q", wantError, resp.Error)
	}
	if len(resp.Signed) != 0 {
		t.Fatalf("signed transaction count = %d, want 0", len(resp.Signed))
	}
	return resp
}

func expectTransferRoutingManualApproval(
	t *testing.T,
	signerURL string,
	authHeader string,
	req signerapi.GroupSignRequest,
	ipcClient *transport.IPCClient,
	wantAddress string,
) signerapi.GroupSignResponse {
	t.Helper()

	done := make(chan struct{})
	var status int
	var body []byte
	go func() {
		defer close(done)
		status, body = postSignRequest(t, signerURL, authHeader, req)
	}()

	signReq := mustReadIPCSignRequest(t, ipcClient, 10*time.Second)
	if signReq.Address != wantAddress {
		t.Fatalf("manual approval address = %s, want %s", signReq.Address, wantAddress)
	}
	if !strings.Contains(signReq.Description, "[TXN APPROVAL]") {
		t.Fatalf("manual approval description missing txn marker:\n%s", signReq.Description)
	}
	mustApproveIPCSignRequest(t, ipcClient, signReq.ID)

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for manually approved sign request")
	}

	resp := decodeTransferRoutingSignResponse(t, body)
	if status != http.StatusOK {
		t.Fatalf("expected 200 OK after manual approval, got %d: %s", status, string(body))
	}
	if resp.Error != "" {
		t.Fatalf("signer returned unexpected error after manual approval: %s", resp.Error)
	}
	if got := len(resp.Signed); got != 1 {
		t.Fatalf("signed transaction count after manual approval = %d, want 1", got)
	}
	return resp
}

func decodeTransferRoutingSignResponse(t *testing.T, body []byte) signerapi.GroupSignResponse {
	t.Helper()

	var resp signerapi.GroupSignResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("failed to decode sign response: %v\nbody: %s", err, string(body))
	}
	return resp
}
