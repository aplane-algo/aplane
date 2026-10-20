// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integration_test

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policy/policytest"
	"github.com/aplane-algo/aplane/pkg/signerapi"
	"github.com/aplane-algo/aplane/test/integration/harness"
)

// perKeyPolicyNode is a signer node holding one ed25519 key, with the
// shipped default applied in place of the permissive test default.
type perKeyPolicyNode struct {
	signerd *harness.SignerHarness
	apadmin *harness.ApAdminHarness
	address string
	sp      types.SuggestedParams
	network string
}

func newPerKeyPolicyNode(t *testing.T, userAutoApprove bool) *perKeyPolicyNode {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping policy integration test in short mode")
	}
	if os.Getenv("TEST_FUNDING_MNEMONIC") == "" {
		t.Skip("TEST_FUNDING_MNEMONIC not set")
	}
	harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{UserAutoApprove: &userAutoApprove})

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
	address, err := apadmin.GenerateKeyWithType("ed25519")
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	if err := apadmin.UnlockSigner(); err != nil {
		t.Fatalf("failed to unlock signer: %v", err)
	}
	if !waitForKey(t, signerd.GetURL(), address, 10*time.Second) {
		t.Fatalf("signer did not load generated key %s", address)
	}
	sp, err := testnet.GetSuggestedParams()
	if err != nil {
		t.Fatalf("failed to get suggested params: %v", err)
	}

	// The test environment's default is permissive; the shipped default is
	// what a fresh store runs under.
	applied := runPolicy(t, apadmin, policytest.EmbeddedDefault(t, noderole.RoleSigner), 0, "apply", "--yes", "-").Stdout
	appliedPolicySHA(t, applied)
	return &perKeyPolicyNode{signerd: signerd, apadmin: apadmin, address: address, sp: sp, network: testnet.Network}
}

func (n *perKeyPolicyNode) signRequest(txnHex string) signerapi.GroupSignRequest {
	return signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{{AuthAddress: n.address, TxnBytesHex: txnHex}}}
}

func (n *perKeyPolicyNode) expectSigned(t *testing.T, context, txnHex string) {
	t.Helper()
	status, body := postSignRequest(t, n.signerd.GetURL(), n.signRequest(txnHex))
	if status != http.StatusOK {
		t.Fatalf("%s: expected 200, got %d: %s", context, status, string(body))
	}
}

// expectPrompt checks that the request waited for an operator: with no
// apadmin connected, the daemon answers 503 instead of signing.
func (n *perKeyPolicyNode) expectPrompt(t *testing.T, context, txnHex string) {
	t.Helper()
	status, body := postSignRequest(t, n.signerd.GetURL(), n.signRequest(txnHex))
	if status != http.StatusServiceUnavailable || !strings.Contains(string(body), "no apadmin connected") {
		t.Fatalf("%s: expected 503 awaiting operator approval, got %d: %s", context, status, string(body))
	}
}

func (n *perKeyPolicyNode) expectRejected(t *testing.T, txnHex, ruleID string) {
	t.Helper()
	expectTransferRoutingReject(t, n.signerd.GetURL(), n.signRequest(txnHex), ruleID)
}

func (n *perKeyPolicyNode) statusLine(t *testing.T) string {
	t.Helper()
	status := runPolicy(t, n.apadmin, "", 0, "status").Stdout
	for _, line := range strings.Split(status, "\n") {
		if strings.Contains(line, n.address) {
			return strings.TrimSpace(line)
		}
	}
	t.Fatalf("policy status does not list %s:\n%s", n.address, status)
	return ""
}

// TestPerKeyPolicyDefaultAndOwnDocument runs one key through the two states
// a key can be in: following the node default, and governed by a document
// of its own.
func TestPerKeyPolicyDefaultAndOwnDocument(t *testing.T) {
	n := newPerKeyPolicyNode(t, true)
	foreign := algocrypto.GenerateAccount().Address.String()
	dest := algocrypto.GenerateAccount().Address.String()
	// The burn address is the zero address, which is not a close target.
	closeTo := algocrypto.GenerateAccount().Address.String()

	// On the shipped default: a foreign rekey is rejected, an outbound
	// payment reaches the operator default and user_auto_approve signs it,
	// and User Auto-Approve satisfies the close-out warning review.
	if line := n.statusLine(t); !strings.HasSuffix(line, "  default") {
		t.Fatalf("status before an own document = %q, want the key on the default", line)
	}
	n.expectRejected(t, mustUnsignedPaymentTxnHexWithRekey(t, n.sp, n.address, n.address, 0, "per-key-default-rekey", foreign), policy.RejectForeignRekeyRuleID)
	n.expectSigned(t, "outbound payment on the default", mustUnsignedPaymentTxnHex(t, n.sp, n.address, integrationBurnAddress, 0, "per-key-default-outbound"))
	n.expectSigned(t, "close-out on the default with user auto-approve", mustUnsignedPaymentTxnHexWithClose(t, n.sp, n.address, integrationBurnAddress, 0, "per-key-default-close", closeTo))

	// The key's own document: one route, every miss rejected.
	own := policytest.Signer(t, n.address, fmt.Sprintf(`{
  "reject_foreign_rekey": false,
  "transfer_policy": {"on_no_route": "reject", "routes": [
    {"id": "to_dest", "networks": [%q], "sources": ["*"], "assets": ["algo"], "destinations": [%q]}
  ]}
}`, n.network, dest))
	ownPath := filepath.Join(t.TempDir(), "own.json")
	if err := os.WriteFile(ownPath, []byte(own), 0o600); err != nil {
		t.Fatal(err)
	}
	diff := runPolicy(t, n.apadmin, "", 0, "diff", ownPath).Stdout
	if !strings.Contains(diff, "the key gets a policy of its own") || !strings.Contains(diff, "/transfer_policy") {
		t.Fatalf("diff for a key on the default:\n%s", diff)
	}
	applied := runPolicy(t, n.apadmin, "", 0, "apply", "--yes", ownPath).Stdout
	ownSHA := appliedPolicySHA(t, applied)
	if line := n.statusLine(t); !strings.Contains(line, "own policy") {
		t.Fatalf("status after apply = %q, want own policy", line)
	}
	if got := runPolicy(t, n.apadmin, "", 0, "export", "--key", n.address).Stdout; got != own {
		t.Fatalf("export of the key's document is not the applied file:\n%s", got)
	}
	// The default no longer governs the only held key.
	defaultDoc := describedPolicy(runPolicy(t, n.apadmin, "", 0, "export").Stdout, "per-key default diff")
	if out := runPolicy(t, n.apadmin, defaultDoc, 0, "diff", "-").Stdout; !strings.Contains(out, "governs no held key") {
		t.Fatalf("diff of the default while every key has its own document:\n%s", out)
	}

	// Governed by its own document alone: the routed destination signs
	// without a prompt, anything else is a route miss.
	n.expectSigned(t, "routed payment under the own document", mustUnsignedPaymentTxnHex(t, n.sp, n.address, dest, 0, "per-key-own-routed"))
	n.expectRejected(t, mustUnsignedPaymentTxnHex(t, n.sp, n.address, integrationBurnAddress, 0, "per-key-own-miss"), policy.TransferRoutingRouteMissRuleID)

	// Removal returns the key to the default; the default itself stays.
	removed := runPolicy(t, n.apadmin, "", 0, "remove", "--yes", n.address).Stdout
	if !strings.Contains(removed, "policy of its own removed") {
		t.Fatalf("remove output:\n%s", removed)
	}
	if sha := policyStatusSHA(t, n.apadmin); sha == ownSHA {
		t.Fatal("remove did not change policy_set_sha256")
	}
	if line := n.statusLine(t); !strings.HasSuffix(line, "  default") {
		t.Fatalf("status after remove = %q, want the key back on the default", line)
	}
	if refused := runPolicy(t, n.apadmin, "", 2, "remove", "--yes", policy.DefaultKey); !strings.Contains(refused.Stderr, "cannot be removed") {
		t.Fatalf("remove default: %s", refused.Stderr)
	}
	n.expectSigned(t, "outbound payment back on the default", mustUnsignedPaymentTxnHex(t, n.sp, n.address, integrationBurnAddress, 0, "per-key-default-again"))
}

// Without user_auto_approve, a key on the shipped default prompts for an
// outbound payment; the foreign rekey rejection does not depend on the
// switch.
func TestPerKeyPolicyDefaultPromptsWithoutUserAutoApprove(t *testing.T) {
	n := newPerKeyPolicyNode(t, false)
	foreign := algocrypto.GenerateAccount().Address.String()
	closeTo := algocrypto.GenerateAccount().Address.String()
	n.expectPrompt(t, "outbound payment without user_auto_approve", mustUnsignedPaymentTxnHex(t, n.sp, n.address, integrationBurnAddress, 0, "per-key-prompt-outbound"))
	n.expectPrompt(t, "close-out without user_auto_approve", mustUnsignedPaymentTxnHexWithClose(t, n.sp, n.address, integrationBurnAddress, 0, "per-key-prompt-close", closeTo))
	n.expectRejected(t, mustUnsignedPaymentTxnHexWithRekey(t, n.sp, n.address, n.address, 0, "per-key-prompt-rekey", foreign), policy.RejectForeignRekeyRuleID)
}
