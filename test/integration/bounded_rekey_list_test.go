// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integration_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"

	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policy/policytest"
	"github.com/aplane-algo/aplane/internal/rotatingkey"
	"github.com/aplane-algo/aplane/internal/signerclient"
	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"
	"github.com/aplane-algo/aplane/lsig/plainhost"
	"github.com/aplane-algo/aplane/test/integration/harness"
)

// onlyTheseNode is a signer with an apshell, for accounts the signer generates
// and signs for as an operator would use them.
type onlyTheseNode struct {
	signerd *harness.SignerHarness
	apadmin *harness.ApAdminHarness
	client  *signerclient.Client
	apshell *harness.ApshellHarness
	network *harness.TestnetConfig
	funder  *harness.FundTestAccount
}

func newOnlyTheseNode(t *testing.T, userAutoApprove bool) *onlyTheseNode {
	t.Helper()
	if os.Getenv("TEST_FUNDING_MNEMONIC") == "" {
		t.Skip("TEST_FUNDING_MNEMONIC not set, skipping funding-backed test")
	}
	lockOnDisconnect := false
	harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{LockOnDisconnect: &lockOnDisconnect, UserAutoApprove: &userAutoApprove})
	network, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("connect to network: %v", err)
	}
	funder, err := harness.NewFundTestAccount(network.Client)
	if err != nil {
		t.Fatalf("load funding account: %v", err)
	}
	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })
	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	t.Cleanup(apadmin.Cleanup)
	if err := apadmin.UnlockSigner(); err != nil {
		t.Fatalf("unlock signer: %v", err)
	}
	return &onlyTheseNode{
		signerd: signerd, apadmin: apadmin, client: signerclient.NewSignerClient(signerd.GetURL()),
		apshell: harness.NewApshellHarness(t), network: network, funder: funder,
	}
}

// key generates and funds a key of keyType held by this node.
func (n *onlyTheseNode) key(t *testing.T, keyType string, params map[string]string, funding uint64) string {
	t.Helper()
	address := mustAdminGenerateKeyNoCleanup(t, n.client, n.signerd, keyType, params)
	if funding > 0 {
		if err := n.funder.FundMicroAlgosAndWait(address, funding); err != nil {
			t.Fatalf("fund %s: %v", address, err)
		}
	}
	return address
}

// onlyThese generates allowlist-lock as the Falcon plain host's bounds offer it:
// payments to the funder only, and a rekey only to a listed address.
func (n *onlyTheseNode) onlyThese(t *testing.T, rekeyTo ...string) string {
	t.Helper()
	return n.key(t, plainFalconKeyType, map[string]string{
		plainhost.ParameterSpendEffects:   "pay",
		plainhost.ParameterRecipients:     n.funder.GetAddress(),
		plainhost.ParameterRekeyAuthority: plainhost.RekeyOnlyThese,
		plainhost.ParameterRekeyTo:        strings.Join(rekeyTo, ","),
	}, 1_000_000)
}

// setRekeys replaces the node default's rekeys setting.
func (n *onlyTheseNode) setRekeys(t *testing.T, value policy.SignerRekeys) {
	t.Helper()
	ipc := mustConnectIPCClient(t, n.signerd.GetWorkDir())
	defer ipc.Close()
	mustReplaceIPCPolicySetting(t, ipc, "rekeys", string(value))
}

// rekey hands account to target through apshell and waits for the network.
func (n *onlyTheseNode) rekey(t *testing.T, account, target string) {
	t.Helper()
	txid, err := n.apshell.RekeyAccount(account, target)
	if err != nil {
		t.Fatalf("rekey %s to %s: %v", account, target, err)
	}
	if _, err := n.network.WaitForConfirmation(txid, 10); err != nil {
		t.Fatalf("rekey %s to %s did not confirm: %v", account, target, err)
	}
	if got := authAddress(t, n.network, account); got != target {
		t.Fatalf("%s authorizer = %q after the rekey, want %s", account, got, target)
	}
}

// send pays 0.01 ALGO from account through apshell and waits for the network.
func (n *onlyTheseNode) send(t *testing.T, account, to string) {
	t.Helper()
	txid, err := n.apshell.SendTransaction(account, to, 0.01)
	if err != nil {
		t.Fatalf("send from %s: %v", account, err)
	}
	if _, err := n.network.WaitForConfirmation(txid, 10); err != nil {
		t.Fatalf("send from %s did not confirm: %v", account, err)
	}
}

// Allowlist-lock's guarantee as a bounded only-these account: the signer refuses
// an unlisted rekey, and a listed one confirms with the spending key alone. A
// post-quantum account hands over to a native Falcon key, which then signs for
// it, including its onward rekey.
func TestBoundedOnlyTheseHandoverThroughSigner(t *testing.T) {
	n := newOnlyTheseNode(t, true)
	// The test environment's default allows every rekey; the shipped default is
	// the one whose declared targets the list extends.
	n.setRekeys(t, policy.RekeysRejectForeign)

	falcon := n.key(t, nativefalcon.KeyType, nil, 0)
	onward := n.key(t, "ed25519", nil, 0)
	unheld := algocrypto.GenerateAccount()
	account := n.onlyThese(t, falcon, unheld.Address.String())

	assertSignerRefusesRekey(t, n.apshell, n.network, account, algocrypto.GenerateAccount().Address.String(),
		"is not on this account's rekey-to list")
	n.rekey(t, account, falcon)
	// The account now signs through the listed key, under no boundary.
	n.send(t, account, n.funder.GetAddress())
	n.rekey(t, account, onward)
	txid, err := n.apshell.CloseAccount(account, n.funder.GetAddress())
	if err != nil {
		t.Fatalf("close %s: %v", account, err)
	}
	if _, err := n.network.WaitForConfirmation(txid, 10); err != nil {
		t.Fatalf("close %s did not confirm: %v", account, err)
	}
}

// Under reject_foreign_rekey, a listed target is declared even when this node
// does not hold it; an unlisted, unheld target is refused by policy.
func TestRejectForeignRekeyTakesListedTargets(t *testing.T) {
	n := newOnlyTheseNode(t, true)
	n.setRekeys(t, policy.RekeysRejectForeign)

	unheld := algocrypto.GenerateAccount()
	listed := n.onlyThese(t, unheld.Address.String())
	n.rekey(t, listed, unheld.Address.String())
	bestEffortCloseRekeyedAccount(t, n.network, listed, n.funder.GetAddress(), unheld.PrivateKey)

	// With no list, the same unheld target is foreign.
	spending := n.key(t, plainFalconKeyType, map[string]string{
		plainhost.ParameterSpendEffects:   "pay",
		plainhost.ParameterRecipients:     n.funder.GetAddress(),
		plainhost.ParameterRekeyAuthority: plainhost.RekeySpendingKey,
	}, 1_000_000)
	assertSignerRefusesRekey(t, n.apshell, n.network, spending, unheld.Address.String(), policy.RejectForeignRekeyRuleID)
}

// Under reject_all_rekeys a key signs no rekey on any path, listed or held,
// while a rotating account's own stage rekeys still let it spend. Under
// allow_rekeys, a rekey to a foreign target goes on to review, which
// user_auto_approve satisfies.
func TestRekeysSettingOnChain(t *testing.T) {
	n := newOnlyTheseNode(t, true)
	if err := n.apadmin.ActivateKeyType(rotatingkey.RotatingTripleXmssV1); err != nil {
		t.Fatalf("activate %s: %v", rotatingkey.RotatingTripleXmssV1, err)
	}
	networkName := harness.IntegrationNetwork()
	if networkName == "" {
		networkName = n.network.GenesisHash
	}
	rotating := n.key(t, rotatingkey.RotatingTripleXmssV1, map[string]string{"network": networkName}, 500_000)
	held := n.key(t, "ed25519", nil, 300_000)
	heldTarget := n.key(t, "ed25519", nil, 0)
	unheld := algocrypto.GenerateAccount()
	listed := n.onlyThese(t, unheld.Address.String())

	n.setRekeys(t, policy.RekeysRejectAll)
	assertSignerRefusesRekey(t, n.apshell, n.network, listed, unheld.Address.String(), policy.RejectAllRekeysRuleID)
	assertSignerRefusesRekey(t, n.apshell, n.network, held, heldTarget, policy.RejectAllRekeysRuleID)
	stage := authAddress(t, n.network, rotating)
	n.send(t, rotating, n.funder.GetAddress())
	if next := authAddress(t, n.network, rotating); next == "" || next == stage {
		t.Fatalf("the rotating account's authorizer did not move: %q to %q", stage, next)
	}

	n.setRekeys(t, policy.RekeysAllow)
	foreign := algocrypto.GenerateAccount()
	n.rekey(t, held, foreign.Address.String())
	bestEffortCloseRekeyedAccount(t, n.network, held, n.funder.GetAddress(), foreign.PrivateKey)
	n.rekey(t, listed, unheld.Address.String())
	bestEffortCloseRekeyedAccount(t, n.network, listed, n.funder.GetAddress(), unheld.PrivateKey)
}

// Without user_auto_approve, allow_rekeys sends a rekey to the operator, and the
// self no-op rule, which approves a 0-ALGO self-payment, never approves one,
// listed or not. With no route and no warning review, the operator default is
// what the no-op rule would otherwise satisfy.
func TestRekeyReachesReviewWithoutUserAutoApprove(t *testing.T) {
	n := newPerKeyPolicyNode(t, false)
	foreign := algocrypto.GenerateAccount().Address.String()
	own := policytest.Signer(t, n.address, `{
  "rekeys": "allow_rekeys",
  "auto_approve_self_noop_transfer": true,
  "transfer_policy": {"on_no_route": "operator_default"}
}`)
	ownPath := filepath.Join(t.TempDir(), "own.json")
	if err := os.WriteFile(ownPath, []byte(own), 0o600); err != nil {
		t.Fatal(err)
	}
	runPolicy(t, n.apadmin, "", 0, "apply", "--yes", ownPath)
	// The rule takes no note, so these two differ only in the rekey.
	n.expectSigned(t, "a self no-op", mustUnsignedPaymentTxnHex(t, n.sp, n.address, n.address, 0, ""))
	n.expectPrompt(t, "an allowed rekey", mustUnsignedPaymentTxnHexWithRekey(t, n.sp, n.address, n.address, 0, "", foreign))

	// A listed rekey of a bounded account is reviewed as every bounded rekey is.
	client := signerclient.NewSignerClient(n.signerd.GetURL())
	funder, err := harness.NewFundTestAccount(mustTestnet(t).Client)
	if err != nil {
		t.Fatalf("load funding account: %v", err)
	}
	unheld := algocrypto.GenerateAccount().Address.String()
	listed := mustAdminGenerateKeyNoCleanup(t, client, n.signerd, plainFalconKeyType, map[string]string{
		plainhost.ParameterSpendEffects:   "pay",
		plainhost.ParameterRecipients:     funder.GetAddress(),
		plainhost.ParameterRekeyAuthority: plainhost.RekeyOnlyThese,
		plainhost.ParameterRekeyTo:        unheld,
	})
	if err := funder.FundMicroAlgosAndWait(listed, 1_000_000); err != nil {
		t.Fatalf("fund %s: %v", listed, err)
	}
	listedDoc := policytest.Signer(t, listed, `{
  "rekeys": "reject_foreign_rekey",
  "auto_approve_self_noop_transfer": true,
  "transfer_policy": {"on_no_route": "operator_default"}
}`)
	listedPath := filepath.Join(t.TempDir(), "listed.json")
	if err := os.WriteFile(listedPath, []byte(listedDoc), 0o600); err != nil {
		t.Fatal(err)
	}
	runPolicy(t, n.apadmin, "", 0, "apply", "--yes", listedPath)
	apshell := harness.NewApshellHarness(t)
	output, _ := apshell.RunWithInput(fmt.Sprintf("rekey %s to %s\nquit\n", listed, unheld))
	if !strings.Contains(output, "no apadmin connected") || strings.Contains(strings.ToLower(output), "rekey transaction submitted:") {
		t.Fatalf("a listed rekey did not wait for the operator:\n%s", output)
	}
	if got := authAddress(t, mustTestnet(t), listed); got != "" {
		t.Fatalf("%s was rekeyed to %s without review", listed, got)
	}
}

func mustTestnet(t *testing.T) *harness.TestnetConfig {
	t.Helper()
	network, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("connect to network: %v", err)
	}
	return network
}
