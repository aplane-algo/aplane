// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integration_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/merkleallowlist"
	"github.com/aplane-algo/aplane/internal/signerclient"
	utilkeys "github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	falcon1024 "github.com/aplane-algo/aplane/lsig/falcon1024"
	"github.com/aplane-algo/aplane/lsig/falcon1024/signerops"
	"github.com/aplane-algo/aplane/test/integration/harness"
)

type timelockRule struct {
	name     string
	policy   string
	maxItems int
	derived  string
	// authorTEAL, when set, runs after the framework's checks, and the stored
	// policy name gains _custom.
	authorTEAL string
}

// timelockRulesWithAuthorTEAL are the timelock policies followed by author
// TEAL that caps a spend at maxAmount microAlgos. The author's code can only
// reject what the framework's timelock and allowlist admitted.
func timelockRulesWithAuthorTEAL(maxAmount uint64) []timelockRule {
	rules := make([]timelockRule, 0, len(timelockRules))
	for _, rule := range timelockRules {
		rule.name += "-custom"
		rule.authorTEAL = fmt.Sprintf(`
template_variables: []

teal: |
  txn Amount
  pushint %d
  <=
  assert
`, maxAmount)
		rules = append(rules, rule)
	}
	return rules
}

// stored is the policy name the account's metadata records.
func (rule timelockRule) stored() string {
	if rule.authorTEAL != "" {
		return rule.policy + "_custom"
	}
	return rule.policy
}

var timelockRules = []timelockRule{
	{name: "plain", policy: boundedmeta.Layer3PolicyTimelock},
	{name: "inline", policy: boundedmeta.Layer3PolicyFixedAllowlistTimelock, maxItems: 30},
	{
		name: "merkle", policy: boundedmeta.Layer3PolicyMerkleAllowlistTimelock, maxItems: 65536,
		derived: `
  derived_args:
    - name: merkle_proof
      kind: merkle_allowlist_proof
      parameter: recipients
      max_size: 512`,
	},
}

func (rule timelockRule) hasList() bool {
	return rule.maxItems != 0
}

func (rule timelockRule) merkle() bool {
	return rule.derived != ""
}

func (rule timelockRule) keyType() string {
	return "test.timelock-rule-" + rule.name + ".v1"
}

// yaml refuses rekeys: a rekey never reaches Layer 3, so a spending-key rekey
// would leave the lock before the unlock round.
func (rule timelockRule) yaml() string {
	recipientsParameter, recipients := "", ""
	if rule.hasList() {
		recipientsParameter = "\n    recipients_parameter: recipients"
		recipients = fmt.Sprintf(`  - name: recipients
    type: address[]
    required: true
    min_items: 1
    max_items: %d
`, rule.maxItems)
	}
	return fmt.Sprintf(`schema_version: 2
derivation_version: 3
template_type: composed
base_key_type: aplane.falcon1024.v1
template_mode: strict
publisher: test
family: timelock-rule-%s
version: 1
display_name: "Timelock Rule %s"
max_opcode_cost: 20000

bounded:
  contract: %s
  spend_effects: [pay, axfer, asset_opt_in]
  max_fee: 10000
  rekey: %s
  layer3:
    policy: %s
    unlock_round_parameter: unlock_round%s%s

parameters:
  - name: unlock_round
    type: uint64
    required: true
    min: 1
%s%s`, rule.name, rule.name, boundedmeta.Contract, boundedmeta.RekeyRefused, rule.policy, recipientsParameter, rule.derived, recipients, rule.authorTEAL)
}

type timelockAccount struct {
	boundedExecutionAccount
	rule       timelockRule
	recipients string
}

func newTimelockAccount(t *testing.T, network *harness.TestnetConfig, rule timelockRule, unlockRound uint64, recipients ...string) timelockAccount {
	t.Helper()
	falcon1024.RegisterClient()
	spec, err := composeddsa.ParseTemplateSpec([]byte(rule.yaml()))
	if err != nil {
		t.Fatalf("parse template: %v", err)
	}
	provider, err := composeddsa.NewProviderFromTemplateSpec(spec)
	if err != nil {
		t.Fatalf("build provider: %v", err)
	}
	provider.SetAlgodClient(network.Client)
	ops := signerops.New(nil)
	publicKey, privateKey, err := ops.GenerateKeypair(randomFalconSeed(t))
	if err != nil {
		t.Fatalf("generate spending key: %v", err)
	}
	params := map[string]string{"unlock_round": fmt.Sprint(unlockRound)}
	list := strings.Join(recipients, ",")
	if rule.hasList() {
		params["recipients"] = list
	}
	derived, err := provider.DeriveLsigWithSalt(context.Background(), publicKey, params)
	if err != nil {
		t.Fatalf("derive LogicSig: %v", err)
	}
	metadata, err := provider.BuildBoundedAuthorizationMetadata(publicKey, params, derived.Bytecode)
	if err != nil {
		t.Fatalf("build metadata: %v", err)
	}
	if metadata.Layer3Policy != rule.stored() || !metadata.RefusesRekeys() {
		t.Fatalf("layer3_policy = %q, rekey = %q; want %q, refused", metadata.Layer3Policy, metadata.Rekey, rule.stored())
	}
	return timelockAccount{
		boundedExecutionAccount: boundedExecutionAccount{
			address: derived.Address.String(), bytecode: append([]byte(nil), derived.Bytecode...),
			spendingPublicKey: publicKey, spendingPrivateKey: privateKey,
			provider: provider, metadata: metadata,
		},
		rule: rule, recipients: list,
	}
}

// args fills the Merkle slot. An empty proof is what a signer sends for a
// self-receiver, and a program with no list has no slot to fill.
func (account timelockAccount) args(t *testing.T, proofFor string) [][]byte {
	t.Helper()
	if !account.rule.merkle() {
		return nil
	}
	if proofFor == "" {
		return [][]byte{{}}
	}
	proof, err := merkleallowlist.ProofForAddressParam(account.recipients, mustAddress(t, proofFor))
	if err != nil {
		t.Fatalf("build Merkle proof: %v", err)
	}
	return [][]byte{proof}
}

// payment backdates FirstValid, which lets a test sit exactly on the unlock
// boundary without waiting for rounds. Every round it uses is already past.
func (account timelockAccount) payment(t *testing.T, network *harness.TestnetConfig, to, note string, firstValid uint64) types.Transaction {
	t.Helper()
	txn := boundedPaymentTxn(t, mustSuggestedParams(t, network), account.address, to, 1_000, note)
	txn.FirstValid = types.Round(firstValid)
	txn.LastValid = types.Round(firstValid + 900)
	return txn
}

func (account timelockAccount) rekey(t *testing.T, network *harness.TestnetConfig, note string, firstValid uint64) types.Transaction {
	t.Helper()
	txn := account.payment(t, network, account.address, note, firstValid)
	txn.Amount = 0
	txn.RekeyTo = algocrypto.GenerateAccount().Address
	return txn
}

func (account timelockAccount) submit(t *testing.T, network *harness.TestnetConfig, txn types.Transaction, args [][]byte, accept bool) {
	t.Helper()
	signed, txid := account.signedGroupWithLayer3Args(t, txn, args)
	raw := make([]byte, 0)
	for _, stxn := range signed {
		raw = append(raw, msgpack.Encode(stxn)...)
	}
	if accept {
		submitCorridorGroupExpectSuccess(t, network, raw, txid)
	} else {
		submitCorridorGroupExpectFailure(t, network, raw)
	}
}

func timelockNetwork(t *testing.T) (*harness.TestnetConfig, *harness.FundTestAccount, uint64) {
	t.Helper()
	if harness.IntegrationNetwork() != harness.IntegrationNetworkLocalnet {
		t.Skip("bounded LogicSig execution requires localnet")
	}
	network, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("connect to localnet: %v", err)
	}
	funder, err := harness.NewFundTestAccount(network.Client)
	if err != nil {
		t.Fatalf("load funding account: %v", err)
	}
	status, err := network.Client.Status().Do(context.Background())
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	if status.LastRound < 2 {
		t.Skip("localnet needs at least two rounds to backdate FirstValid")
	}
	return network, funder, status.LastRound
}

// These transactions go straight to the network, so each rejection is the
// program's, not the signer refusing to build the request. A rekey carries only
// the spending signature: the account has no rekey path, so it fails on either
// side of the unlock round.
func TestBoundedTimelockPoliciesOnChainLocalnet(t *testing.T) {
	network, funder, unlockRound := timelockNetwork(t)
	before, at, after := unlockRound-1, unlockRound, unlockRound+1

	for _, rule := range timelockRules {
		t.Run(rule.name, func(t *testing.T) {
			allowed := funder.GetAddress()
			second := algocrypto.GenerateAccount().Address.String()
			account := newTimelockAccount(t, network, rule, unlockRound, allowed, second)
			if err := funder.FundMicroAlgosAndWait(account.address, 2_000_000); err != nil {
				t.Fatalf("fund account: %v", err)
			}
			outsider := algocrypto.GenerateAccount().Address.String()
			if err := funder.FundMicroAlgosAndWait(outsider, 200_000); err != nil {
				t.Fatalf("fund outsider: %v", err)
			}

			for _, test := range []struct {
				name   string
				txn    types.Transaction
				args   [][]byte
				accept bool
				merkle bool
			}{
				{name: "allowed recipient one round early", txn: account.payment(t, network, allowed, "a", before), args: account.args(t, allowed)},
				{name: "self recipient one round early", txn: account.payment(t, network, account.address, "b", before), args: account.args(t, "")},
				{name: "rekey one round early", txn: account.rekey(t, network, "c", before)},
				{name: "allowed recipient at the unlock round", txn: account.payment(t, network, allowed, "d", at), args: account.args(t, allowed), accept: true},
				{name: "allowed recipient after the unlock round", txn: account.payment(t, network, allowed, "e", after), args: account.args(t, allowed), accept: true},
				{name: "self recipient at the unlock round", txn: account.payment(t, network, account.address, "f", at), args: account.args(t, ""), accept: true},
				{name: "outsider after the unlock round", txn: account.payment(t, network, outsider, "g", after), args: account.args(t, allowed), accept: !rule.hasList()},
				{name: "allowed recipient without proof", txn: account.payment(t, network, allowed, "h", after), args: account.args(t, ""), merkle: true},
				{name: "rekey at the unlock round", txn: account.rekey(t, network, "i", at)},
				{name: "rekey after the unlock round", txn: account.rekey(t, network, "j", after)},
			} {
				if test.merkle && !rule.merkle() {
					continue
				}
				t.Run(test.name, func(t *testing.T) {
					account.submit(t, network, test.txn, test.args, test.accept)
				})
			}
		})
	}
}

// A timelock followed by author TEAL, on chain. The framework's checks run
// first, the timelock and then any allowlist, and the author's code runs after
// them: here it caps a spend at 1,000 microAlgos. Each layer rejects by
// itself, and a spend passes only when all three do.
func TestBoundedTimelockWithAuthorTEALOnChainLocalnet(t *testing.T) {
	network, funder, unlockRound := timelockNetwork(t)
	before, at, after := unlockRound-1, unlockRound, unlockRound+1

	for _, rule := range timelockRulesWithAuthorTEAL(1_000) {
		t.Run(rule.name, func(t *testing.T) {
			allowed := funder.GetAddress()
			second := algocrypto.GenerateAccount().Address.String()
			account := newTimelockAccount(t, network, rule, unlockRound, allowed, second)
			if err := funder.FundMicroAlgosAndWait(account.address, 2_000_000); err != nil {
				t.Fatalf("fund account: %v", err)
			}
			outsider := algocrypto.GenerateAccount().Address.String()
			if err := funder.FundMicroAlgosAndWait(outsider, 200_000); err != nil {
				t.Fatalf("fund outsider: %v", err)
			}
			// payment sends 1,000 microAlgos, the author's cap; over raises it.
			over := func(txn types.Transaction) types.Transaction {
				txn.Amount = 1_001
				return txn
			}

			for _, test := range []struct {
				name   string
				txn    types.Transaction
				args   [][]byte
				accept bool
			}{
				{name: "within the cap, one round early: the timelock rejects", txn: account.payment(t, network, allowed, "a", before), args: account.args(t, allowed)},
				{name: "within the cap, at the unlock round", txn: account.payment(t, network, allowed, "b", at), args: account.args(t, allowed), accept: true},
				{name: "within the cap, after the unlock round", txn: account.payment(t, network, allowed, "c", after), args: account.args(t, allowed), accept: true},
				{name: "over the cap, after the unlock round: the author's code rejects", txn: over(account.payment(t, network, allowed, "d", after)), args: account.args(t, allowed)},
				{name: "within the cap to an outsider, after the unlock round", txn: account.payment(t, network, outsider, "e", after), args: account.args(t, allowed), accept: !rule.hasList()},
				{name: "rekey after the unlock round", txn: account.rekey(t, network, "f", after)},
			} {
				t.Run(test.name, func(t *testing.T) {
					account.submit(t, network, test.txn, test.args, test.accept)
				})
			}
		})
	}
}

// This is the same rule through the signer: it fills the Merkle slot itself, and
// stored metadata must survive a rescan. A locked account must move no funds, and
// an unlocked one still cannot be rekeyed.
func TestBoundedTimelockThroughSigner(t *testing.T) {
	if os.Getenv("TEST_FUNDING_MNEMONIC") == "" {
		t.Skip("TEST_FUNDING_MNEMONIC not set, skipping funding-backed test")
	}
	lockOnDisconnect := false
	harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{LockOnDisconnect: &lockOnDisconnect})
	network, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("connect to network: %v", err)
	}
	funder, err := harness.NewFundTestAccount(network.Client)
	if err != nil {
		t.Fatalf("load funding account: %v", err)
	}
	status, err := network.Client.Status().Do(context.Background())
	if err != nil {
		t.Fatalf("read status: %v", err)
	}

	signerd := harness.NewSignerHarness(t)
	workDir := signerd.GetWorkDir()
	paths := utilkeys.NewPaths(workDir)
	if err := os.MkdirAll(paths.TemplateLibraryDir(), 0o755); err != nil {
		t.Fatalf("create template library: %v", err)
	}
	installer := harness.NewApAdminHarness(t, workDir)
	t.Cleanup(installer.Cleanup)
	// The same rules again with author TEAL that caps a spend at 0.1 ALGO, the
	// amount this test sends: the stored policy gains _custom and must be
	// generated, signed for and rescanned like the plain ones.
	rules := append(append([]timelockRule(nil), timelockRules...), timelockRulesWithAuthorTEAL(100_000)...)
	for _, rule := range rules {
		templatePath := filepath.Join(paths.TemplateLibraryDir(), rule.keyType()+".yaml")
		yaml := rule.yaml()
		if err := os.WriteFile(templatePath, []byte(yaml), 0o644); err != nil {
			t.Fatalf("write template: %v", err)
		}
		mustImportTemplateViaApadmin(t, workDir, installer, templatePath, rule.keyType())
	}
	if err := signerd.Start(); err != nil {
		t.Fatalf("start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })
	apadmin := harness.NewApAdminHarness(t, workDir)
	t.Cleanup(apadmin.Cleanup)
	if err := apadmin.UnlockSigner(); err != nil {
		t.Fatalf("unlock signer: %v", err)
	}
	client := signerclient.NewSignerClient(signerd.GetURL())
	apshell := harness.NewApshellHarness(t)
	accounts := make(map[string]string, 2*len(rules))

	for _, rule := range rules {
		t.Run(rule.name, func(t *testing.T) {
			allowed := algocrypto.GenerateAccount().Address.String()
			if err := funder.FundMicroAlgosAndWait(allowed, 200_000); err != nil {
				t.Fatalf("fund recipient: %v", err)
			}
			generate := func(unlockRound uint64) string {
				params := map[string]string{"unlock_round": fmt.Sprint(unlockRound)}
				if rule.hasList() {
					params["recipients"] = allowed + "," + algocrypto.GenerateAccount().Address.String()
				}
				// The account must outlive this subtest for the rescan check below.
				account := mustAdminGenerateKeyNoCleanup(t, client, signerd, rule.keyType(), params)
				if err := funder.FundMicroAlgosAndWait(account, 2_000_000); err != nil {
					t.Fatalf("fund account: %v", err)
				}
				assertAuthorAllowlistInventory(t, client, account, rule.stored())
				accounts[account] = rule.stored()
				return account
			}
			balance := func(account string) uint64 {
				info, err := network.Client.AccountInformation(account).Do(context.Background())
				if err != nil {
					t.Fatalf("read balance: %v", err)
				}
				return info.Amount
			}
			sendAmount := func(amount, account, to string) string {
				output, err := apshell.RunWithInput(fmt.Sprintf("send %s algo from %s to %s\nquit\n", amount, account, to))
				if err != nil {
					t.Fatalf("run apshell: %v\n%s", err, output)
				}
				return output
			}
			send := func(account, to string) string { return sendAmount("0.1", account, to) }
			refusedAmount := func(name, amount, account, to string) {
				t.Helper()
				before := balance(account)
				output := sendAmount(amount, account, to)
				if after := balance(account); after != before {
					t.Fatalf("%s moved funds: %d to %d\n%s", name, before, after, output)
				}
				if strings.Contains(strings.ToLower(output), "confirmed") {
					t.Fatalf("%s reported confirmation:\n%s", name, output)
				}
			}
			refused := func(name, account, to string) {
				t.Helper()
				refusedAmount(name, "0.1", account, to)
			}

			refused("locked account", generate(status.LastRound+1_000_000), allowed)

			open := generate(status.LastRound)
			if rule.hasList() {
				refused("outsider", open, algocrypto.GenerateAccount().Address.String())
			}
			if rule.authorTEAL != "" {
				// Unlocked and to an allowed recipient, but over the author's cap.
				refusedAmount("spend over the author's cap", "0.2", open, allowed)
			}
			output := send(open, allowed)
			if _, err := network.WaitForConfirmation(mustExtractTxID(t, output), 10); err != nil {
				t.Fatalf("payment failed to confirm: %v\n%s", err, output)
			}
			if received := balance(allowed); received != 300_000 {
				t.Fatalf("recipient holds %d, want 300000", received)
			}
			// Reaching the unlock round opens a spend path, not a rekey path.
			assertSignerRefusesRekey(t, apshell, network, open, algocrypto.GenerateAccount().Address.String(),
				boundedmeta.Contract+" account permanently disables rekey")
		})
	}

	// A restart rescans the key files, so the stored policy must load and survive.
	if err := signerd.Stop(); err != nil {
		t.Fatalf("stop signer: %v", err)
	}
	if err := signerd.Start(); err != nil {
		t.Fatalf("restart signer: %v", err)
	}
	if err := apadmin.UnlockSigner(); err != nil {
		t.Fatalf("unlock signer: %v", err)
	}
	client = signerclient.NewSignerClient(signerd.GetURL())
	for account, policy := range accounts {
		if !waitForKey(t, signerd.GetURL(), account, 10*time.Second) {
			t.Fatalf("signer did not rescan %s", account)
		}
		assertAuthorAllowlistInventory(t, client, account, policy)
	}
}
