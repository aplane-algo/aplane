// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integration_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/transaction"

	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"
	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/pkg/signerapi"
	"github.com/aplane-algo/aplane/test/integration/harness"
)

// LogicSig arguments given once for a command go, by name, only to the
// positions whose signing key declares them: these tests run that on the
// network, with hashlock accounts (a generic LogicSig that pays out when its
// one runtime argument hashes to the stored hash) and native ed25519 accounts,
// which take no arguments and whose signer refuses any sent for them.

// lsigArgRoutingEnv is a signer with a hashlock template per argument name,
// unlocked, with apshell and a funding account on the integration network.
type lsigArgRoutingEnv struct {
	testnet  *harness.TestnetConfig
	funder   *harness.FundTestAccount
	signerd  *harness.SignerHarness
	apadmin  *harness.ApAdminHarness
	apshell  *harness.ApshellHarness
	keyTypes map[string]string // argument name -> hashlock key type taking it
}

func setupLsigArgRoutingEnv(t *testing.T, argNames ...string) *lsigArgRoutingEnv {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping LogicSig argument routing integration test in short mode")
	}
	if os.Getenv("TEST_FUNDING_MNEMONIC") == "" {
		t.Skip("TEST_FUNDING_MNEMONIC not set, skipping funding-backed LogicSig argument routing test")
	}
	lockOnDisconnect := false
	clone := harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{LockOnDisconnect: &lockOnDisconnect})
	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("failed to connect to the integration network: %v", err)
	}
	funder, err := harness.NewFundTestAccount(testnet.Client)
	if err != nil {
		t.Fatalf("failed to load funding account: %v", err)
	}

	env := &lsigArgRoutingEnv{testnet: testnet, funder: funder, keyTypes: map[string]string{}}
	t.Setenv("APSIGNER_PASSPHRASE", mustReadPassphrase(t, clone.SignerDataDir))
	env.apadmin = harness.NewApAdminHarness(t, clone.SignerDataDir)
	for _, name := range argNames {
		family := fmt.Sprintf("integration-hashlock-%s-%d", strings.ReplaceAll(name, "_", "-"), time.Now().UnixNano())
		mustImportTemplateViaApadmin(t, clone.SignerDataDir, env.apadmin, writeHashlockTemplate(t, family, name), "hashlock "+name)
		env.keyTypes[name] = integrationTemplateKeyType(family)
	}

	env.signerd = harness.NewSignerHarness(t)
	if err := env.signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = env.signerd.Stop() })
	t.Cleanup(env.apadmin.Cleanup)
	if err := env.apadmin.UnlockSigner(); err != nil {
		t.Fatalf("failed to unlock signer: %v", err)
	}
	env.apshell = harness.NewApshellHarness(t)
	return env
}

// writeHashlockTemplate writes a generic template whose account pays (no
// close-out, no rekey, a capped fee) when its runtime argument argName
// hashes to its hash parameter.
func writeHashlockTemplate(t *testing.T, family, argName string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), family+".yaml")
	yaml := fmt.Sprintf(`schema_version: 1
derivation_version: 3
template_type: generic
template_mode: generated
publisher: %s
family: %s
version: 1
display_name: "Integration Hashlock (%s)"
description: "Integration test template: pays when its runtime argument %s hashes to the stored hash"
max_opcode_cost: 20000
valid_rekey_target: false

parameters:
  - name: hash
    label: "Hash (SHA256)"
    description: "SHA256 hash of the secret (64 hex characters)"
    type: bytes
    required: true
    max_length: 64
    example: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

runtime_args:
  - name: %s
    label: "Secret"
    description: "The value that hashes to the stored hash, up to 64 bytes"
    type: bytes
    required: true
    max_size: 64

teal: |
  #pragma version 13

  txn Fee
  int 100000
  <=
  assert

  txn RekeyTo
  global ZeroAddress
  ==
  assert

  txn CloseRemainderTo
  global ZeroAddress
  ==
  assert

  txn TypeEnum
  int pay
  ==
  assert

  arg 0
  sha256
  byte @hash
  ==
`, integrationTemplatePublisher, family, argName, argName, argName)
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("failed to write hashlock template: %v", err)
	}
	return path
}

// newHashlock generates and funds a hashlock account of the key type that
// takes argName, unlocked by secret.
func (env *lsigArgRoutingEnv) newHashlock(t *testing.T, argName, secret string, funding uint64) string {
	t.Helper()
	digest := sha256.Sum256([]byte(secret))
	address, err := env.apadmin.GenerateKeyWithTypeAndParams(env.keyTypes[argName], map[string]string{"hash": hex.EncodeToString(digest[:])})
	if err != nil {
		t.Fatalf("failed to generate hashlock (%s): %v", argName, err)
	}
	env.waitAndFund(t, address, funding)
	return address
}

// newNative generates and funds an ed25519 account.
func (env *lsigArgRoutingEnv) newNative(t *testing.T, funding uint64) string {
	t.Helper()
	address, err := env.apadmin.GenerateKeyWithType("ed25519")
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}
	env.waitAndFund(t, address, funding)
	return address
}

func (env *lsigArgRoutingEnv) waitAndFund(t *testing.T, address string, funding uint64) {
	t.Helper()
	if !waitForKey(t, env.signerd.GetURL(), address, 15*time.Second) {
		t.Fatalf("signer did not load key %s", address)
	}
	if err := env.funder.FundMicroAlgosAndWait(address, funding); err != nil {
		t.Fatalf("failed to fund %s: %v", address, err)
	}
}

func (env *lsigArgRoutingEnv) balance(t *testing.T, address string) uint64 {
	t.Helper()
	amount, err := env.testnet.GetAccountInfo(address)
	if err != nil {
		t.Fatalf("failed to read the balance of %s: %v", address, err)
	}
	return amount
}

// sweep over a set of a native account and a hashlock account with
// arg:preimage: the hashlock is sent the preimage and pays, the native account
// is sent nothing, which its signer would refuse, and is swept too. A name no
// account in the set declares is refused before anything is sent.
func TestSweepOverNativeAndHashlockAccountsPlacesThePreimage(t *testing.T) {
	env := setupLsigArgRoutingEnv(t, "preimage")
	const preimage = "integration-sweep-preimage"
	const funding = 1_000_000
	native := env.newNative(t, funding)
	hashlock := env.newHashlock(t, "preimage", preimage, funding)
	destination := env.funder.GetAddress()

	// A typo is refused up front: nothing moves.
	output, _ := env.apshell.RunWithInput(fmt.Sprintf(
		"sets mixedtypo %s %s\nsweep algo from @mixedtypo to %s arg:premage=text:%s\nquit\n", native, hashlock, destination, preimage))
	if !strings.Contains(output, `no signing key here declares the LogicSig argument "premage"`) {
		t.Fatalf("sweep with a misspelled argument name was not refused by name:\n%s", output)
	}
	if got := env.balance(t, native); got != funding {
		t.Fatalf("native balance after the refused sweep = %d, want %d", got, funding)
	}
	if got := env.balance(t, hashlock); got != funding {
		t.Fatalf("hashlock balance after the refused sweep = %d, want %d", got, funding)
	}

	output, err := env.apshell.RunWithInput(fmt.Sprintf(
		"sets mixed %s %s\nsweep algo from @mixed to %s arg:preimage=text:%s\nquit\n", native, hashlock, destination, preimage))
	if err != nil {
		t.Fatalf("sweep failed: %v\n%s", err, output)
	}
	if !strings.Contains(output, "Sweep complete: 2 succeeded, 0 failed") {
		t.Fatalf("sweep did not sign and confirm both accounts:\n%s", output)
	}
	// The native account is left its minimum balance, 100000 microAlgos for a
	// bare account; the hashlock at least that, and what its fee reserve left.
	if got := env.balance(t, native); got != 100_000 {
		t.Fatalf("native balance after the sweep = %d, want 100000\n%s", got, output)
	}
	if got := env.balance(t, hashlock); got < 100_000 || got > funding/2 {
		t.Fatalf("hashlock balance after the sweep = %d, want it swept to near its minimum balance\n%s", got, output)
	}

	// The signer's half: lsig_args sent for a native key are refused with a
	// bad request, before planning or approval.
	params, err := env.testnet.GetSuggestedParams()
	if err != nil {
		t.Fatalf("failed to get suggested params: %v", err)
	}
	txn, err := transaction.MakePaymentTxn(native, native, 0, []byte("native-lsig-args"), "", params)
	if err != nil {
		t.Fatalf("failed to build payment: %v", err)
	}
	_, err = signerclient.NewSignerClient(env.signerd.GetURL()).RequestGroupSign([]signerapi.SignRequest{{
		AuthAddress: native, TxnSender: native,
		TxnBytesHex: hex.EncodeToString(append([]byte("TX"), msgpack.Encode(txn)...)),
		LsigArgs:    map[string]string{"preimage": hex.EncodeToString([]byte(preimage))},
	}})
	var status *signerclient.HTTPStatusError
	if !errors.As(err, &status) || status.StatusCode != http.StatusBadRequest ||
		!strings.Contains(status.Message, "is native and takes no LogicSig arguments") {
		t.Fatalf("/sign with lsig_args for a native key: error = %v, want a 400 refusal", err)
	}
}

// A plugin group, in the default flow, with two hashlock accounts whose keys
// take differently named arguments, and a native account: each position is
// sent only its own key's argument, so the group signs and confirms. Before,
// every position got every argument, and each hashlock refused the other's.
func TestPluginGroupWithTwoLogicSigTypesPlacesEachArgument(t *testing.T) {
	env := setupLsigArgRoutingEnv(t, "preimage", "secret")
	const preimage, secret = "integration-plugin-preimage", "integration-plugin-secret"
	const funding = 1_000_000
	first := env.newHashlock(t, "preimage", preimage, funding)
	second := env.newHashlock(t, "secret", secret, funding)
	native := env.newNative(t, funding)
	destination := env.funder.GetAddress()

	eng, err := engine.NewEngine(env.testnet.Network, engine.WithAlgodClient(env.testnet.Client))
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	eng.Connection.SignerClient = signerclient.NewSignerClient(env.signerd.GetURL())
	app := apshellapp.New(eng, config.DefaultConfig(), t.TempDir())
	ctx := context.Background()

	params, err := env.testnet.GetSuggestedParams()
	if err != nil {
		t.Fatalf("failed to get suggested params: %v", err)
	}
	senders := []string{first, second, native}
	intents := make([]jsonrpc.TransactionIntent, len(senders))
	for i, sender := range senders {
		txn, err := transaction.MakePaymentTxn(sender, destination, 100_000, []byte(fmt.Sprintf("lsig-arg-routing-%d", i)), "", params)
		if err != nil {
			t.Fatalf("failed to build payment %d: %v", i, err)
		}
		intents[i] = jsonrpc.TransactionIntent{Type: jsonrpc.TransactionIntentRaw, Encoded: base64.StdEncoding.EncodeToString(msgpack.Encode(txn))}
	}
	result := &jsonrpc.ExecuteResult{Success: true, Transactions: intents}
	values := map[string][]byte{"preimage": []byte(preimage), "secret": []byte(secret)}

	// A name no position's key declares is refused by the check, before the
	// review and before anything is sent.
	_, err = app.CheckPluginGroup(ctx, result, apshellapp.PluginCheckOptions{LsigArgs: map[string][]byte{"preimage": []byte(preimage), "secrte": []byte(secret)}})
	var undeclared *engine.UndeclaredLsigArgsError
	if !errors.As(err, &undeclared) || !reflect.DeepEqual(undeclared.Names, []string{"secrte"}) {
		t.Fatalf("CheckPluginGroup(typo) error = %v, want the misspelled name refused", err)
	}

	group, err := app.CheckPluginGroup(ctx, result, apshellapp.PluginCheckOptions{LsigArgs: values})
	if err != nil {
		t.Fatalf("CheckPluginGroup: %v", err)
	}
	submit, err := app.SubmitPluginTransactions(ctx, "integration", group)
	if err != nil {
		output := ""
		if submit != nil {
			output = submit.Output
		}
		t.Fatalf("SubmitPluginTransactions: %v\n%s", err, output)
	}
	if len(submit.TxIDs) < len(senders) {
		t.Fatalf("submitted %d transaction(s), want at least %d", len(submit.TxIDs), len(senders))
	}

	// What each position carried on chain: its own key's argument, or none.
	want := [][][]byte{{[]byte(preimage)}, {[]byte(secret)}, nil}
	for i := range senders {
		info, _, err := env.testnet.Client.PendingTransactionInformation(submit.TxIDs[i]).Do(ctx)
		if err != nil {
			t.Fatalf("pending transaction %d: %v", i, err)
		}
		if info.ConfirmedRound == 0 {
			t.Fatalf("transaction %d (%s) not confirmed", i, submit.TxIDs[i])
		}
		if got := info.Transaction.Lsig.Args; !reflect.DeepEqual(got, want[i]) {
			t.Fatalf("transaction %d carried LogicSig arguments %q, want %q", i, got, want[i])
		}
	}
	if got := env.balance(t, native); got >= funding-100_000 {
		t.Fatalf("native balance = %d, want the payment taken", got)
	}
}
