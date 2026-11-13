// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integration_test

import (
	"context"
	"crypto/sha256"
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
	"github.com/aplane-algo/aplane/internal/cmdspec"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/pkg/signerapi"
	"github.com/aplane-algo/aplane/test/integration/harness"
)

// A LogicSig argument goes to every transaction a command builds, or, written
// arg:<account>:<name>=<value>, only to the transactions that account sends.
// These tests run that on the network with hashlock accounts (a generic
// LogicSig that pays when its one runtime argument hashes to the stored hash)
// of two key types, whose arguments are named differently, and a native
// ed25519 account, whose signer refuses any LogicSig argument.

// lsigArgTargetEnv is a signer with a hashlock template per argument name,
// unlocked, and a funding account on the integration network.
type lsigArgTargetEnv struct {
	testnet  *harness.TestnetConfig
	funder   *harness.FundTestAccount
	signerd  *harness.SignerHarness
	apadmin  *harness.ApAdminHarness
	keyTypes map[string]string // argument name -> hashlock key type taking it
}

func setupLsigArgTargetEnv(t *testing.T, argNames ...string) *lsigArgTargetEnv {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping LogicSig argument target integration test in short mode")
	}
	if os.Getenv("TEST_FUNDING_MNEMONIC") == "" {
		t.Skip("TEST_FUNDING_MNEMONIC not set, skipping funding-backed LogicSig argument target test")
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

	env := &lsigArgTargetEnv{testnet: testnet, funder: funder, keyTypes: map[string]string{}}
	t.Setenv("APSIGNER_PASSPHRASE", mustReadPassphrase(t, clone.SignerDataDir))
	env.apadmin = harness.NewApAdminHarness(t, clone.SignerDataDir)
	for _, name := range argNames {
		family := fmt.Sprintf("integration-target-hashlock-%s-%d", strings.ReplaceAll(name, "_", "-"), time.Now().UnixNano())
		mustImportTemplateViaApadmin(t, clone.SignerDataDir, env.apadmin, writeTargetHashlockTemplate(t, family, name), "hashlock "+name)
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
	return env
}

// writeTargetHashlockTemplate writes a generic template whose account pays
// (no close-out, no rekey, a capped fee) when its required runtime argument
// argName hashes to its hash parameter.
func writeTargetHashlockTemplate(t *testing.T, family, argName string) string {
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
func (env *lsigArgTargetEnv) newHashlock(t *testing.T, argName, secret string, funding uint64) string {
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
func (env *lsigArgTargetEnv) newNative(t *testing.T, funding uint64) string {
	t.Helper()
	address, err := env.apadmin.GenerateKeyWithType("ed25519")
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}
	env.waitAndFund(t, address, funding)
	return address
}

func (env *lsigArgTargetEnv) waitAndFund(t *testing.T, address string, funding uint64) {
	t.Helper()
	if !waitForKey(t, env.signerd.GetURL(), address, 15*time.Second) {
		t.Fatalf("signer did not load key %s", address)
	}
	if err := env.funder.FundMicroAlgosAndWait(address, funding); err != nil {
		t.Fatalf("failed to fund %s: %v", address, err)
	}
}

func (env *lsigArgTargetEnv) balance(t *testing.T, address string) uint64 {
	t.Helper()
	amount, err := env.testnet.GetAccountInfo(address)
	if err != nil {
		t.Fatalf("failed to read the balance of %s: %v", address, err)
	}
	return amount
}

// app is apshell's application layer, in process, connected to the signer
// and the network.
func (env *lsigArgTargetEnv) app(t *testing.T) *apshellapp.App {
	t.Helper()
	eng, err := engine.NewEngine(env.testnet.Network, engine.WithAlgodClient(env.testnet.Client))
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	eng.Connection.SignerClient = signerclient.NewSignerClient(env.signerd.GetURL())
	return apshellapp.New(eng, config.DefaultConfig(), t.TempDir())
}

func targetWords(t *testing.T, tokens ...string) cmdspec.LsigArgs {
	t.Helper()
	var words cmdspec.LsigArgs
	for _, token := range tokens {
		if err := cmdspec.AddLsigArg(&words, token); err != nil {
			t.Fatalf("AddLsigArg(%q): %v", token, err)
		}
	}
	return words
}

// An atomic send from two hashlock accounts of different key types and a
// native account, each hashlock given its own argument by naming it: every
// position carries on chain exactly its own account's argument, the native
// one none, and the group confirms. The same arguments untargeted reach
// every position and the group is refused, nothing moving: by the client,
// against each hashlock key's declared argument, and by the signer, for the
// native position, when only the native position cannot take it.
func TestAtomicSendGivesEachLogicSigAccountItsArgument(t *testing.T) {
	env := setupLsigArgTargetEnv(t, "preimage", "secret")
	const preimage, secret = "integration-target-preimage", "integration-target-secret"
	const funding, amount = 1_000_000, 100_000
	first := env.newHashlock(t, "preimage", preimage, funding)
	second := env.newHashlock(t, "secret", secret, funding)
	native := env.newNative(t, funding)
	destination := env.funder.GetAddress()
	app := env.app(t)
	ctx := context.Background()

	send := func(from []string, tokens ...string) (*apshellapp.SendExecutionResult, error) {
		return app.ExecuteSend(ctx, apshellapp.SendRequest{
			AmountText: "0.1", AssetRef: "algo", FromRaw: from, ToRaw: []string{destination},
			Atomic: true, Wait: true, LsigArgs: targetWords(t, tokens...),
		})
	}
	// A hashlock's address follows from its template and hash alone, so on a
	// chain an earlier run used it still holds what that run left: balances
	// are compared with what they were before any send here, not with the
	// funding amount.
	before := make(map[string]uint64)
	for _, account := range []string{first, second, native} {
		before[account] = env.balance(t, account)
	}
	unchanged := func(when string) {
		t.Helper()
		for _, account := range []string{first, second, native} {
			if got := env.balance(t, account); got != before[account] {
				t.Fatalf("%s: balance of %s = %d, want %d: nothing may move", when, account, got, before[account])
			}
		}
	}

	// Untargeted, both names reach every position: the first hashlock does
	// not take secret, and the client refuses before signing.
	_, err := send([]string{first, second, native}, "arg:preimage=text:"+preimage, "arg:secret=text:"+secret)
	if err == nil || !strings.Contains(err.Error(), "unknown argument 'secret' for this account type") {
		t.Fatalf("untargeted arguments over the group: error = %v, want the client's refusal", err)
	}
	unchanged("after the untargeted group")

	// Untargeted preimage over the preimage hashlock and the native account:
	// the client's check passes both, and the signer refuses the native one.
	_, err = send([]string{first, native}, "arg:preimage=text:"+preimage)
	if err == nil || !strings.Contains(err.Error(), "is native and takes no LogicSig arguments") {
		t.Fatalf("untargeted preimage with a native position: error = %v, want the signer's refusal", err)
	}
	unchanged("after the untargeted preimage")

	result, err := send([]string{first, second, native}, "arg:"+first+":preimage=text:"+preimage, "arg:"+second+":secret=text:"+secret)
	if err != nil {
		t.Fatalf("atomic send with targeted arguments: %v", err)
	}
	if result.Atomic == nil || len(result.Atomic.TxIDs) < 3 || !result.Atomic.Confirmed {
		t.Fatalf("atomic send result = %+v, want three confirmed transactions", result.Atomic)
	}
	want := [][][]byte{{[]byte(preimage)}, {[]byte(secret)}, nil}
	for i := range want {
		info, _, err := env.testnet.Client.PendingTransactionInformation(result.Atomic.TxIDs[i]).Do(ctx)
		if err != nil {
			t.Fatalf("pending transaction %d: %v", i, err)
		}
		if info.ConfirmedRound == 0 {
			t.Fatalf("transaction %d (%s) not confirmed", i, result.Atomic.TxIDs[i])
		}
		if got := info.Transaction.Lsig.Args; !reflect.DeepEqual(got, want[i]) {
			t.Fatalf("transaction %d carried LogicSig arguments %q, want %q", i, got, want[i])
		}
	}
	if got := env.balance(t, native); got > before[native]-amount {
		t.Fatalf("native balance = %d, want the payment taken", got)
	}

	// The signer's half on its own: lsig_args sent for a native key are a
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
