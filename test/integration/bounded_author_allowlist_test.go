// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integration_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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

const authorAllowlistPreimage = "open-sesame"

type authorAllowlistEncoding struct {
	name       string
	policy     string
	stored     string
	maxItems   int
	derivedArg string
	preimageAt int
}

var authorAllowlistEncodings = []authorAllowlistEncoding{
	{
		name: "inline", policy: "fixed_allowlist", stored: boundedmeta.Layer3PolicyFixedAllowlistCustom,
		maxItems: 30, preimageAt: 1,
	},
	{
		name: "merkle", policy: "merkle_allowlist", stored: boundedmeta.Layer3PolicyMerkleAllowlistCustom,
		maxItems: 65536, preimageAt: 2,
		derivedArg: `
  derived_args:
    - name: merkle_proof
      kind: merkle_allowlist_proof
      parameter: recipients
      max_size: 512`,
	},
}

func (encoding authorAllowlistEncoding) keyType() string {
	return "test.author-allowlist-" + encoding.name + ".v1"
}

// yaml is a framework allowlist plus a preimage rule, with a spending-key rekey.
// The rule applies to spends only: a rekey never reaches Layer 3.
func (encoding authorAllowlistEncoding) yaml() string {
	return fmt.Sprintf(`schema_version: 2
derivation_version: 3
template_type: composed
base_key_type: aplane.falcon1024.v1
template_mode: strict
publisher: test
family: author-allowlist-%s
version: 1
display_name: "Author Allowlist %s"
max_opcode_cost: 20000
valid_rekey_target: true

bounded:
  contract: %s
  spend_effects: [pay, axfer, asset_opt_in]
  max_fee: 10000
  rekey: %s
  layer3:
    policy: %s
    recipients_parameter: recipients%s
  runtime_args:
    - name: preimage
      type: bytes
      max_size: 64
      required_on: [spend]

parameters:
  - name: recipients
    type: address[]
    required: true
    min_items: 1
    max_items: %d
  - name: hash
    type: bytes
    required: true
    max_length: 64

template_variables:
  - name: hash
    source: parameter
    parameter: hash
    type: bytes
    constant: byte

teal: |
  arg %d
  sha256
  $hash
  ==
  assert
`, encoding.name, encoding.name, boundedmeta.Contract, boundedmeta.RekeySpendingKey, encoding.policy, encoding.derivedArg, encoding.maxItems, encoding.preimageAt)
}

func authorAllowlistHash() string {
	sum := sha256.Sum256([]byte(authorAllowlistPreimage))
	return hex.EncodeToString(sum[:])
}

// These transactions go straight to the network, so each rejection is the
// program's, not the signer refusing to build the request.
func TestBoundedAllowlistAuthorTEALOnChainLocalnet(t *testing.T) {
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

	for _, encoding := range authorAllowlistEncodings {
		t.Run(encoding.name, func(t *testing.T) {
			allowed := funder.GetAddress()
			second := algocrypto.GenerateAccount().Address.String()
			account := newAuthorAllowlistAccount(t, network, encoding, allowed, second)
			if err := funder.FundMicroAlgosAndWait(account.address, 2_000_000); err != nil {
				t.Fatalf("fund account: %v", err)
			}
			outsider := algocrypto.GenerateAccount().Address.String()
			right, wrong := []byte(authorAllowlistPreimage), []byte("wrong")

			// A Merkle account takes a proof slot before the preimage. An empty
			// slot is what a signer sends for a self-receiver.
			args := func(preimage []byte, proofFor string) [][]byte {
				if encoding.stored == boundedmeta.Layer3PolicyFixedAllowlistCustom {
					return [][]byte{preimage}
				}
				proof := []byte{}
				if proofFor != "" {
					var err error
					proof, err = merkleallowlist.ProofForAddressParam(account.recipients, mustAddress(t, proofFor))
					if err != nil {
						t.Fatalf("build Merkle proof: %v", err)
					}
				}
				return [][]byte{proof, preimage}
			}
			payment := func(to, note string) types.Transaction {
				return boundedPaymentTxn(t, mustSuggestedParams(t, network), account.address, to, 1_000, note)
			}
			rekey := func(note string) types.Transaction {
				txn := payment(account.address, note)
				txn.Amount = 0
				txn.RekeyTo = algocrypto.GenerateAccount().Address
				return txn
			}

			for _, test := range []struct {
				name   string
				txn    types.Transaction
				args   [][]byte
				accept bool
				merkle bool
			}{
				{name: "allowed recipient and right preimage", txn: payment(allowed, "a"), args: args(right, allowed), accept: true},
				{name: "allowed recipient and wrong preimage", txn: payment(allowed, "b"), args: args(wrong, allowed)},
				{name: "outsider and right preimage", txn: payment(outsider, "c"), args: args(right, allowed)},
				{name: "self recipient and right preimage", txn: payment(account.address, "d"), args: args(right, ""), accept: true},
				{name: "self recipient and wrong preimage", txn: payment(account.address, "e"), args: args(wrong, "")},
				{name: "allowed recipient without proof", txn: payment(allowed, "f"), args: args(right, ""), merkle: true},
				// The rekey path never reads the preimage slot, so it passes with the
				// spending signature alone. Last, because it moves the account away.
				{name: "rekey without the preimage", txn: rekey("g"), accept: true},
			} {
				if test.merkle && encoding.stored != boundedmeta.Layer3PolicyMerkleAllowlistCustom {
					continue
				}
				t.Run(test.name, func(t *testing.T) {
					signed, txid := account.signedGroupWithLayer3Args(t, test.txn, test.args)
					raw := make([]byte, 0)
					for _, stxn := range signed {
						raw = append(raw, msgpack.Encode(stxn)...)
					}
					if test.accept {
						submitCorridorGroupExpectSuccess(t, network, raw, txid)
					} else {
						submitCorridorGroupExpectFailure(t, network, raw)
					}
				})
			}
		})
	}
}

type authorAllowlistAccount struct {
	boundedExecutionAccount
	recipients string
}

func newAuthorAllowlistAccount(t *testing.T, network *harness.TestnetConfig, encoding authorAllowlistEncoding, recipients ...string) authorAllowlistAccount {
	t.Helper()
	falcon1024.RegisterClient()
	spec, err := composeddsa.ParseTemplateSpec([]byte(encoding.yaml()))
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
	list := strings.Join(recipients, ",")
	params := map[string]string{"recipients": list, "hash": authorAllowlistHash()}
	derived, err := provider.DeriveLsigWithSalt(context.Background(), publicKey, params)
	if err != nil {
		t.Fatalf("derive LogicSig: %v", err)
	}
	metadata, err := provider.BuildBoundedAuthorizationMetadata(publicKey, params, derived.Bytecode)
	if err != nil {
		t.Fatalf("build metadata: %v", err)
	}
	if metadata.Layer3Policy != encoding.stored {
		t.Fatalf("layer3_policy = %q, want %q", metadata.Layer3Policy, encoding.stored)
	}
	return authorAllowlistAccount{
		boundedExecutionAccount: boundedExecutionAccount{
			address: derived.Address.String(), bytecode: append([]byte(nil), derived.Bytecode...),
			spendingPublicKey: publicKey, spendingPrivateKey: privateKey, provider: provider, metadata: metadata,
		},
		recipients: list,
	}
}

// This is the same account through the signer: it assembles the proof and the
// runtime argument into their slots, and stored metadata must survive a rescan.
func TestBoundedAllowlistAuthorTEALThroughSigner(t *testing.T) {
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

	signerd := harness.NewSignerHarness(t)
	workDir := signerd.GetWorkDir()
	paths := utilkeys.NewPaths(workDir)
	if err := os.MkdirAll(paths.TemplateLibraryDir(), 0o755); err != nil {
		t.Fatalf("create template library: %v", err)
	}
	installer := harness.NewApAdminHarness(t, workDir)
	t.Cleanup(installer.Cleanup)
	for _, encoding := range authorAllowlistEncodings {
		templatePath := filepath.Join(paths.TemplateLibraryDir(), encoding.keyType()+".yaml")
		if err := os.WriteFile(templatePath, []byte(encoding.yaml()), 0o644); err != nil {
			t.Fatalf("write template: %v", err)
		}
		mustImportTemplateViaApadmin(t, workDir, installer, templatePath, encoding.keyType())
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
	accounts := make(map[string]string, len(authorAllowlistEncodings))

	for _, encoding := range authorAllowlistEncodings {
		t.Run(encoding.name, func(t *testing.T) {
			allowed := algocrypto.GenerateAccount().Address.String()
			if err := funder.FundMicroAlgosAndWait(allowed, 200_000); err != nil {
				t.Fatalf("fund recipient: %v", err)
			}
			// The account must outlive this subtest for the rescan check below.
			account := mustAdminGenerateKeyNoCleanup(t, client, signerd, encoding.keyType(), map[string]string{
				"recipients": allowed + "," + algocrypto.GenerateAccount().Address.String(),
				"hash":       authorAllowlistHash(),
			})
			if err := funder.FundMicroAlgosAndWait(account, 2_000_000); err != nil {
				t.Fatalf("fund account: %v", err)
			}
			assertAuthorAllowlistInventory(t, client, account, encoding.stored)
			accounts[encoding.stored] = account

			balance := func() uint64 {
				info, err := network.Client.AccountInformation(account).Do(context.Background())
				if err != nil {
					t.Fatalf("read balance: %v", err)
				}
				return info.Amount
			}
			send := func(to, suffix string) string {
				output, err := apshell.RunWithInput(fmt.Sprintf("send 0.1 algo from %s to %s%s\nquit\n", account, to, suffix))
				if err != nil {
					t.Fatalf("run apshell: %v\n%s", err, output)
				}
				return output
			}
			refused := func(name, to, suffix string) {
				t.Helper()
				before := balance()
				output := send(to, suffix)
				if after := balance(); after != before {
					t.Fatalf("%s moved funds: %d to %d\n%s", name, before, after, output)
				}
				if strings.Contains(strings.ToLower(output), "confirmed") {
					t.Fatalf("%s reported confirmation:\n%s", name, output)
				}
			}
			preimage := " arg:preimage=text:" + authorAllowlistPreimage
			refused("missing preimage", allowed, "")
			refused("wrong preimage", allowed, " arg:preimage=text:wrong")
			refused("outsider", algocrypto.GenerateAccount().Address.String(), preimage)

			output := send(allowed, preimage)
			if _, err := network.WaitForConfirmation(mustExtractTxID(t, output), 10); err != nil {
				t.Fatalf("payment failed to confirm: %v\n%s", err, output)
			}
			if received, err := network.Client.AccountInformation(allowed).Do(context.Background()); err != nil {
				t.Fatalf("read recipient: %v", err)
			} else if received.Amount != 300_000 {
				t.Fatalf("recipient holds %d, want 300000", received.Amount)
			}
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
	for stored, account := range accounts {
		if !waitForKey(t, signerd.GetURL(), account, 10*time.Second) {
			t.Fatalf("signer did not rescan %s", account)
		}
		assertAuthorAllowlistInventory(t, client, account, stored)
	}
}

func assertAuthorAllowlistInventory(t *testing.T, client *signerclient.Client, address, want string) {
	t.Helper()
	keys, err := client.GetKeys()
	if err != nil {
		t.Fatalf("list keys: %v", err)
	}
	for _, key := range keys.Keys {
		if key.Address != address {
			continue
		}
		if key.BoundedAuthorization == nil || key.BoundedAuthorization.Layer3Policy != want {
			t.Fatalf("inventory for %s = %#v, want layer3_policy %q", address, key.BoundedAuthorization, want)
		}
		return
	}
	t.Fatalf("inventory has no %s", address)
}
