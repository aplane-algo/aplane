// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integration_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/library/templates"
	"github.com/aplane-algo/aplane/lsig/generictemplate"
	"github.com/aplane-algo/aplane/test/integration/harness"
)

// A zero CloseRemainderTo means no close-out, so a path comparing it to a zero
// destination would pass without closing the account and could repeat, burning
// the balance in fees. Generation rejects a zero destination, so these programs
// are built by hand to prove the guard in the TEAL holds on its own. The control
// strips the guard to show the same transactions are otherwise valid.
func TestHTLCCloseOutGuardRejectsZeroDestination(t *testing.T) {
	if os.Getenv("TEST_FUNDING_MNEMONIC") == "" {
		t.Skip("TEST_FUNDING_MNEMONIC not set, skipping funding-backed HTLC test")
	}
	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("failed to connect to testnet: %v", err)
	}
	funder, err := harness.NewFundTestAccount(testnet.Client)
	if err != nil {
		t.Fatalf("failed to load funding account: %v", err)
	}
	status, err := testnet.Client.Status().Do(context.Background())
	if err != nil {
		t.Fatalf("failed to get algod status: %v", err)
	}

	data, err := templates.ReadFile("aplane.htlc.v1.yaml")
	if err != nil {
		t.Fatalf("failed to read HTLC template: %v", err)
	}
	spec, err := generictemplate.ParseTemplateSpec(data)
	if err != nil {
		t.Fatalf("failed to parse HTLC template: %v", err)
	}
	const guard = "txn CloseRemainderTo\nglobal ZeroAddress\n!=\nassert\n"
	if !strings.Contains(spec.TEAL, guard) {
		t.Fatalf("HTLC template is missing the close-out guard:\n%s", spec.TEAL)
	}

	zero := types.ZeroAddress.String()
	other := crypto.GenerateAccount().Address.String()
	const preimage = "open-sesame"
	digest := sha256.Sum256([]byte(preimage))
	hash := "0x" + hex.EncodeToString(digest[:])
	paths := []struct {
		name      string
		recipient string
		refund    string
		timeout   uint64
		args      [][]byte
	}{
		{
			name: "refund", recipient: other, refund: zero, timeout: status.LastRound,
		},
		{
			name: "claim", recipient: zero, refund: other, timeout: status.LastRound + 2_000,
			args: [][]byte{[]byte(preimage)},
		},
	}

	compile := func(t *testing.T, source string) crypto.LogicSigAccount {
		t.Helper()
		compiled, err := testnet.Client.TealCompile([]byte(source)).Do(context.Background())
		if err != nil {
			t.Fatalf("failed to compile HTLC: %v", err)
		}
		bytecode, err := base64.StdEncoding.DecodeString(compiled.Result)
		if err != nil {
			t.Fatalf("failed to decode HTLC bytecode: %v", err)
		}
		return crypto.LogicSigAccount{Lsig: types.LogicSig{Logic: bytecode}}
	}
	submit := func(t *testing.T, account crypto.LogicSigAccount, args [][]byte, note string) (string, error) {
		t.Helper()
		sender, err := account.Address()
		if err != nil {
			t.Fatalf("failed to derive HTLC address: %v", err)
		}
		params, err := testnet.GetSuggestedParams()
		if err != nil {
			t.Fatalf("failed to get suggested params: %v", err)
		}
		params.FlatFee = true
		params.Fee = 5_000
		txn, err := transaction.MakePaymentTxn(sender.String(), zero, 0, []byte(note), "", params)
		if err != nil {
			t.Fatalf("failed to build HTLC payment: %v", err)
		}
		account.Lsig.Args = args
		_, encoded, err := crypto.SignLogicSigAccountTransaction(account, txn)
		if err != nil {
			t.Fatalf("failed to sign HTLC payment: %v", err)
		}
		var signed types.SignedTxn
		if err := msgpack.Decode(encoded, &signed); err != nil {
			t.Fatalf("failed to decode HTLC payment: %v", err)
		}
		return testnet.SubmitTransaction(signed)
	}

	for _, path := range paths {
		t.Run(path.name, func(t *testing.T) {
			source := strings.NewReplacer(
				"@timeout_round", fmt.Sprintf("%d", path.timeout),
				"@recipient", path.recipient,
				"@refund_address", path.refund,
				"@hash", hash,
			).Replace(spec.TEAL)

			cosigned := compile(t, source)
			cosignedAddress, err := cosigned.Address()
			if err != nil {
				t.Fatalf("failed to derive HTLC address: %v", err)
			}
			const funding = 300_000
			if err := funder.FundMicroAlgosAndWait(cosignedAddress.String(), funding); err != nil {
				t.Fatalf("failed to fund HTLC: %v", err)
			}
			if _, err := submit(t, cosigned, path.args, "cosigned"); err == nil {
				t.Fatal("cosigned HTLC accepted a payment that does not close the account")
			} else if !strings.Contains(err.Error(), "rejected by logic") {
				t.Fatalf("cosigned HTLC failed for the wrong reason: %v", err)
			}
			balance, err := testnet.GetAccountInfo(cosignedAddress.String())
			if err != nil {
				t.Fatalf("failed to read HTLC balance: %v", err)
			}
			if balance != funding {
				t.Fatalf("cosigned HTLC holds %d, want %d", balance, funding)
			}

			// Without the guard, the same payment passes and repeats.
			control := compile(t, strings.Replace(source, guard, "", 1))
			controlAddress, err := control.Address()
			if err != nil {
				t.Fatalf("failed to derive control address: %v", err)
			}
			if err := funder.FundMicroAlgosAndWait(controlAddress.String(), funding); err != nil {
				t.Fatalf("failed to fund control: %v", err)
			}
			for attempt := 1; attempt <= 2; attempt++ {
				txid, err := submit(t, control, path.args, fmt.Sprintf("control %d", attempt))
				if err != nil {
					t.Fatalf("control payment %d rejected: %v", attempt, err)
				}
				if _, err := testnet.WaitForConfirmation(txid, 10); err != nil {
					t.Fatalf("control payment %d did not confirm: %v", attempt, err)
				}
			}
			balance, err = testnet.GetAccountInfo(controlAddress.String())
			if err != nil {
				t.Fatalf("failed to read control balance: %v", err)
			}
			if want := uint64(funding - 2*5_000); balance != want {
				t.Fatalf("control holds %d, want %d after two repeated payments", balance, want)
			}
		})
	}
}
