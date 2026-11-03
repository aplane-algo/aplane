// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integration_test

import (
	"strings"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
	"github.com/aplane-algo/aplane/internal/protocol"
	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"
	"github.com/aplane-algo/aplane/pkg/signerapi"
	"github.com/aplane-algo/aplane/test/integration/harness"
)

// TestNativeMnemonicExportRecoversDeletedKey is the end-to-end recovery
// round trip for exportable native keys, against a running signer over admin
// IPC: generate a key, reveal its recovery phrase, delete the key, recover it
// from the phrase into the same store, and prove the recovered key controls
// the funded account by signing a close-out payment that confirms on chain.
//
// Unit coverage for the export service (denials, delivery auditing, buffer
// clearing) is in internal/signerapp/keyadmin/export_test.go; the IPC-only
// transport gate is in internal/signerapp/adminserver/key_transport_test.go.
// Encrypted backup/restore, the recovery path for every other key class, is
// exercised in backup_portability_test.go.
func TestNativeMnemonicExportRecoversDeletedKey(t *testing.T) {
	harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{})
	network, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("validate network profile: %v", err)
	}

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })
	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	t.Cleanup(apadmin.Cleanup)

	funder, err := harness.NewFundTestAccount(network.Client)
	if err != nil {
		t.Fatalf("load funding account: %v", err)
	}
	fundingAddress := funder.GetAddress()

	for _, keyType := range []string{"ed25519", nativefalcon.KeyType} {
		t.Run(keyType, func(t *testing.T) {
			address, err := apadmin.GenerateKeyWithType(keyType)
			if err != nil {
				t.Fatalf("generate %s key: %v", keyType, err)
			}
			if !waitForKey(t, signerd.GetURL(), address, 10*time.Second) {
				t.Fatalf("signer did not publish generated key %s", address)
			}

			// Read the phrase. A wrong re-entered passphrase must not release it.
			refused, err := apadmin.ExportKeyWithPassphrase(address, "not-the-signer-passphrase")
			if err != nil {
				t.Fatalf("export with wrong passphrase: %v", err)
			}
			if refused.Success || len(refused.Mnemonic) != 0 || refused.Code != signerapi.ErrCodeInvalidPassphrase {
				refused.Mnemonic.Zero()
				t.Fatalf("export with wrong passphrase = success %v, code %q", refused.Success, refused.Code)
			}
			phrase := mustExportPhrase(t, apadmin, address, keyType)
			defer phrase.Zero()

			// Delete the key; it must leave the signer and no longer export.
			if err := apadmin.DeleteGeneratedKey(address); err != nil {
				t.Fatalf("delete %s key: %v", keyType, err)
			}
			if !waitForKeyMissing(t, signerd.GetURL(), address, 10*time.Second) {
				t.Fatalf("signer still serves deleted key %s", address)
			}
			gone, err := apadmin.ExportKey(address)
			if err != nil {
				t.Fatalf("export deleted key: %v", err)
			}
			if gone.Success || len(gone.Mnemonic) != 0 || gone.Code != signerapi.ErrCodeNotFound {
				gone.Mnemonic.Zero()
				t.Fatalf("export of deleted key = success %v, code %q", gone.Success, gone.Code)
			}

			// Recover the key from the phrase into the same store.
			recovered, err := apadmin.ImportKeyWithType(keyType, string(phrase))
			if err != nil {
				t.Fatalf("import %s key from exported phrase: %v", keyType, err)
			}
			if recovered != address {
				t.Fatalf("recovered address = %s, want %s", recovered, address)
			}
			if !waitForKey(t, signerd.GetURL(), recovered, 10*time.Second) {
				t.Fatalf("signer did not publish recovered key %s", recovered)
			}
			reexported := mustExportPhrase(t, apadmin, recovered, keyType)
			defer reexported.Zero()
			if string(reexported) != string(phrase) {
				t.Fatal("recovered key exports a different phrase")
			}

			// The recovered key must control the account: fund it, then sign
			// a close-out back to the funder and confirm it on chain.
			if err := funder.FundMicroAlgosAndWait(recovered, 300_000); err != nil {
				t.Fatalf("fund recovered %s account: %v", keyType, err)
			}
			sp, err := network.GetSuggestedParams()
			if err != nil {
				t.Fatalf("get suggested params: %v", err)
			}
			closeOut, err := transaction.MakePaymentTxn(recovered, fundingAddress, 0,
				[]byte("aplane-mnemonic-recovery-"+keyType), fundingAddress, sp)
			if err != nil {
				t.Fatalf("build close-out payment: %v", err)
			}
			response := signNativeFalconGroup(t, signerd.GetURL(), []signerapi.SignRequest{
				nativeFalconSignRequest(recovered, closeOut),
			})
			if len(response.Signed) != 1 {
				t.Fatalf("sign response contains %d transactions, want 1", len(response.Signed))
			}
			if keyType == nativefalcon.KeyType {
				assertNativeFalconSignedTxn(t, response.Signed[0], recovered)
			} else if signed := decodeSignedTxnHex(t, response.Signed[0]); signed.Sig == (types.Signature{}) || !signed.PQsig.Blank() {
				t.Fatal("recovered Ed25519 key returned the wrong authorization envelope")
			}
			txIDs := submitSignedTxnGroup(t, network, response.Signed)
			if _, err := network.WaitForConfirmation(txIDs[0], 10); err != nil {
				t.Fatalf("close-out signed by recovered %s key did not confirm: %v", keyType, err)
			}
			if balance, err := network.GetAccountInfo(recovered); err != nil || balance != 0 {
				t.Fatalf("recovered account balance after close-out = %d, %v", balance, err)
			}
			t.Logf("recovered %s key %s from its exported phrase; close-out %s confirmed", keyType, recovered, txIDs[0])
		})
	}
}

// mustExportPhrase exports address's recovery phrase and checks the reply
// shape. The caller should zero the returned phrase.
func mustExportPhrase(t *testing.T, apadmin *harness.ApAdminHarness, address, keyType string) protocol.SensitiveBytes {
	t.Helper()
	result, err := apadmin.ExportKey(address)
	if err != nil {
		t.Fatalf("export %s key %s: %v", keyType, address, err)
	}
	if !result.Success {
		t.Fatalf("export %s key %s refused: %s (%s)", keyType, address, result.Error, result.Code)
	}
	if result.Address != address || result.KeyType != keyType || result.WordCount != 25 ||
		len(strings.Fields(string(result.Mnemonic))) != 25 {
		result.Mnemonic.Zero()
		t.Fatalf("export reply = address %s, type %s, word_count %d", result.Address, result.KeyType, result.WordCount)
	}
	return result.Mnemonic
}
