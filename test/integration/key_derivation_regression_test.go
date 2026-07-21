// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integration_test

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/test/integration/harness"
)

// TestKeyDerivationRegression is a known-answer test for supported derivation
// paths: given a fixed input (mnemonic for currently importable DSA key types,
// creation parameters for LogicSig templates), the derived address must match a
// hardcoded expected value. Any accidental change to a generator, seed
// derivation, TEAL template body, or versioning scheme will shift the address
// and trip this test.
//
// Adding a new key type:
//  1. Append a row with the fixed input and leave wantAddress: "".
//  2. Run this test — the subtest will skip in "capture mode" and log the
//     derived address.
//  3. Paste the logged address into wantAddress.
//  4. Commit both the key type code and the fixture in one change.
//
// Intentionally modifying a derivation path (e.g., bumping a template version
// or changing a generator): update the expected address in the same commit
// that changes the behavior, so git history documents the deliberate break.
func TestKeyDerivationRegression(t *testing.T) {
	// Canonical Algorand test mnemonic (25 words), shared by every DSA key
	// type that uses the Ed25519-family mnemonic handler.
	const ed25519TestMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invest"
	// Canonical BIP-39 test mnemonic (24 words), shared by every Falcon-1024
	// family key type.
	const falcon1024TestMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

	// Fixed deterministic values for template parameters.
	// preimageHashHex is SHA-256 of the literal bytes "aplane-regression-preimage".
	const preimageHashHex = "f62a83b13f2a70dfb8c88f1e3f33fe7bdfa1f3d5ab2d7c8866aa7a6cbe3e0d2e"
	const fixedTimeoutRound = "42000000"

	lockOnDisconnect := false
	harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{LockOnDisconnect: &lockOnDisconnect})

	signerd := harness.NewSignerHarness(t)
	installHTLCTemplate(t, signerd.GetWorkDir())
	installFalconAllowlistTemplate(t, signerd.GetWorkDir())

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

	cases := []struct {
		name     string
		keyType  string
		mnemonic string // empty for generic LogicSig templates
		params   map[string]string
		// wantAddress is the expected derived address. Leave empty to run in
		// capture mode: the test logs the observed address and skips the
		// assertion. Paste the logged value back into this field to lock in
		// the regression.
		wantAddress string
	}{
		{
			name:        "ed25519",
			keyType:     "ed25519",
			mnemonic:    ed25519TestMnemonic,
			wantAddress: "HNVCPPGOW2SC2YVDVDICU3YNONSTEFLXDXREHJR2YBEKDC2Z3IUZSC6YGI",
		},
		{
			name:        "aplane.falcon1024.v1",
			keyType:     "aplane.falcon1024.v1",
			mnemonic:    falcon1024TestMnemonic,
			wantAddress: "X62BVELWGZ7U2SCP3PCO2REMW24MRLJORKHEW25VR37EZNQW74BXWQWTHE",
		},
		{
			name:     "aplane.htlc.v1",
			keyType:  "aplane.htlc.v1",
			mnemonic: "",
			params: map[string]string{
				"hash":           preimageHashHex,
				"recipient":      integrationBurnAddress,
				"refund_address": integrationBurnAddress,
				"timeout_round":  fixedTimeoutRound,
			},
			wantAddress: "IL3QVEJLECESYIDLRXXOASBZ3NDTNYZ4YFQS625HV5KJTME4UGYYSHL2XU",
		},
	}

	// Sanity-check the preimage hash string so a typo surfaces as a clear
	// error rather than as a derivation mismatch.
	if _, err := hex.DecodeString(preimageHashHex); err != nil {
		t.Fatalf("preimageHashHex is not valid hex: %v", err)
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var (
				got string
				err error
			)
			if tc.mnemonic != "" {
				got, err = apadmin.ImportKeyWithTypeAndParams(tc.keyType, tc.mnemonic, tc.params)
				if err != nil {
					t.Fatalf("ImportKeyWithTypeAndParams(%s) failed: %v", tc.keyType, err)
				}
			} else {
				resp, genErr := signerClient.AdminGenerate(tc.keyType, tc.params)
				if genErr != nil {
					t.Fatalf("AdminGenerate(%s) failed: %v", tc.keyType, genErr)
				}
				got = resp.Address
			}
			t.Cleanup(func() {
				if _, cErr := signerClient.AdminDeleteKey(got); cErr != nil {
					t.Logf("cleanup: AdminDeleteKey(%s) failed: %v", got, cErr)
				}
			})
			if !waitForKey(t, signerd.GetURL(), token, got, 10*time.Second) {
				t.Fatalf("signer did not reload derived key %s", got)
			}

			if tc.wantAddress == "" {
				t.Logf("CAPTURE %s → %s", tc.keyType, got)
				t.Skipf("capture mode: set wantAddress to %q and rerun", got)
			}
			if got != tc.wantAddress {
				t.Fatalf("%s derivation regression:\n  got:  %s\n  want: %s\n\nIf this change is intentional, update wantAddress in this fixture.",
					tc.keyType, got, tc.wantAddress)
			}
		})
	}
}
