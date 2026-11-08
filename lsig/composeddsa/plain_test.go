// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package composeddsa

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
	"github.com/aplane-algo/aplane/internal/txeffects"
)

func plainTestProfile(rekey boundedmeta.RekeySetting) *BoundedAuthorizationProfile {
	return &BoundedAuthorizationProfile{
		Contract: PlainContract,
		Rekey:    rekey,
		Cosigner: &boundedmeta.CosignerAuthorization{
			Contract: boundedmeta.CosignerContractV1, ComponentKeyType: boundedmeta.CosignerComponentKeyTypeV1,
			SignatureMaxSize: boundedmeta.CosignerSignatureMaxSizeV1, RequiredOn: boundedmeta.CosignerRequiredOn(rekey),
		},
	}
}

func newPlainTestProvider(profile *BoundedAuthorizationProfile, suffix string, layer3 *Layer3Policy) *ComposedDSA {
	return NewComposedDSA(Config{
		KeyType:     "aplane.falcon1024.v1",
		BaseKeyType: "aplane.falcon1024.v1",
		FamilyName:  "aplane.falcon1024",
		Version:     1,
		Ops:         boundedTestOps{},
		SaltStyle:   lsigsalt.StyleNone,
		TEALSuffix:  suffix,
		Bounded:     profile,
		Layer3:      layer3,
	})
}

// A plain host's program is the spending-key check, the rekey dispatch, and the
// cosigner: no fee gate, no zero-address envelope and no transaction-type list.
func TestPlainHostRendersNoEnvelope(t *testing.T) {
	provider := newPlainTestProvider(plainTestProfile(boundedmeta.RekeySpendingKey), "", &Layer3Policy{Policy: Layer3PolicyNone})
	cosignerKey := strings.Repeat("42", boundedmeta.CosignerPublicKeySizeV1)
	teal, err := provider.GenerateTEAL([]byte{0x01}, map[string]string{BoundedCosignerPublicKeyParameter: cosignerKey})
	if err != nil {
		t.Fatalf("GenerateTEAL() error = %v", err)
	}
	assertOrderedMarkers(t, teal,
		"// === plain host: rekey dispatch ===",
		"txn RekeyTo\nglobal ZeroAddress\n!=\nbnz "+boundedRekeyLabel+"\nb "+boundedSpendLabel+"\n",
		boundedRekeyLabel+":",
		"txn TypeEnum\npushint 1\n==\nassert",
		"callsub "+boundedCosignerLabel+"\nb "+boundedAcceptLabel,
		boundedCosignerLabel+":",
		"arg 1\npushbytes 0x"+cosignerKey+"\nfalcon_verify\nassert",
		"retsub",
		boundedSpendLabel+":",
		"callsub "+boundedCosignerLabel,
		"// === plain host: no host rules; the cosigner signed this spend ===",
		boundedAcceptLabel+":\npushint 1\nreturn",
	)
	for _, absent := range []string{"txn Fee", boundedPayLabel, boundedAxferLabel, "txn TypeEnum\npushint 4"} {
		if strings.Contains(teal, absent) {
			t.Fatalf("plain host program contains %q:\n%s", absent, teal)
		}
	}
	// The only zero-address checks are the pure rekey's, inside the rekey body.
	if strings.Index(teal, "txn CloseRemainderTo") < strings.Index(teal, boundedRekeyLabel+":") {
		t.Fatalf("a close check precedes the rekey body:\n%s", teal)
	}

	metadata := provider.BoundedAuthorizationMetadata()
	if metadata == nil || metadata.Contract != PlainContract || metadata.MaxFee != nil ||
		len(metadata.SpendEffects) != 0 || metadata.Layer3Policy != boundedmeta.Layer3PolicyNone {
		t.Fatalf("metadata = %+v", metadata)
	}
	if err := metadata.ValidateProfile(); err != nil {
		t.Fatalf("ValidateProfile() error = %v", err)
	}
}

func TestPlainHostRefusesHostRules(t *testing.T) {
	none := &Layer3Policy{Policy: Layer3PolicyNone}
	for _, tc := range []struct {
		name   string
		mutate func(*BoundedAuthorizationProfile)
		suffix string
		layer3 *Layer3Policy
		want   string
	}{
		{name: "fee ceiling", mutate: func(p *BoundedAuthorizationProfile) { p.MaxFee = new(uint64(1_000)) }, layer3: none, want: "max_fee must be absent"},
		{name: "spend effects", mutate: func(p *BoundedAuthorizationProfile) {
			p.SpendEffects = []txeffects.SpendEffect{txeffects.SpendEffectPay}
		}, layer3: none, want: "declares no spend effects"},
		{name: "no cosigner", mutate: func(p *BoundedAuthorizationProfile) { p.Cosigner = nil }, layer3: none, want: "needs a cosigner"},
		{name: "author TEAL", suffix: "int 1\nassert", layer3: none, want: "no author TEAL"},
		{name: "a recipient list", layer3: &Layer3Policy{Policy: Layer3PolicyFixedAllowlist, RecipientsParameter: "recipients"}, want: "layer3 policy none"},
		{name: "no Layer 3", want: "layer3 policy none"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			profile := plainTestProfile(boundedmeta.RekeyRefused)
			if tc.mutate != nil {
				tc.mutate(profile)
			}
			provider := newPlainTestProvider(profile, tc.suffix, tc.layer3)
			params := map[string]string{}
			if profile.Cosigner != nil {
				params[BoundedCosignerPublicKeyParameter] = strings.Repeat("42", boundedmeta.CosignerPublicKeySizeV1)
			}
			_, err := provider.GenerateTEAL([]byte{0x01}, params)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("GenerateTEAL() error = %v, want %q", err, tc.want)
			}
		})
	}
}

// The plain contract's encoding has no fee field, and leads with its own name.
func TestCanonicalPlainProfileGolden(t *testing.T) {
	provider := newPlainTestProvider(plainTestProfile(boundedmeta.RekeySpendingKey), "", &Layer3Policy{Policy: Layer3PolicyNone})
	metadata := provider.BoundedAuthorizationMetadata()
	if metadata == nil {
		t.Fatal("no metadata")
	}
	encoded, err := CanonicalBoundedProfile(provider.BoundedAuthorizationProfile(), metadata)
	if err != nil {
		t.Fatalf("CanonicalBoundedProfile() error = %v", err)
	}
	const want = "0000001941504c414e455f424f554e4445445f50524f46494c455f563200000006706c61696e31000000000000000c7370656e64696e675f6b6579000000000000000100000009636f7369676e6572310000001c61706c616e652e7769746e6573732d66616c636f6e313032342e76310000058f00000002000000057370656e640000000e7370656e64696e675f72656b6579000000046e6f6e6500000001000000040000000000000000000000020000000000000010626173655f7369676e61747572655f300000000e626173655f7369676e6174757265000000040000000872657175697265640000000872657175697265640000000872657175697265640000000100000012636f7369676e65725f7369676e617475726500000008636f7369676e65720000058f00000008726571756972656400000008726571756972656400000009666f7262696464656e"
	if got := hex.EncodeToString(encoded); got != want {
		t.Fatalf("canonical plain profile = %s, want %s", got, want)
	}
}
