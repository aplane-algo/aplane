// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package plainhost_test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	ed25519v1 "github.com/aplane-algo/aplane/lsig/ed25519lsig/v1"
	"github.com/aplane-algo/aplane/lsig/falcon1024/family"
	falconv1 "github.com/aplane-algo/aplane/lsig/falcon1024/v1"
	"github.com/aplane-algo/aplane/lsig/plainhost"
)

type base struct {
	name        string
	provider    *plainhost.Provider
	spendingKey []byte
}

func bases(t *testing.T) []base {
	t.Helper()
	falcon, err := plainhost.Wrap(&falconv1.Falcon1024V1{}, plainhost.Base{Ops: falconv1.NewFalconOps(family.FalconBase), SaltStyle: lsigsalt.StyleAlgodAutoSalt})
	if err != nil {
		t.Fatal(err)
	}
	ed, err := plainhost.Wrap(ed25519v1.NewProvider(), plainhost.Base{Ops: ed25519v1.NewOps(), SaltStyle: lsigsalt.StyleAlgodAutoSalt})
	if err != nil {
		t.Fatal(err)
	}
	return []base{
		{"falcon", falcon, bytes.Repeat([]byte{0x22}, family.PublicKeySize)},
		{"ed25519", ed, bytes.Repeat([]byte{0x22}, 32)},
	}
}

var (
	testCosigner = strings.Repeat("44", boundedmeta.CosignerPublicKeySizeV1)
	testListKey  = bytes.Repeat([]byte{0x77}, 64)
)

func testRekeyTo() string {
	var a, b types.Address
	a[0], b[0] = 0x31, 0x32
	return b.String() + "," + a.String()
}

func request(rekey string) map[string]string {
	return requestFor(plainhost.Arrangement{Rekey: rekey, Cosigner: true})
}

func requestFor(arrangement plainhost.Arrangement) map[string]string {
	params := map[string]string{plainhost.ParameterRekeyAuthority: arrangement.Rekey}
	if arrangement.Cosigner {
		params[composeddsa.BoundedCosignerPublicKeyParameter] = testCosigner
	}
	if arrangement.Rekey == plainhost.RekeyOnlyThese || arrangement.Rekey == plainhost.RekeyPlusCosigned {
		params[plainhost.ParameterRekeyTo] = testRekeyTo()
	}
	return params
}

// With no parameters the key type is the plain program it was, with no overlay
// contract; it can be created as an account like any other.
func TestNoParametersIsThePlainProgram(t *testing.T) {
	for _, b := range bases(t) {
		t.Run(b.name, func(t *testing.T) {
			instance, err := b.provider.ResolveInstance(nil)
			if err != nil {
				t.Fatal(err)
			}
			if instance.Bounded != nil || instance.Fingerprint != "" {
				t.Fatalf("instance = %+v", instance)
			}
			got, err := b.provider.GenerateTEAL(b.spendingKey, nil)
			if err != nil {
				t.Fatal(err)
			}
			want, err := b.provider.Plain.GenerateTEAL(b.spendingKey, nil)
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Fatalf("plain program changed:\n%s\nwant\n%s", got, want)
			}
			metadata, err := b.provider.BuildBoundedAuthorizationMetadata(b.spendingKey, nil, []byte{1})
			if err != nil || metadata != nil {
				t.Fatalf("plain program metadata = %+v, %v", metadata, err)
			}
			if _, ok := b.provider.CosignerComponentKeyType(nil); ok {
				t.Fatal("the plain program asks for a cosigner")
			}
			if err := b.provider.ValidateCreationParams(nil); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Every arrangement, with or without a cosigner, renders plain1 with no envelope
// and records a fingerprint its stored metadata leads back to.
func TestEveryArrangementResolvesToPlain1(t *testing.T) {
	if got := len(plainhost.Arrangements()); got != 7 {
		t.Fatalf("%d arrangements, want 7: four rekey settings with a cosigner, three without", got)
	}
	for _, b := range bases(t) {
		t.Run(b.name, func(t *testing.T) {
			seen := map[string]bool{}
			for _, arrangement := range plainhost.Arrangements() {
				rekey := fmt.Sprintf("%s/cosigner=%v", arrangement.Rekey, arrangement.Cosigner)
				params := requestFor(arrangement)
				instance, err := b.provider.ResolveInstance(params)
				if err != nil {
					t.Fatalf("%s: %v", rekey, err)
				}
				metadata := instance.Bounded
				if metadata == nil || metadata.Contract != boundedmeta.PlainContract || metadata.MaxFee != nil ||
					(metadata.Cosigner != nil) != arrangement.Cosigner || metadata.Layer3Policy != boundedmeta.Layer3PolicyNone {
					t.Fatalf("%s: instance = %+v", rekey, instance)
				}
				wantList := arrangement.Rekey == plainhost.RekeyOnlyThese || arrangement.Rekey == plainhost.RekeyPlusCosigned
				wantSpendingKey := arrangement.Rekey == plainhost.RekeySpendingKey || arrangement.Rekey == plainhost.RekeyPlusCosigned
				if (metadata.RekeyList != nil) != wantList || (metadata.Rekey == boundedmeta.RekeySpendingKey) != wantSpendingKey {
					t.Fatalf("%s: rekey %s, list %v", rekey, metadata.Rekey, metadata.RekeyList)
				}
				if instance.ReviewFingerprint != b.provider.GrammarFingerprint() || instance.BoundaryDigest == "" || seen[instance.Fingerprint] {
					t.Fatalf("%s: fingerprints %+v", rekey, instance)
				}
				seen[instance.Fingerprint] = true
				if component, ok := b.provider.CosignerComponentKeyType(params); ok != arrangement.Cosigner || (ok && component != boundedmeta.CosignerComponentKeyTypeV1) {
					t.Fatalf("%s: cosigner component %q, %v", rekey, component, ok)
				}

				prepared, err := b.provider.PrepareRekeyList(testListKey, params)
				if err != nil {
					t.Fatalf("%s: %v", rekey, err)
				}
				teal, err := b.provider.GenerateTEAL(b.spendingKey, prepared)
				if err != nil {
					t.Fatalf("%s: GenerateTEAL() error = %v", rekey, err)
				}
				if !strings.Contains(teal, "plain host: rekey dispatch") || strings.Contains(teal, "txn Fee") {
					t.Fatalf("%s: not a plain1 program:\n%s", rekey, teal)
				}
				stored, err := b.provider.BuildBoundedAuthorizationMetadata(b.spendingKey, prepared, make([]byte, 3_000))
				if err != nil {
					t.Fatalf("%s: %v", rekey, err)
				}
				if err := stored.Validate(); err != nil {
					t.Fatalf("%s: stored metadata: %v", rekey, err)
				}
				fingerprint, err := b.provider.StoredFingerprint(nil, stored)
				if err != nil || fingerprint != instance.Fingerprint {
					t.Fatalf("%s: stored fingerprint %s, %v; want %s", rekey, fingerprint, err, instance.Fingerprint)
				}
			}
		})
	}
}

func TestOverlayRequestsFailClosed(t *testing.T) {
	provider := bases(t)[0].provider
	withList := request(plainhost.RekeyOnlyThese)
	for _, tc := range []struct {
		name   string
		params map[string]string
		want   string
	}{
		{"plus cosigned without a cosigner", map[string]string{plainhost.ParameterRekeyAuthority: plainhost.RekeyPlusCosigned, plainhost.ParameterRekeyTo: testRekeyTo()}, "without one it is rekey_authority=spending_key"},
		{"an empty cosigner key", map[string]string{plainhost.ParameterRekeyAuthority: plainhost.RekeyRefused, composeddsa.BoundedCosignerPublicKeyParameter: ""}, "is empty"},
		{"no rekey authority", map[string]string{composeddsa.BoundedCosignerPublicKeyParameter: testCosigner}, "rekey_authority must be"},
		{"unknown rekey authority", map[string]string{plainhost.ParameterRekeyAuthority: "admin_key", composeddsa.BoundedCosignerPublicKeyParameter: testCosigner}, "rekey_authority"},
		{"a list without only_these", func() map[string]string {
			params := request(plainhost.RekeySpendingKey)
			params[plainhost.ParameterRekeyTo] = testRekeyTo()
			return params
		}(), "rekey_to needs"},
		{"only_these without a list", func() map[string]string {
			params := request(plainhost.RekeyOnlyThese)
			delete(params, plainhost.ParameterRekeyTo)
			return params
		}(), "needs the addresses"},
		{"an unresolved cosigner name", map[string]string{plainhost.ParameterCosigner: "corp", plainhost.ParameterRekeyAuthority: plainhost.RekeyRefused}, "not resolved"},
		{"a bounded host parameter", map[string]string{"spend_effects": "pay", plainhost.ParameterRekeyAuthority: plainhost.RekeyRefused, composeddsa.BoundedCosignerPublicKeyParameter: testCosigner}, "unknown parameter"},
		{"a generated root", map[string]string{boundedmeta.RekeyListRootParameter: strings.Repeat("ab", 32), plainhost.ParameterRekeyAuthority: plainhost.RekeyOnlyThese, composeddsa.BoundedCosignerPublicKeyParameter: testCosigner, plainhost.ParameterRekeyTo: withList[plainhost.ParameterRekeyTo]}, "unknown parameter"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := provider.ResolveInstance(tc.params); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ResolveInstance() error = %v, want %q", err, tc.want)
			}
			if err := provider.ValidateCreationParams(tc.params); err == nil {
				t.Fatal("ValidateCreationParams() accepted it")
			}
		})
	}
}

// The boundary digest binds the cosigner and the rekey-to list, the two external
// authorities a review compares.
func TestBoundaryDigestBindsTheOverlays(t *testing.T) {
	provider := bases(t)[0].provider
	digest := func(params map[string]string) string {
		t.Helper()
		instance, err := provider.ResolveInstance(params)
		if err != nil {
			t.Fatal(err)
		}
		return instance.BoundaryDigest
	}
	base := request(plainhost.RekeyPlusCosigned)
	otherCosigner := request(plainhost.RekeyPlusCosigned)
	otherCosigner[composeddsa.BoundedCosignerPublicKeyParameter] = strings.Repeat("45", boundedmeta.CosignerPublicKeySizeV1)
	var c types.Address
	c[0] = 0x33
	otherList := request(plainhost.RekeyPlusCosigned)
	otherList[plainhost.ParameterRekeyTo] = c.String()
	reordered := request(plainhost.RekeyPlusCosigned)
	parts := strings.Split(reordered[plainhost.ParameterRekeyTo], ",")
	reordered[plainhost.ParameterRekeyTo] = parts[1] + "," + parts[0]
	if digest(base) == digest(otherCosigner) || digest(base) == digest(otherList) {
		t.Fatal("the digest does not bind the cosigner and the list")
	}
	if digest(base) != digest(reordered) {
		t.Fatal("the digest depends on the list's order")
	}
	if digest(base) == digest(request(plainhost.RekeyOnlyThese)) {
		t.Fatal("the digest does not bind the arrangement")
	}
}

func TestStoredFingerprintRefusesAnotherContract(t *testing.T) {
	provider := bases(t)[0].provider
	if _, err := provider.StoredFingerprint(nil, &boundedmeta.Metadata{Contract: boundedmeta.Contract}); err == nil {
		t.Fatal("a bounded2 account resolved to a plain host arrangement")
	}
	if _, err := provider.StoredFingerprint(nil, nil); err == nil {
		t.Fatal("an account without metadata resolved to an arrangement")
	}
}

func TestBoundedOpcodeProfileIsSeparate(t *testing.T) {
	provider := bases(t)[0].provider
	plain, err := lsigprovider.ResolveOpcodeProfile(provider, false)
	if err != nil {
		t.Fatal(err)
	}
	bounded, err := lsigprovider.ResolveOpcodeProfile(provider, true)
	if err != nil {
		t.Fatal(err)
	}
	if plain.Default == 0 || bounded.Spend == 0 || bounded.ListedRekey == 0 || bounded.Default != 0 {
		t.Fatalf("profiles plain %+v, bounded %+v", plain, bounded)
	}
}

// The grammar fingerprints hash configuration, so a rendering change must be
// declared by a revision; these goldens make that review unavoidable.
func TestPlainHostGrammarGoldens(t *testing.T) {
	want := map[string]string{
		"falcon":  "1:eb7ab41b5d6236a5c76df5737b621c59e53c786718fa281ef238552cf9f48dd2",
		"ed25519": "1:fca5bc914b1cc80e3dbd57df6acfdaff84005b793181c4a1906b4e1b83491de4",
	}
	for _, b := range bases(t) {
		if got := b.provider.GrammarFingerprint(); got != want[b.name] {
			t.Errorf("%s grammar fingerprint = %s, want %s", b.name, got, want[b.name])
		}
	}
}
