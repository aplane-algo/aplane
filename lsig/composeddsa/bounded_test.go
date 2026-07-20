// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package composeddsa

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
	"github.com/aplane-algo/aplane/internal/txeffects"
)

type boundedTestOps struct{}

func (boundedTestOps) PublicKeySize() int       { return 1 }
func (boundedTestOps) CryptoSignatureSize() int { return 4 }
func (boundedTestOps) MnemonicScheme() string   { return "" }
func (boundedTestOps) MnemonicWordCount() int   { return 0 }
func (boundedTestOps) DisplayColor() string     { return "" }
func (boundedTestOps) TEALVersion() int         { return 12 }
func (boundedTestOps) BuildVerifyTEAL([]byte) (string, error) {
	return "// BOUNDED_TEST_VERIFIER\nint 1\n", nil
}
func (boundedTestOps) BuildSignatureArgs(signature []byte) ([][]byte, error) {
	return [][]byte{signature}, nil
}
func (boundedTestOps) SignatureArgLayout() SignatureArgLayout {
	return SignatureArgLayout{Count: 1, MaxSizes: []int{4}}
}

func TestBoundedGoldenVector(t *testing.T) {
	profile := &BoundedAuthorizationProfile{
		Contract:     BoundedContractV1,
		SpendEffects: []txeffects.SpendEffect{txeffects.SpendEffectAssetOptIn, txeffects.SpendEffectAxfer, txeffects.SpendEffectPay},
		MaxFee:       10_000,
		AdminOperations: []AdminOperationSpec{{
			Kind: AdminOperationRekey, Authorization: AdminAuthorizationAdminKey, PolicyGate: AdminPolicyGateNone,
		}},
	}
	profileMetadata := &boundedmeta.Metadata{
		Contract:               BoundedContractV1,
		BaseSignatureArgLayout: boundedmeta.SignatureArgLayout{Count: 1, MaxSizes: []int{4}},
		SpendEffects:           []string{boundedmeta.SpendEffectPay, boundedmeta.SpendEffectAxfer, boundedmeta.SpendEffectAssetOptIn},
		MaxFee:                 10_000,
		AdminOperations: []boundedmeta.AdminOperation{{
			Kind: boundedmeta.AdminOperationRekey, Authorization: boundedmeta.AdminAuthorizationAdmin, PolicyGate: boundedmeta.PolicyGateNone,
		}},
		Layer3Policy:   boundedmeta.Layer3PolicyCustom,
		ArgumentLayout: boundedmeta.BaseArgumentLayout(SignatureArgLayout{Count: 1, MaxSizes: []int{4}}, true),
	}
	profileEncoding, err := CanonicalBoundedProfile(profile, profileMetadata)
	if err != nil {
		t.Fatalf("CanonicalBoundedProfile() error = %v", err)
	}
	const wantProfile = "0000001941504c414e455f424f554e4445445f50524f46494c455f563100000008626f756e6465643100000003000000037061790000000561786665720000000c61737365745f6f70745f696e0000000000002710000000010000000572656b65790000000961646d696e5f6b6579000000046e6f6e6500000006637573746f6d00000001000000040000000000000000000000020000000000000010626173655f7369676e61747572655f300000000e626173655f7369676e617475726500000004000000087265717569726564000000087265717569726564000000087265717569726564000000010000000f61646d696e5f7369676e61747572650000000561646d696e0000050000000009666f7262696464656e00000009666f7262696464656e000000087265717569726564"
	if got := hex.EncodeToString(profileEncoding); got != wantProfile {
		t.Fatalf("canonical profile = %s, want %s", got, wantProfile)
	}

	recipient := types.Address{}
	for i := range recipient {
		recipient[i] = 0x33
	}
	defs := []lsigprovider.ParameterDef{{Name: "recipients", Type: "address[]", Required: true}}
	behaviorEncoding, err := CanonicalBoundedBehaviorParameters(map[string]string{"recipients": recipient.String()}, defs)
	if err != nil {
		t.Fatalf("CanonicalBoundedBehaviorParameters() error = %v", err)
	}
	const wantBehavior = "0000002541504c414e455f424f554e4445445f4245484156494f525f504152414d45544552535f5631000000010000000a726563697069656e747300000009616464726573735b5d0000002800000001000000203333333333333333333333333333333333333333333333333333333333333333"
	if got := hex.EncodeToString(behaviorEncoding); got != wantBehavior {
		t.Fatalf("canonical behavior parameters = %s, want %s", got, wantBehavior)
	}

	spendingPublicKey := bytes.Repeat([]byte{0x11}, BoundedAdminPublicKeySize)
	adminPublicKey := bytes.Repeat([]byte{0x22}, BoundedAdminPublicKeySize)
	keyID, err := BoundedAdminKeyID(adminPublicKey)
	if err != nil {
		t.Fatalf("BoundedAdminKeyID() error = %v", err)
	}
	const wantKeyID = "WS6X45XM2AI7Y2GNJ46GXMNJ42LCIOAETMEEOIMPSWS3LOFDDGQA"
	if keyID != wantKeyID {
		t.Fatalf("admin key ID = %s, want %s", keyID, wantKeyID)
	}

	binding := BoundedProgramBinding(
		"aplane.falcon1024-admin-allowlist.v1",
		"aplane.falcon1024.v1",
		12,
		spendingPublicKey,
		adminPublicKey,
		profileEncoding,
		behaviorEncoding,
	)
	const wantBinding = "92850ae9fbcbdd74efa92f281fa37275ca223b2ca36bf5262b3eff72c7412d93"
	if got := hex.EncodeToString(binding[:]); got != wantBinding {
		t.Fatalf("program binding = %s, want %s", got, wantBinding)
	}
	message, err := BoundedAdminMessage(AdminOperationRekey, binding, bytes.Repeat([]byte{0x44}, 32))
	if err != nil {
		t.Fatalf("BoundedAdminMessage() error = %v", err)
	}
	const wantMessage = "b700d2e5b4eb40ea16664cabea629ad87bfe4f83cdacfd2263f892b77ffbb193"
	if got := hex.EncodeToString(message[:]); got != wantMessage {
		t.Fatalf("admin message = %s, want %s", got, wantMessage)
	}
}

func TestBoundedComposerEmitsOrderedEnvelope(t *testing.T) {
	provider := newBoundedTestProvider(&BoundedAuthorizationProfile{
		Contract:     BoundedContractV1,
		SpendEffects: []txeffects.SpendEffect{txeffects.SpendEffectAxfer, txeffects.SpendEffectPay},
		MaxFee:       7_000,
		AdminOperations: []AdminOperationSpec{{
			Kind: AdminOperationRekey, Authorization: AdminAuthorizationSpendingKey, PolicyGate: AdminPolicyGateNone,
		}},
	})
	teal, err := provider.GenerateTEAL([]byte{1}, nil)
	if err != nil {
		t.Fatalf("GenerateTEAL() error = %v", err)
	}

	assertOrderedMarkers(t, teal,
		"// BOUNDED_TEST_VERIFIER",
		"// === bounded1 transaction envelope ===",
		"txn Fee\npushint 7000\n<=\nassert",
		"txn RekeyTo\nglobal ZeroAddress\n!=\nbnz "+boundedRekeyLabel,
		boundedRekeyLabel+":",
		boundedSpendLabel+":",
		"// LAYER3_TEST_POLICY",
		boundedAcceptLabel+":",
		"pushint 1\nreturn",
	)
	for _, field := range []string{"CloseRemainderTo", "AssetCloseTo", "AssetSender"} {
		if got := strings.Count(teal, "txn "+field+"\nglobal ZeroAddress\n==\nassert"); got != 2 {
			t.Fatalf("%s zero assertion count = %d, want 2\n%s", field, got, teal)
		}
	}
	pay := strings.Index(teal, "pushint 1\n==")
	axfer := strings.Index(teal, "pushint 4\n==")
	if pay < 0 || axfer < 0 || pay >= axfer {
		t.Fatalf("spend effects are not in canonical order:\n%s", teal)
	}
}

func TestBoundedDisabledRekeyCompilesToErr(t *testing.T) {
	provider := newBoundedTestProvider(&BoundedAuthorizationProfile{
		Contract: BoundedContractV1, SpendEffects: []txeffects.SpendEffect{txeffects.SpendEffectPay}, MaxFee: 1_000,
	})
	teal, err := provider.GenerateTEAL([]byte{1}, nil)
	if err != nil {
		t.Fatalf("GenerateTEAL() error = %v", err)
	}
	if !strings.Contains(teal, boundedRekeyLabel+":\nerr") {
		t.Fatalf("disabled rekey does not fail closed:\n%s", teal)
	}
	if !strings.Contains(teal, boundedAxferLabel+":\ntxn AssetAmount") ||
		!strings.Contains(teal, "bnz "+boundedOptInLabel+"\nerr\n\n"+boundedOptInLabel+":\nerr") {
		t.Fatalf("disabled asset effects do not fail closed:\n%s", teal)
	}
}

func TestBoundedSpendingRekeyCanRequireLayer3(t *testing.T) {
	provider := newBoundedTestProvider(&BoundedAuthorizationProfile{
		Contract: BoundedContractV1, SpendEffects: []txeffects.SpendEffect{txeffects.SpendEffectPay}, MaxFee: 1_000,
		AdminOperations: []AdminOperationSpec{{
			Kind: AdminOperationRekey, Authorization: AdminAuthorizationSpendingKey, PolicyGate: AdminPolicyGateLayer3,
		}},
	})
	teal, err := provider.GenerateTEAL([]byte{1}, nil)
	if err != nil {
		t.Fatalf("GenerateTEAL() error = %v", err)
	}
	rekey := strings.Index(teal, boundedRekeyLabel+":")
	spend := strings.Index(teal, boundedSpendLabel+":")
	if rekey < 0 || spend < 0 || rekey >= spend || !strings.Contains(teal[rekey:spend], "b "+boundedSpendLabel) {
		t.Fatalf("Layer-3-gated rekey does not branch through spending policy:\n%s", teal)
	}
}

func TestBoundedProfileRejectsLayer3GateForExternalAdmin(t *testing.T) {
	profile := &BoundedAuthorizationProfile{
		Contract: BoundedContractV1, SpendEffects: []txeffects.SpendEffect{txeffects.SpendEffectPay}, MaxFee: 1_000,
		AdminOperations: []AdminOperationSpec{{
			Kind: AdminOperationRekey, Authorization: AdminAuthorizationAdminKey, PolicyGate: AdminPolicyGateLayer3,
		}},
	}
	if err := profile.validate(); err == nil || !strings.Contains(err.Error(), "requires policy_gate") {
		t.Fatalf("validate() error = %v, want external-admin gate rejection", err)
	}
}

func TestBoundedAdminKeyUsesFirstArgAfterBaseLayout(t *testing.T) {
	profile := &BoundedAuthorizationProfile{
		Contract: BoundedContractV1, SpendEffects: []txeffects.SpendEffect{txeffects.SpendEffectPay}, MaxFee: 1_000,
		AdminOperations: []AdminOperationSpec{{Kind: AdminOperationRekey, Authorization: AdminAuthorizationAdminKey, PolicyGate: AdminPolicyGateNone}},
	}
	provider := newBoundedTestProvider(profile)
	params := provider.CreationParams()
	if len(params) != 1 || params[0].Name != BoundedAdminPublicKeyParameter || params[0].MaxLength != BoundedAdminPublicKeySize*2 {
		t.Fatalf("CreationParams() = %#v, want injected Falcon admin public key", params)
	}
	adminHex := hex.EncodeToString(bytes.Repeat([]byte{0x22}, BoundedAdminPublicKeySize))
	teal, err := provider.GenerateTEAL([]byte{1}, map[string]string{BoundedAdminPublicKeyParameter: adminHex})
	if err != nil {
		t.Fatalf("GenerateTEAL() error = %v", err)
	}
	if strings.Count(teal, "arg 1") != 3 {
		t.Fatalf("admin authorization does not consistently use arg 1:\n%s", teal)
	}
	if !strings.Contains(teal, "falcon_verify\nassert") {
		t.Fatalf("admin authorization omits Falcon verification:\n%s", teal)
	}
}

func TestBoundedRejectsInvalidProfilesAndCapabilities(t *testing.T) {
	valid := &BoundedAuthorizationProfile{
		Contract: BoundedContractV1, SpendEffects: []txeffects.SpendEffect{txeffects.SpendEffectPay}, MaxFee: 1_000,
	}
	tests := []struct {
		name string
		make func() *ComposedDSA
		want string
	}{
		{
			name: "fee above ceiling",
			make: func() *ComposedDSA {
				profile := cloneBoundedProfile(valid)
				profile.MaxFee = BoundedMaxFeeV1 + 1
				return newBoundedTestProvider(profile)
			},
			want: "exceeds bounded1 ceiling",
		},
		{
			name: "denied spend effect",
			make: func() *ComposedDSA {
				profile := cloneBoundedProfile(valid)
				profile.SpendEffects = []txeffects.SpendEffect{txeffects.SpendEffect("appl")}
				return newBoundedTestProvider(profile)
			},
			want: "unsupported spend effect",
		},
		{
			name: "missing admin policy gate",
			make: func() *ComposedDSA {
				profile := cloneBoundedProfile(valid)
				profile.AdminOperations = []AdminOperationSpec{{Kind: AdminOperationRekey, Authorization: AdminAuthorizationSpendingKey}}
				return newBoundedTestProvider(profile)
			},
			want: "unsupported policy gate",
		},
		{
			name: "runtime args",
			make: func() *ComposedDSA {
				provider := newBoundedTestProvider(valid)
				provider.runtimeArgs = []lsigprovider.RuntimeArgDef{{Name: "proof", Type: "bytes"}}
				return provider
			},
			want: "must use the bounded argument contract",
		},
		{
			name: "reserved label",
			make: func() *ComposedDSA {
				provider := newBoundedTestProvider(valid)
				provider.tealSuffix = boundedSpendLabel + ":\nint 1\nassert"
				return provider
			},
			want: "reserved bounded label",
		},
		{
			name: "base without static layout",
			make: func() *ComposedDSA {
				provider := newBoundedTestProvider(valid)
				provider.ops = suffixTestOps{}
				return provider
			},
			want: "does not expose a static bounded signature argument layout",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.make().GenerateTEAL([]byte{1}, nil)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("GenerateTEAL() error = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestBoundedFingerprintCanonicalizesProfileOrder(t *testing.T) {
	profileA := &BoundedAuthorizationProfile{
		Contract: BoundedContractV1, SpendEffects: []txeffects.SpendEffect{txeffects.SpendEffectAxfer, txeffects.SpendEffectPay}, MaxFee: 1_000,
	}
	profileB := cloneBoundedProfile(profileA)
	profileB.SpendEffects = []txeffects.SpendEffect{txeffects.SpendEffectPay, txeffects.SpendEffectAxfer}
	if got, want := newBoundedTestProvider(profileA).CompatibilityFingerprint(), newBoundedTestProvider(profileB).CompatibilityFingerprint(); got != want {
		t.Fatalf("profile order changed fingerprint: %s != %s", got, want)
	}
	profileB.MaxFee++
	if newBoundedTestProvider(profileA).CompatibilityFingerprint() == newBoundedTestProvider(profileB).CompatibilityFingerprint() {
		t.Fatal("max_fee did not change fingerprint")
	}
}

func TestBoundedBuildArgsEnforcesStaticLayout(t *testing.T) {
	provider := newBoundedTestProvider(&BoundedAuthorizationProfile{
		Contract: BoundedContractV1, SpendEffects: []txeffects.SpendEffect{txeffects.SpendEffectPay}, MaxFee: 1_000,
	})
	if _, err := provider.BuildArgs([]byte{1, 2, 3, 4}, nil); err != nil {
		t.Fatalf("BuildArgs(valid) error = %v", err)
	}
	if _, err := provider.BuildArgs([]byte{1, 2, 3, 4, 5}, nil); err == nil || !strings.Contains(err.Error(), "length 5 invalid") {
		t.Fatalf("BuildArgs(oversized) error = %v, want static-layout rejection", err)
	}
}

func TestBoundedAuthorizationMetadataSnapshotsAdminContract(t *testing.T) {
	provider := newBoundedTestProvider(&BoundedAuthorizationProfile{
		Contract:     BoundedContractV1,
		SpendEffects: []txeffects.SpendEffect{txeffects.SpendEffectPay, txeffects.SpendEffectAxfer},
		MaxFee:       2_000,
		AdminOperations: []AdminOperationSpec{{
			Kind: AdminOperationRekey, Authorization: AdminAuthorizationAdminKey, PolicyGate: AdminPolicyGateNone,
		}},
	})
	adminPublicKey := bytes.Repeat([]byte{0x5a}, BoundedAdminPublicKeySize)
	metadata, err := provider.BuildBoundedAuthorizationMetadata(
		[]byte{0x01},
		map[string]string{BoundedAdminPublicKeyParameter: hex.EncodeToString(adminPublicKey)},
		bytes.Repeat([]byte{0x02}, 100),
	)
	if err != nil {
		t.Fatalf("BoundedAuthorizationMetadata() error = %v", err)
	}
	if metadata.Contract != BoundedContractV1 || len(metadata.DerivedArgs) != 0 {
		t.Fatalf("metadata = %#v", metadata)
	}
	if metadata.AdminKeyID == "" || len(metadata.ProgramBindingHex) != 64 {
		t.Fatalf("admin metadata = %#v", metadata)
	}
	if want := 100 + 4 + BoundedAdminSignatureMaxSize; metadata.PostSigningLogicSigSize != want {
		t.Fatalf("PostSigningLogicSigSize = %d, want %d", metadata.PostSigningLogicSigSize, want)
	}
	if got := len(metadata.ArgumentLayout); got != 2 || metadata.ArgumentLayout[1].Source != boundedmeta.ArgSourceAdmin {
		t.Fatalf("ArgumentLayout = %#v", metadata.ArgumentLayout)
	}
}

func TestBoundedDefaultsHaveOneProgramAndBinding(t *testing.T) {
	provider := NewComposedDSA(Config{
		KeyType:     "aplane.test-bounded-default.v1",
		BaseKeyType: "aplane.falcon1024.v1",
		FamilyName:  "aplane.test",
		Version:     1,
		Ops:         boundedTestOps{},
		SaltStyle:   lsigsalt.StyleNone,
		TEALSuffix:  "txn Fee\nint @limit\n<=\nassert",
		Params: []lsigprovider.ParameterDef{{
			Name: "limit", Type: "uint64", Default: "100",
		}},
		Bounded: &BoundedAuthorizationProfile{
			Contract:     BoundedContractV1,
			SpendEffects: []txeffects.SpendEffect{txeffects.SpendEffectPay},
			MaxFee:       1_000,
			AdminOperations: []AdminOperationSpec{{
				Kind: AdminOperationRekey, Authorization: AdminAuthorizationAdminKey, PolicyGate: AdminPolicyGateNone,
			}},
		},
	})
	adminPublicKey := bytes.Repeat([]byte{0x5a}, BoundedAdminPublicKeySize)
	adminHex := hex.EncodeToString(adminPublicKey)
	inputs := []map[string]string{
		{BoundedAdminPublicKeyParameter: adminHex},
		{BoundedAdminPublicKeyParameter: adminHex, "limit": ""},
		{BoundedAdminPublicKeyParameter: adminHex, "limit": "100"},
	}

	var wantTEAL, wantBinding string
	for i, params := range inputs {
		teal, err := provider.GenerateTEAL([]byte{1}, params)
		if err != nil {
			t.Fatalf("GenerateTEAL(input %d) error = %v", i, err)
		}
		metadata, err := provider.BuildBoundedAuthorizationMetadata([]byte{1}, params, []byte{1, 2, 3})
		if err != nil {
			t.Fatalf("BuildBoundedAuthorizationMetadata(input %d) error = %v", i, err)
		}
		if i == 0 {
			wantTEAL = teal
			wantBinding = metadata.ProgramBindingHex
			continue
		}
		if teal != wantTEAL {
			t.Fatalf("input %d generated different TEAL", i)
		}
		if metadata.ProgramBindingHex != wantBinding {
			t.Fatalf("input %d binding = %s, want %s", i, metadata.ProgramBindingHex, wantBinding)
		}
	}
}

func TestNilBoundedPreservesLegacyTEAL(t *testing.T) {
	provider := NewComposedDSA(Config{
		KeyType: "legacy.v1", Ops: boundedTestOps{}, SaltStyle: lsigsalt.StyleNone,
		TEALSuffix: "// LEGACY_POLICY\nint 1\nassert",
	})
	teal, err := provider.GenerateTEAL([]byte{1}, nil)
	if err != nil {
		t.Fatalf("GenerateTEAL() error = %v", err)
	}
	const want = "#pragma version 12\n\n// BOUNDED_TEST_VERIFIER\nint 1\nassert\n\n// LEGACY_POLICY\nint 1\nassert\n\nint 1\nreturn\n"
	if teal != want {
		t.Fatalf("nil-profile TEAL changed:\n%s\nwant:\n%s", teal, want)
	}
}

func newBoundedTestProvider(profile *BoundedAuthorizationProfile) *ComposedDSA {
	return NewComposedDSA(Config{
		KeyType:     "aplane.test-bounded.v1",
		BaseKeyType: "aplane.falcon1024.v1",
		FamilyName:  "aplane.test",
		Version:     1,
		Ops:         boundedTestOps{},
		SaltStyle:   lsigsalt.StyleNone,
		TEALSuffix:  "// LAYER3_TEST_POLICY\nint 1\nassert",
		Bounded:     profile,
	})
}

func assertOrderedMarkers(t *testing.T, text string, markers ...string) {
	t.Helper()
	position := -1
	for _, marker := range markers {
		next := strings.Index(text[position+1:], marker)
		if next < 0 {
			t.Fatalf("marker %q missing or out of order:\n%s", marker, text)
		}
		position += next + 1
	}
}
