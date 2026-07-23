// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package composeddsa

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
	"github.com/aplane-algo/aplane/internal/txeffects"
	"github.com/aplane-algo/aplane/internal/witness"
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
	const wantProfile = "0000001941504c414e455f424f554e4445445f50524f46494c455f563100000008626f756e6465643100000003000000037061790000000561786665720000000c61737365745f6f70745f696e0000000000002710000000010000000572656b65790000000961646d696e5f6b6579000000046e6f6e650000000000000006637573746f6d00000001000000040000000000000000000000020000000000000010626173655f7369676e61747572655f300000000e626173655f7369676e617475726500000004000000087265717569726564000000087265717569726564000000087265717569726564000000010000000f61646d696e5f7369676e61747572650000000561646d696e0000050000000009666f7262696464656e00000009666f7262696464656e000000087265717569726564"
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
	keyID, err := witness.ID(witness.Falcon1024V1, adminPublicKey)
	if err != nil {
		t.Fatalf("witness.ID() error = %v", err)
	}
	const wantKeyID = "MM3VSIAUKJ2BT2JBNB7V3HX2YUP7SMLWRWGWDQPEGSZ4ZRK6SLVQ"
	if keyID != wantKeyID {
		t.Fatalf("admin key ID = %s, want %s", keyID, wantKeyID)
	}

	const fullKeyType = "aplane.falcon1024-allowlist-alock.v1"
	binding := BoundedProgramBinding(
		fullKeyType,
		"aplane.falcon1024.v1",
		12,
		spendingPublicKey,
		adminPublicKey,
		profileEncoding,
		behaviorEncoding,
	)
	const wantBinding = "23aebf3166f64d6a0e6467d0fde647191094907f733c60fb946129d7cc828509"
	if got := hex.EncodeToString(binding[:]); got != wantBinding {
		t.Fatalf("program binding = %s, want %s", got, wantBinding)
	}
	message, err := BoundedAdminMessage(AdminOperationRekey, binding, bytes.Repeat([]byte{0x44}, 32))
	if err != nil {
		t.Fatalf("BoundedAdminMessage() error = %v", err)
	}
	const wantMessage = "324dfa8eee495b7f4ddaa67f640c906184beb49abfd304d1336be233e84998b6"
	if got := hex.EncodeToString(message[:]); got != wantMessage {
		t.Fatalf("admin message = %s, want %s", got, wantMessage)
	}
	assertBoundedGoldenVectorDocumentation(t, fullKeyType, wantKeyID, wantBinding, wantMessage)
}

func assertBoundedGoldenVectorDocumentation(t *testing.T, fullKeyType, adminKeyID, binding, message string) {
	t.Helper()
	docPath := filepath.Join("..", "..", "docs", "ARCH_BOUNDED_DSA.md")
	doc, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("read bounded architecture document: %v", err)
	}
	for label, value := range map[string]string{
		"full_key_type":           fullKeyType,
		"contract_admin_key_id":   adminKeyID,
		"bounded_program_binding": binding,
		"admin_message":           message,
	} {
		if !strings.Contains(string(doc), label+":\n  "+value) &&
			!strings.Contains(string(doc), label+": "+value) {
			t.Fatalf("%s does not document golden %s %q", docPath, label, value)
		}
	}
}

func TestCanonicalBoundedBehaviorParametersEncodesAbsentOptionalScalar(t *testing.T) {
	def := lsigprovider.ParameterDef{Name: "limit", Type: "uint64"}
	absent, err := CanonicalBoundedBehaviorParameters(nil, []lsigprovider.ParameterDef{def})
	if err != nil {
		t.Fatalf("CanonicalBoundedBehaviorParameters(absent) error = %v", err)
	}
	want := boundedmeta.AppendField(nil, []byte(boundedBehaviorParametersDomainV1))
	want = boundedmeta.AppendUint32(want, 1)
	want = boundedmeta.AppendField(want, []byte(def.Name))
	want = boundedmeta.AppendField(want, []byte(def.Type))
	want = boundedmeta.AppendField(want, nil)
	if !bytes.Equal(absent, want) {
		t.Fatalf("absent optional encoding = %x, want %x", absent, want)
	}

	zero, err := CanonicalBoundedBehaviorParameters(map[string]string{"limit": "0"}, []lsigprovider.ParameterDef{def})
	if err != nil {
		t.Fatalf("CanonicalBoundedBehaviorParameters(zero) error = %v", err)
	}
	if bytes.Equal(absent, zero) {
		t.Fatal("absent optional value encoded identically to an explicit zero")
	}
}

func TestCanonicalBoundedSentryProfileGolden(t *testing.T) {
	profile := &BoundedAuthorizationProfile{
		Contract: BoundedContractV1, SpendEffects: []txeffects.SpendEffect{txeffects.SpendEffectPay}, MaxFee: 1_000,
		Sentry: &boundedmeta.SentryAuthorization{
			Contract: boundedmeta.SentryContractV1, ComponentKeyType: boundedmeta.SentryComponentKeyTypeV1,
			SignatureMaxSize: boundedmeta.SentrySignatureMaxSizeV1, RequiredOn: []string{boundedmeta.PathSpend},
		},
	}
	metadata := &boundedmeta.Metadata{
		Contract: BoundedContractV1, BaseSignatureArgLayout: SignatureArgLayout{Count: 1, MaxSizes: []int{4}},
		SpendEffects: []string{boundedmeta.SpendEffectPay}, MaxFee: 1_000, Layer3Policy: boundedmeta.Layer3PolicyCustom,
		Sentry: profile.Sentry,
		ArgumentLayout: []boundedmeta.ArgumentSlot{
			{Index: 0, Name: "base_signature_0", Source: boundedmeta.ArgSourceBaseSignature, MaxSize: 4, Paths: boundedmeta.ArgumentPathMask{Spend: boundedmeta.ArgRequired, SpendingRekey: boundedmeta.ArgRequired, AdminRekey: boundedmeta.ArgRequired}},
			{Index: 1, Name: boundedmeta.SentrySignatureSlot, Source: boundedmeta.ArgSourceSentry, MaxSize: boundedmeta.SentrySignatureMaxSizeV1, Paths: boundedmeta.ArgumentPathMask{Spend: boundedmeta.ArgRequired, SpendingRekey: boundedmeta.ArgForbidden, AdminRekey: boundedmeta.ArgForbidden}},
		},
	}
	encoded, err := CanonicalBoundedProfile(profile, metadata)
	if err != nil {
		t.Fatalf("CanonicalBoundedProfile() error = %v", err)
	}
	const want = "0000001941504c414e455f424f554e4445445f50524f46494c455f563100000008626f756e64656431000000010000000370617900000000000003e800000000000000010000000773656e747279310000001c61706c616e652e7769746e6573732d66616c636f6e313032342e76310000050000000001000000057370656e6400000006637573746f6d00000001000000040000000000000000000000020000000000000010626173655f7369676e61747572655f300000000e626173655f7369676e617475726500000004000000087265717569726564000000087265717569726564000000087265717569726564000000010000001073656e7472795f7369676e61747572650000000673656e7472790000050000000008726571756972656400000009666f7262696464656e00000009666f7262696464656e"
	if got := hex.EncodeToString(encoded); got != want {
		t.Fatalf("canonical sentry profile = %s, want %s", got, want)
	}
}

func TestBoundedAuthorizationMetadataSnapshotsSentryContract(t *testing.T) {
	profile := &BoundedAuthorizationProfile{
		Contract: BoundedContractV1, SpendEffects: []txeffects.SpendEffect{txeffects.SpendEffectPay}, MaxFee: 1_000,
		Sentry: &boundedmeta.SentryAuthorization{
			Contract: boundedmeta.SentryContractV1, ComponentKeyType: boundedmeta.SentryComponentKeyTypeV1,
			SignatureMaxSize: boundedmeta.SentrySignatureMaxSizeV1, RequiredOn: []string{boundedmeta.PathSpend},
		},
	}
	provider := newBoundedTestProvider(profile)
	teal, err := provider.GenerateTEAL(
		[]byte{0x01},
		map[string]string{BoundedSentryPublicKeyParameter: strings.Repeat("42", boundedmeta.SentryPublicKeySizeV1)},
	)
	if err != nil {
		t.Fatalf("GenerateTEAL() error = %v", err)
	}
	assertOrderedMarkers(t, teal,
		boundedSpendLabel+":",
		"// Sentry-authorized pure spend",
		"pushbytes 0x41504c414e455f53454e5452595f5631\npushbytes 0x02\nconcat\ntxn TxID\nconcat\nsha512_256",
		"arg 1\npushbytes 0x"+strings.Repeat("42", boundedmeta.SentryPublicKeySizeV1)+"\nfalcon_verify\nassert",
		"b "+boundedLayer3Label,
		boundedLayer3Label+":",
		"// LAYER3_TEST_POLICY",
	)
	if strings.Index(teal, boundedRekeyLabel+":") >= strings.Index(teal, "// Sentry-authorized pure spend") {
		t.Fatalf("rekey path is not dispatched before the sentry-only spend gate:\n%s", teal)
	}
	if _, err := provider.BuildArgs([]byte{1, 2, 3, 4}, nil); err == nil || !strings.Contains(err.Error(), boundedmeta.SentrySignatureSlot) {
		t.Fatalf("BuildArgs() error = %v, want required sentry-slot rejection", err)
	}
	spendingPublicKey := bytes.Repeat([]byte{0x31}, boundedmeta.SentryPublicKeySizeV1)
	sentryPublicKey := bytes.Repeat([]byte{0x42}, boundedmeta.SentryPublicKeySizeV1)
	metadata, err := provider.BuildBoundedAuthorizationMetadata(
		spendingPublicKey,
		map[string]string{BoundedSentryPublicKeyParameter: hex.EncodeToString(sentryPublicKey)},
		bytes.Repeat([]byte{0x02}, 100),
	)
	if err != nil {
		t.Fatalf("BuildBoundedAuthorizationMetadata() error = %v", err)
	}
	wantID, err := witness.ID(boundedmeta.SentryComponentKeyTypeV1, sentryPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Sentry == nil || metadata.Sentry.ComponentKeyID != wantID || metadata.Sentry.PublicKeyHex != hex.EncodeToString(sentryPublicKey) {
		t.Fatalf("Sentry = %#v", metadata.Sentry)
	}
	if got, want := metadata.PostSigningLogicSigSize, 100+4+boundedmeta.SentrySignatureMaxSizeV1; got != want {
		t.Fatalf("PostSigningLogicSigSize = %d, want %d", got, want)
	}
	if _, err := provider.BuildBoundedAuthorizationMetadata(
		sentryPublicKey,
		map[string]string{BoundedSentryPublicKeyParameter: hex.EncodeToString(sentryPublicKey)},
		[]byte{1},
	); err == nil || !strings.Contains(err.Error(), "must differ from the spending key") {
		t.Fatalf("collision error = %v", err)
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

func TestBoundedSentryRejectsSpendingKeyAuthorizedRekey(t *testing.T) {
	profile := &BoundedAuthorizationProfile{
		Contract: BoundedContractV1, SpendEffects: []txeffects.SpendEffect{txeffects.SpendEffectPay}, MaxFee: 1_000,
		AdminOperations: []AdminOperationSpec{{
			Kind: AdminOperationRekey, Authorization: AdminAuthorizationSpendingKey, PolicyGate: AdminPolicyGateLayer3,
		}},
		Sentry: &boundedmeta.SentryAuthorization{
			Contract: boundedmeta.SentryContractV1, ComponentKeyType: boundedmeta.SentryComponentKeyTypeV1,
			SignatureMaxSize: boundedmeta.SentrySignatureMaxSizeV1, RequiredOn: []string{boundedmeta.PathSpend},
		},
	}
	provider := newBoundedTestProvider(profile)
	_, err := provider.GenerateTEAL([]byte{1}, map[string]string{
		BoundedSentryPublicKeyParameter: strings.Repeat("42", boundedmeta.SentryPublicKeySizeV1),
	})
	if err == nil || !strings.Contains(err.Error(), "do not support spending-key-authorized rekey") {
		t.Fatalf("GenerateTEAL() error = %v, want bounded-sentry spending-rekey rejection", err)
	}
}

func TestBoundedSentryAdminKeyUsesSlotAfterSentry(t *testing.T) {
	profile := &BoundedAuthorizationProfile{
		Contract: BoundedContractV1, SpendEffects: []txeffects.SpendEffect{txeffects.SpendEffectPay}, MaxFee: 1_000,
		AdminOperations: []AdminOperationSpec{{
			Kind: AdminOperationRekey, Authorization: AdminAuthorizationAdminKey, PolicyGate: AdminPolicyGateNone,
		}},
		Sentry: &boundedmeta.SentryAuthorization{
			Contract: boundedmeta.SentryContractV1, ComponentKeyType: boundedmeta.SentryComponentKeyTypeV1,
			SignatureMaxSize: boundedmeta.SentrySignatureMaxSizeV1, RequiredOn: []string{boundedmeta.PathSpend},
		},
	}
	provider := newBoundedTestProvider(profile)
	sentryKey := strings.Repeat("42", boundedmeta.SentryPublicKeySizeV1)
	adminKey := strings.Repeat("24", BoundedAdminPublicKeySize)
	teal, err := provider.GenerateTEAL([]byte{1}, map[string]string{
		BoundedSentryPublicKeyParameter: sentryKey,
		BoundedAdminPublicKeyParameter:  adminKey,
	})
	if err != nil {
		t.Fatalf("GenerateTEAL() error = %v", err)
	}
	metadata := provider.BoundedAuthorizationMetadata()
	if got := metadata.ArgumentLayout; len(got) != 3 || got[1].Source != boundedmeta.ArgSourceSentry || got[2].Source != boundedmeta.ArgSourceAdmin {
		t.Fatalf("ArgumentLayout = %#v, want base/sentry/admin", got)
	}
	if !strings.Contains(teal, "arg 1\npushbytes 0x"+sentryKey+"\nfalcon_verify") || !strings.Contains(teal, "arg 2\npushbytes 0x"+adminKey+"\nfalcon_verify") {
		t.Fatalf("sentry/admin verification does not use frozen slots:\n%s", teal)
	}
	if _, err := provider.GenerateTEAL([]byte{1}, map[string]string{
		BoundedSentryPublicKeyParameter: adminKey,
		BoundedAdminPublicKeyParameter:  adminKey,
	}); err == nil || !strings.Contains(err.Error(), "must differ from the contract-admin key") {
		t.Fatalf("GenerateTEAL() collision error = %v", err)
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

func TestBoundedBuildArgsPreservesDerivedSlotBeforeRuntimeArg(t *testing.T) {
	provider := NewComposedDSA(Config{
		KeyType:     "aplane.test-bounded-args.v1",
		BaseKeyType: "aplane.falcon1024.v1",
		FamilyName:  "aplane.test",
		Version:     1,
		Ops:         boundedTestOps{},
		SaltStyle:   lsigsalt.StyleNone,
		TEALSuffix:  "int 1\nassert",
		Params: []lsigprovider.ParameterDef{{
			Name: "recipients", Type: "address[]", Required: true, MinItems: 1, MaxItems: 30,
		}},
		RuntimeArgs: []lsigprovider.RuntimeArgDef{{
			Name: "preimage", Type: "bytes", Required: true, MaxSize: 64,
		}},
		BoundedRuntimeArgs: []boundedmeta.RuntimeArg{{
			Name: "preimage", Type: "bytes", Required: true, MaxSize: 64,
		}},
		DerivedArgs: []boundedmeta.DerivedArg{{
			Name: "merkle_proof", Kind: boundedmeta.DerivedArgMerkleProof,
			Parameter: "recipients", MaxSize: boundedmeta.MerkleProofSize,
		}},
		Bounded: &BoundedAuthorizationProfile{
			Contract: BoundedContractV1, SpendEffects: []txeffects.SpendEffect{txeffects.SpendEffectPay}, MaxFee: 1_000,
		},
	})

	args, err := provider.BuildArgs([]byte{1, 2, 3, 4}, map[string][]byte{"preimage": {0xaa}})
	if err != nil {
		t.Fatalf("BuildArgs() error = %v", err)
	}
	if len(args) != 3 || !bytes.Equal(args[0], []byte{1, 2, 3, 4}) || len(args[1]) != 0 || !bytes.Equal(args[2], []byte{0xaa}) {
		t.Fatalf("BuildArgs() = %#v, want [signature, empty derived slot, runtime arg]", args)
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
