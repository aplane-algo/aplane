// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package composeddsa

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math"
	"strconv"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
	"github.com/aplane-algo/aplane/internal/sigconstruction"
	"github.com/aplane-algo/aplane/internal/txeffects"
	"github.com/aplane-algo/aplane/internal/witness"
)

// boundedTestOps is a stub verifier standing in for the Falcon base: tests compose
// it under "aplane.falcon1024.v1", so it declares that base's construction.
type boundedTestOps struct{}

func (boundedTestOps) Construction() sigconstruction.Construction {
	return sigconstruction.Falcon1024()
}
func (boundedTestOps) PublicKeySize() int       { return 1 }
func (boundedTestOps) CryptoSignatureSize() int { return 4 }
func (boundedTestOps) MnemonicScheme() string   { return "" }
func (boundedTestOps) MnemonicWordCount() int   { return 0 }
func (boundedTestOps) DisplayColor() string     { return "" }
func (boundedTestOps) TEALVersion() int         { return 13 }
func (boundedTestOps) BuildVerifyTEAL([]byte) (string, error) {
	return "// BOUNDED_TEST_VERIFIER\nint 1\n", nil
}
func (boundedTestOps) BuildSignatureArgs(signature []byte) ([][]byte, error) {
	return [][]byte{signature}, nil
}
func (boundedTestOps) SignatureArgLayout() SignatureArgLayout {
	return SignatureArgLayout{Count: 1, MaxSizes: []int{4}}
}

// The behavior-parameter encoding feeds the general boundary digest. These bytes
// were frozen with the first bounded golden vector.
func TestCanonicalBoundedBehaviorParametersGolden(t *testing.T) {
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

func TestCanonicalBoundedCosignerProfileGolden(t *testing.T) {
	profile := &BoundedAuthorizationProfile{
		Contract: BoundedContract, SpendEffects: []txeffects.SpendEffect{txeffects.SpendEffectPay}, MaxFee: new(uint64(1_000)),
		Rekey: boundedmeta.RekeyRefused,
		Cosigner: &boundedmeta.CosignerAuthorization{
			Contract: boundedmeta.CosignerContractV1, ComponentKeyType: boundedmeta.CosignerComponentKeyTypeV1,
			SignatureMaxSize: boundedmeta.CosignerSignatureMaxSizeV1, RequiredOn: []string{boundedmeta.PathSpend},
		},
	}
	metadata := &boundedmeta.Metadata{
		Contract: BoundedContract, BaseSignatureArgLayout: SignatureArgLayout{Count: 1, MaxSizes: []int{4}},
		SpendEffects: []string{boundedmeta.SpendEffectPay}, MaxFee: new(uint64(1_000)), Rekey: boundedmeta.RekeyRefused,
		Layer3Policy: boundedmeta.Layer3PolicyCustom, Cosigner: profile.Cosigner,
		ArgumentLayout: []boundedmeta.ArgumentSlot{
			{Index: 0, Name: "base_signature_0", Source: boundedmeta.ArgSourceBaseSignature, MaxSize: 4, Paths: boundedmeta.ArgumentPathMask{Spend: boundedmeta.ArgRequired, SpendingRekey: boundedmeta.ArgRequired, ListedRekey: boundedmeta.ArgRequired}},
			{Index: 1, Name: boundedmeta.CosignerSignatureSlot, Source: boundedmeta.ArgSourceCosigner, MaxSize: boundedmeta.CosignerSignatureMaxSizeV1, Paths: boundedmeta.ArgumentPathMask{Spend: boundedmeta.ArgRequired, SpendingRekey: boundedmeta.ArgForbidden, ListedRekey: boundedmeta.ArgForbidden}},
		},
	}
	encoded, err := CanonicalBoundedProfile(profile, metadata)
	if err != nil {
		t.Fatalf("CanonicalBoundedProfile() error = %v", err)
	}
	const want = "0000001941504c414e455f424f554e4445445f50524f46494c455f563200000008626f756e64656432000000010000000370617900000000000003e80000000772656675736564000000000000000100000009636f7369676e6572310000001c61706c616e652e7769746e6573732d66616c636f6e313032342e76310000058f00000001000000057370656e6400000006637573746f6d00000001000000040000000000000000000000020000000000000010626173655f7369676e61747572655f300000000e626173655f7369676e6174757265000000040000000872657175697265640000000872657175697265640000000872657175697265640000000100000012636f7369676e65725f7369676e617475726500000008636f7369676e65720000058f00000008726571756972656400000009666f7262696464656e00000009666f7262696464656e"
	if got := hex.EncodeToString(encoded); got != want {
		t.Fatalf("canonical cosigner profile = %s, want %s", got, want)
	}
}

func TestBoundedAuthorizationMetadataSnapshotsCosignerContract(t *testing.T) {
	profile := &BoundedAuthorizationProfile{
		Contract: BoundedContract, SpendEffects: []txeffects.SpendEffect{txeffects.SpendEffectPay}, MaxFee: new(uint64(1_000)),
		Rekey: boundedmeta.RekeyRefused,
		Cosigner: &boundedmeta.CosignerAuthorization{
			Contract: boundedmeta.CosignerContractV1, ComponentKeyType: boundedmeta.CosignerComponentKeyTypeV1,
			SignatureMaxSize: boundedmeta.CosignerSignatureMaxSizeV1, RequiredOn: []string{boundedmeta.PathSpend},
		},
	}
	provider := newBoundedTestProvider(profile)
	teal, err := provider.GenerateTEAL(
		[]byte{0x01},
		map[string]string{BoundedCosignerPublicKeyParameter: strings.Repeat("42", boundedmeta.CosignerPublicKeySizeV1)},
	)
	if err != nil {
		t.Fatalf("GenerateTEAL() error = %v", err)
	}
	assertOrderedMarkers(t, teal,
		boundedCosignerLabel+":",
		"pushbytes 0x41504c414e455f434f5349474e45525f5631\npushbytes 0x02\nconcat\ntxn TxID\nconcat\nsha512_256",
		"arg 1\npushbytes 0x"+strings.Repeat("42", boundedmeta.CosignerPublicKeySizeV1)+"\nfalcon_verify\nassert",
		"retsub",
		boundedSpendLabel+":",
		"callsub "+boundedCosignerLabel,
		"b "+boundedLayer3Label,
		boundedLayer3Label+":",
		"// LAYER3_TEST_POLICY",
	)
	if strings.Index(teal, boundedRekeyLabel+":") >= strings.Index(teal, boundedCosignerLabel+":") {
		t.Fatalf("rekey path is not dispatched before the cosigner check:\n%s", teal)
	}
	if _, err := provider.BuildArgs([]byte{1, 2, 3, 4}, nil); err == nil || !strings.Contains(err.Error(), boundedmeta.CosignerSignatureSlot) {
		t.Fatalf("BuildArgs() error = %v, want required cosigner-slot rejection", err)
	}
	spendingPublicKey := bytes.Repeat([]byte{0x31}, boundedmeta.CosignerPublicKeySizeV1)
	cosignerPublicKey := bytes.Repeat([]byte{0x42}, boundedmeta.CosignerPublicKeySizeV1)
	metadata, err := provider.BuildBoundedAuthorizationMetadata(
		spendingPublicKey,
		map[string]string{BoundedCosignerPublicKeyParameter: hex.EncodeToString(cosignerPublicKey)},
		bytes.Repeat([]byte{0x02}, 100),
	)
	if err != nil {
		t.Fatalf("BuildBoundedAuthorizationMetadata() error = %v", err)
	}
	wantID, err := witness.ID(boundedmeta.CosignerComponentKeyTypeV1, cosignerPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Cosigner == nil || metadata.Cosigner.ComponentKeyID != wantID || metadata.Cosigner.PublicKeyHex != hex.EncodeToString(cosignerPublicKey) {
		t.Fatalf("Cosigner = %#v", metadata.Cosigner)
	}
	if got, want := metadata.ArgumentBytesForPath(boundedmeta.PathSpend), 4+boundedmeta.CosignerSignatureMaxSizeV1; got != want {
		t.Fatalf("spend argument bytes = %d, want %d", got, want)
	}
	if _, err := provider.BuildBoundedAuthorizationMetadata(
		cosignerPublicKey,
		map[string]string{BoundedCosignerPublicKeyParameter: hex.EncodeToString(cosignerPublicKey)},
		[]byte{1},
	); err == nil || !strings.Contains(err.Error(), "must differ from the spending key") {
		t.Fatalf("collision error = %v", err)
	}
}

func TestBoundedComposerEmitsOrderedEnvelope(t *testing.T) {
	provider := newBoundedTestProvider(&BoundedAuthorizationProfile{
		Contract:     BoundedContract,
		SpendEffects: []txeffects.SpendEffect{txeffects.SpendEffectAxfer, txeffects.SpendEffectPay},
		MaxFee:       new(uint64(7_000)),
		Rekey:        boundedmeta.RekeySpendingKey,
	})
	teal, err := provider.GenerateTEAL([]byte{1}, nil)
	if err != nil {
		t.Fatalf("GenerateTEAL() error = %v", err)
	}

	assertOrderedMarkers(t, teal,
		"// BOUNDED_TEST_VERIFIER",
		"// === bounded transaction envelope ===",
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
		Contract: BoundedContract, SpendEffects: []txeffects.SpendEffect{txeffects.SpendEffectPay}, MaxFee: new(uint64(1_000)),
		Rekey: boundedmeta.RekeyRefused,
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

// No host rule gates a rekey: a spending-key rekey checks its normal form and
// accepts, and the spend path's Layer 3 policy never sees it.
func TestBoundedSpendingRekeyAcceptsWithoutLayer3(t *testing.T) {
	provider := newBoundedTestProvider(&BoundedAuthorizationProfile{
		Contract: BoundedContract, SpendEffects: []txeffects.SpendEffect{txeffects.SpendEffectPay}, MaxFee: new(uint64(1_000)),
		Rekey: boundedmeta.RekeySpendingKey,
	})
	teal, err := provider.GenerateTEAL([]byte{1}, nil)
	if err != nil {
		t.Fatalf("GenerateTEAL() error = %v", err)
	}
	rekey := strings.Index(teal, boundedRekeyLabel+":")
	spend := strings.Index(teal, boundedSpendLabel+":")
	policy := strings.Index(teal, "// LAYER3_TEST_POLICY")
	if rekey < 0 || spend < 0 || rekey >= spend || policy < spend {
		t.Fatalf("rekey path at %d, spend path at %d, Layer 3 at %d:\n%s", rekey, spend, policy, teal)
	}
	branch := teal[rekey:spend]
	if !strings.HasPrefix(branch, boundedRekeyLabel+":\ntxn TypeEnum\npushint 1\n==\nassert\n") ||
		!strings.HasSuffix(branch, "b "+boundedAcceptLabel+"\n\n") {
		t.Fatalf("spending-key rekey does not check a pure payment and accept:\n%s", branch)
	}
	for _, field := range []string{"CloseRemainderTo", "AssetCloseTo", "AssetSender"} {
		if !strings.Contains(branch, "txn "+field+"\nglobal ZeroAddress\n==\nassert") {
			t.Fatalf("spending-key rekey does not require a zero %s:\n%s", field, branch)
		}
	}
	if strings.Contains(branch, boundedSpendLabel) || strings.Contains(branch, boundedLayer3Label) || strings.Contains(branch, "LAYER3_TEST_POLICY") {
		t.Fatalf("spending-key rekey reaches the spend path:\n%s", branch)
	}
}

// A cosigned spending-key rekey needs the cosigner, named in the record, and
// calls the same cosigner check the spend path does: the cosigner's key compiles
// once.
func TestBoundedCosignedRekeyCallsTheCosignerCheck(t *testing.T) {
	cosignerKey := strings.Repeat("42", boundedmeta.CosignerPublicKeySizeV1)
	profile := &BoundedAuthorizationProfile{
		Contract: BoundedContract, SpendEffects: []txeffects.SpendEffect{txeffects.SpendEffectPay}, MaxFee: new(uint64(1_000)),
		Rekey: boundedmeta.RekeySpendingKey,
		Cosigner: &boundedmeta.CosignerAuthorization{
			Contract: boundedmeta.CosignerContractV1, ComponentKeyType: boundedmeta.CosignerComponentKeyTypeV1,
			SignatureMaxSize: boundedmeta.CosignerSignatureMaxSizeV1, RequiredOn: []string{boundedmeta.PathSpend},
		},
	}
	params := map[string]string{BoundedCosignerPublicKeyParameter: cosignerKey}
	if _, err := newBoundedTestProvider(profile).GenerateTEAL([]byte{1}, params); err == nil ||
		!strings.Contains(err.Error(), "exactly [spend, spending_rekey] with rekey spending_key") {
		t.Fatalf("a spend-only cosigner beside a spending-key rekey: error = %v", err)
	}
	profile.Cosigner.RequiredOn = boundedmeta.CosignerRequiredOn(boundedmeta.RekeySpendingKey)
	teal, err := newBoundedTestProvider(profile).GenerateTEAL([]byte{1}, params)
	if err != nil {
		t.Fatalf("GenerateTEAL() error = %v", err)
	}
	rekey := strings.Index(teal, boundedRekeyLabel+":")
	check := strings.Index(teal, boundedCosignerLabel+":")
	spend := strings.Index(teal, boundedSpendLabel+":")
	if rekey < 0 || check < rekey || spend < check {
		t.Fatalf("rekey at %d, cosigner check at %d, spend at %d:\n%s", rekey, check, spend, teal)
	}
	if branch := teal[rekey:check]; !strings.HasSuffix(branch, "callsub "+boundedCosignerLabel+"\nb "+boundedAcceptLabel+"\n\n") {
		t.Fatalf("the cosigned rekey does not call the cosigner check and accept:\n%s", branch)
	}
	if !strings.HasSuffix(teal[check:spend], "assert\nretsub\n\n") {
		t.Fatalf("the cosigner check is not a subroutine:\n%s", teal[check:spend])
	}
	if !strings.HasPrefix(teal[spend:], boundedSpendLabel+":\ncallsub "+boundedCosignerLabel+"\n") {
		t.Fatalf("the spend path does not call the cosigner check:\n%s", teal[spend:])
	}
	if n := strings.Count(teal, cosignerKey); n != 1 {
		t.Fatalf("the cosigner key compiles %d times, want once", n)
	}
}

func TestBoundedRejectsInvalidProfilesAndCapabilities(t *testing.T) {
	valid := &BoundedAuthorizationProfile{
		Contract: BoundedContract, SpendEffects: []txeffects.SpendEffect{txeffects.SpendEffectPay}, MaxFee: new(uint64(1_000)),
		Rekey: boundedmeta.RekeyRefused,
	}
	tests := []struct {
		name string
		make func() *ComposedDSA
		want string
	}{
		{
			name: "no fee ceiling",
			make: func() *ComposedDSA {
				profile := cloneBoundedProfile(valid)
				profile.MaxFee = nil
				return newBoundedTestProvider(profile)
			},
			want: BoundedContract + " requires max_fee",
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
			name: "missing rekey setting",
			make: func() *ComposedDSA {
				profile := cloneBoundedProfile(valid)
				profile.Rekey = ""
				return newBoundedTestProvider(profile)
			},
			want: `unsupported rekey setting ""`,
		},
		{
			name: "unknown rekey setting",
			make: func() *ComposedDSA {
				profile := cloneBoundedProfile(valid)
				profile.Rekey = "admin_key"
				return newBoundedTestProvider(profile)
			},
			want: `unsupported rekey setting "admin_key"`,
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
				provider.ops = noLayoutV13Ops{}
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

// The fee ceiling has no cap but the wire's, and zero is a value: each compiles,
// with its own fee check, metadata and fingerprint.
func TestBoundedAcceptsAnyFeeCeiling(t *testing.T) {
	fingerprints := make(map[string]uint64)
	for _, ceiling := range []uint64{0, 1_000, 10_000, 10_001, 20_000, boundedmeta.MaxFeeLimit} {
		t.Run(strconv.FormatUint(ceiling, 10), func(t *testing.T) {
			provider := newBoundedTestProvider(&BoundedAuthorizationProfile{
				Contract: BoundedContract, SpendEffects: []txeffects.SpendEffect{txeffects.SpendEffectPay}, MaxFee: new(ceiling),
				Rekey: boundedmeta.RekeyRefused,
			})
			teal, err := provider.GenerateTEAL([]byte{1}, nil)
			if err != nil {
				t.Fatalf("GenerateTEAL() error = %v", err)
			}
			if want := fmt.Sprintf("txn Fee\npushint %d\n<=\nassert\n", ceiling); !strings.Contains(teal, want) {
				t.Fatalf("fee check %q missing:\n%s", want, teal)
			}
			metadata := provider.BoundedAuthorizationMetadata()
			if metadata == nil || metadata.MaxFee == nil || *metadata.MaxFee != ceiling {
				t.Fatalf("metadata = %+v", metadata)
			}
			if err := metadata.ValidateProfile(); err != nil {
				t.Fatalf("ValidateProfile() error = %v", err)
			}
			fingerprint := provider.CompatibilityFingerprint()
			if other, seen := fingerprints[fingerprint]; seen {
				t.Fatalf("ceilings %d and %d share fingerprint %s", other, ceiling, fingerprint)
			}
			fingerprints[fingerprint] = ceiling
		})
	}
}

// A ceiling above the largest whole number every client reads exactly is
// refused when the profile is validated, as generating the program does.
func TestBoundedRefusesAFeeCeilingAboveTheWireLimit(t *testing.T) {
	if boundedmeta.MaxFeeLimit != 9007199254740991 {
		t.Fatalf("MaxFeeLimit = %d", uint64(boundedmeta.MaxFeeLimit))
	}
	for _, ceiling := range []uint64{boundedmeta.MaxFeeLimit + 1, 1 << 63, math.MaxUint64} {
		t.Run(strconv.FormatUint(ceiling, 10), func(t *testing.T) {
			profile := &BoundedAuthorizationProfile{
				Contract: BoundedContract, SpendEffects: []txeffects.SpendEffect{txeffects.SpendEffectPay}, MaxFee: new(ceiling),
				Rekey: boundedmeta.RekeyRefused,
			}
			want := fmt.Sprintf("max_fee %d is above 9007199254740991, the largest value every client reads exactly", ceiling)
			if err := profile.validate(); err == nil || err.Error() != want {
				t.Fatalf("validate() error = %v, want %q", err, want)
			}
			if _, err := newBoundedTestProvider(profile).GenerateTEAL([]byte{1}, nil); err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("GenerateTEAL() error = %v, want containing %q", err, want)
			}
		})
	}
}

func TestBoundedFingerprintCanonicalizesProfileOrder(t *testing.T) {
	profileA := &BoundedAuthorizationProfile{
		Contract: BoundedContract, SpendEffects: []txeffects.SpendEffect{txeffects.SpendEffectAxfer, txeffects.SpendEffectPay}, MaxFee: new(uint64(1_000)),
		Rekey: boundedmeta.RekeyRefused,
	}
	profileB := cloneBoundedProfile(profileA)
	profileB.SpendEffects = []txeffects.SpendEffect{txeffects.SpendEffectPay, txeffects.SpendEffectAxfer}
	if got, want := newBoundedTestProvider(profileA).CompatibilityFingerprint(), newBoundedTestProvider(profileB).CompatibilityFingerprint(); got != want {
		t.Fatalf("profile order changed fingerprint: %s != %s", got, want)
	}
	profileB.MaxFee = new(*profileB.MaxFee + 1)
	if newBoundedTestProvider(profileA).CompatibilityFingerprint() == newBoundedTestProvider(profileB).CompatibilityFingerprint() {
		t.Fatal("max_fee did not change fingerprint")
	}
	profileC := cloneBoundedProfile(profileA)
	profileC.Rekey = boundedmeta.RekeySpendingKey
	if newBoundedTestProvider(profileA).CompatibilityFingerprint() == newBoundedTestProvider(profileC).CompatibilityFingerprint() {
		t.Fatal("rekey setting did not change fingerprint")
	}
}

func TestBoundedBuildArgsEnforcesStaticLayout(t *testing.T) {
	provider := newBoundedTestProvider(&BoundedAuthorizationProfile{
		Contract: BoundedContract, SpendEffects: []txeffects.SpendEffect{txeffects.SpendEffectPay}, MaxFee: new(uint64(1_000)),
		Rekey: boundedmeta.RekeyRefused,
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
			Contract: BoundedContract, SpendEffects: []txeffects.SpendEffect{txeffects.SpendEffectPay}, MaxFee: new(uint64(1_000)),
			Rekey: boundedmeta.RekeyRefused,
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

func TestBoundedDefaultsHaveOneProgramAndBehaviorEncoding(t *testing.T) {
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
			Contract:     BoundedContract,
			SpendEffects: []txeffects.SpendEffect{txeffects.SpendEffectPay},
			MaxFee:       new(uint64(1_000)),
			Rekey:        boundedmeta.RekeySpendingKey,
		},
	})
	inputs := []map[string]string{
		{},
		{"limit": ""},
		{"limit": "100"},
	}

	var wantTEAL, wantBehavior string
	for i, params := range inputs {
		teal, err := provider.GenerateTEAL([]byte{1}, params)
		if err != nil {
			t.Fatalf("GenerateTEAL(input %d) error = %v", i, err)
		}
		if _, err := provider.BuildBoundedAuthorizationMetadata([]byte{1}, params, []byte{1, 2, 3}); err != nil {
			t.Fatalf("BuildBoundedAuthorizationMetadata(input %d) error = %v", i, err)
		}
		behavior, err := CanonicalBoundedBehaviorParameters(params, provider.CreationParams())
		if err != nil {
			t.Fatalf("CanonicalBoundedBehaviorParameters(input %d) error = %v", i, err)
		}
		if i == 0 {
			wantTEAL = teal
			wantBehavior = hex.EncodeToString(behavior)
			continue
		}
		if teal != wantTEAL {
			t.Fatalf("input %d generated different TEAL", i)
		}
		if got := hex.EncodeToString(behavior); got != wantBehavior {
			t.Fatalf("input %d behavior encoding = %s, want %s", i, got, wantBehavior)
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
	const want = "#pragma version 13\n\n// BOUNDED_TEST_VERIFIER\nint 1\nassert\n\n// LEGACY_POLICY\nint 1\nassert\n\nint 1\nreturn\n"
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

// Key separation resolves the witness's construction from its key type, as
// rendering does, instead of assuming Falcon, and compares component by component.
// An unknown witness key type is an error rather than "no overlap".
func TestSpendingKeyHoldsResolvesTheWitnessFromItsKeyType(t *testing.T) {
	composite, err := sigconstruction.New(sigconstruction.Definition{
		ID: "test.falcon-ed25519",
		Components: []sigconstruction.ComponentSpec{
			{Name: "falcon", Primitive: sigconstruction.PrimitiveFalcon1024},
			{Name: "ed25519", Primitive: sigconstruction.PrimitiveEd25519},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	provider := NewComposedDSA(Config{KeyType: "test.key-separation.v1", Ops: testOps{construction: composite}})
	falconKey := bytes.Repeat([]byte{0x11}, sigconstruction.Falcon1024().PublicKeySize())
	edKey := bytes.Repeat([]byte{0x22}, sigconstruction.Ed25519().PublicKeySize())
	spendingKey := append(append([]byte{}, falconKey...), edKey...)
	otherFalconKey := bytes.Repeat([]byte{0x33}, len(falconKey))

	for _, test := range []struct {
		name          string
		witnessType   string
		witnessKey    []byte
		want, wantErr bool
	}{
		{name: "reused Falcon component", witnessType: witness.Falcon1024V1, witnessKey: falconKey, want: true},
		{name: "non-canonical spelling resolves the same", witnessType: " APLANE.WITNESS-FALCON1024.V1 ", witnessKey: falconKey, want: true},
		{name: "distinct key", witnessType: witness.Falcon1024V1, witnessKey: otherFalconKey},
		{name: "whole spending key", witnessType: witness.Falcon1024V1, witnessKey: spendingKey, want: true},
		{name: "unknown witness type", witnessType: "test.unknown-witness.v1", witnessKey: otherFalconKey, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := provider.spendingKeyHolds(spendingKey, test.witnessType, test.witnessKey)
			if test.wantErr {
				if err == nil || !strings.Contains(err.Error(), "has no signature construction") {
					t.Fatalf("spendingKeyHolds() error = %v, want an unknown-witness error", err)
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("spendingKeyHolds() = %v, %v, want %v", got, err, test.want)
			}
		})
	}
}
