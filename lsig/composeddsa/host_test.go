// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package composeddsa

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/hostmeta"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
	"github.com/aplane-algo/aplane/internal/sigconstruction"
	"github.com/aplane-algo/aplane/internal/tealtemplate"
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
	want := hostmeta.AppendField(nil, []byte(boundedBehaviorParametersDomainV1))
	want = binary.BigEndian.AppendUint32(want, 1)
	want = hostmeta.AppendField(want, []byte(def.Name))
	want = hostmeta.AppendField(want, []byte(def.Type))
	want = hostmeta.AppendField(want, nil)
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
	profile := &HostProfile{
		Contract: BoundedContract, Bounds: &ProfileBounds{SpendEffects: []txeffects.SpendEffect{txeffects.SpendEffectPay}, MaxFee: new(uint64(1_000))},
		Rekey: hostmeta.RekeyRefused,
		Cosigner: &hostmeta.CosignerAuthorization{
			Contract: hostmeta.CosignerContractV1, ComponentKeyType: hostmeta.DefaultCosignerComponentKeyType,
			SignatureMaxSize: hostmeta.DefaultCosignerSignatureMaxSize, RequiredOn: []string{hostmeta.PathSpend},
		},
	}
	metadata := &hostmeta.Metadata{
		Contract: BoundedContract, BaseSignatureArgLayout: SignatureArgLayout{Count: 1, MaxSizes: []int{4}},
		Bounds: &hostmeta.Bounds{SpendEffects: []string{hostmeta.SpendEffectPay}, MaxFee: new(uint64(1_000)), Layer3Policy: hostmeta.Layer3PolicyCustom}, Rekey: hostmeta.RekeyRefused, Cosigner: profile.Cosigner,
		ArgumentLayout: []hostmeta.ArgumentSlot{
			{Index: 0, Name: "base_signature_0", Source: hostmeta.ArgSourceBaseSignature, MaxSize: 4, Paths: hostmeta.ArgumentPathMask{Spend: hostmeta.ArgRequired, SpendingRekey: hostmeta.ArgRequired, ListedRekey: hostmeta.ArgRequired}},
			{Index: 1, Name: hostmeta.CosignerSignatureSlot, Source: hostmeta.ArgSourceCosigner, MaxSize: hostmeta.DefaultCosignerSignatureMaxSize, Paths: hostmeta.ArgumentPathMask{Spend: hostmeta.ArgRequired, SpendingRekey: hostmeta.ArgForbidden, ListedRekey: hostmeta.ArgForbidden}},
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

func TestHostMetadataSnapshotsCosignerContract(t *testing.T) {
	profile := &HostProfile{
		Contract: BoundedContract, Bounds: &ProfileBounds{SpendEffects: []txeffects.SpendEffect{txeffects.SpendEffectPay}, MaxFee: new(uint64(1_000))},
		Rekey: hostmeta.RekeyRefused,
		Cosigner: &hostmeta.CosignerAuthorization{
			Contract: hostmeta.CosignerContractV1, ComponentKeyType: hostmeta.DefaultCosignerComponentKeyType,
			SignatureMaxSize: hostmeta.DefaultCosignerSignatureMaxSize, RequiredOn: []string{hostmeta.PathSpend},
		},
	}
	provider := newBoundedTestProvider(profile)
	teal, err := provider.GenerateTEAL(
		[]byte{0x01},
		map[string]string{CosignerPublicKeyParameter: strings.Repeat("42", hostmeta.DefaultCosignerPublicKeySize)},
	)
	if err != nil {
		t.Fatalf("GenerateTEAL() error = %v", err)
	}
	assertOrderedMarkers(t, teal,
		hostCosignerLabel+":",
		"pushbytes 0x41504c414e455f434f5349474e45525f5631\npushbytes 0x02\nconcat\ntxn TxID\nconcat\nsha512_256",
		"arg 1\npushbytes 0x"+strings.Repeat("42", hostmeta.DefaultCosignerPublicKeySize)+"\nfalcon_verify\nassert",
		"retsub",
		hostSpendLabel+":",
		"callsub "+hostCosignerLabel,
		"b "+boundedLayer3Label,
		boundedLayer3Label+":",
		"// LAYER3_TEST_POLICY",
	)
	if strings.Index(teal, hostRekeyLabel+":") >= strings.Index(teal, hostCosignerLabel+":") {
		t.Fatalf("rekey path is not dispatched before the cosigner check:\n%s", teal)
	}
	spendingPublicKey := bytes.Repeat([]byte{0x31}, hostmeta.DefaultCosignerPublicKeySize)
	cosignerPublicKey := bytes.Repeat([]byte{0x42}, hostmeta.DefaultCosignerPublicKeySize)
	metadata, err := provider.BuildHostMetadata(
		spendingPublicKey,
		map[string]string{CosignerPublicKeyParameter: hex.EncodeToString(cosignerPublicKey)},
		bytes.Repeat([]byte{0x02}, 100),
	)
	if err != nil {
		t.Fatalf("BuildHostMetadata() error = %v", err)
	}
	wantID, err := witness.ID(hostmeta.DefaultCosignerComponentKeyType, cosignerPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Cosigner == nil || metadata.Cosigner.ComponentKeyID != wantID || metadata.Cosigner.PublicKeyHex != hex.EncodeToString(cosignerPublicKey) {
		t.Fatalf("Cosigner = %#v", metadata.Cosigner)
	}
	if got, want := metadata.ArgumentBytesForPath(hostmeta.PathSpend), 4+hostmeta.DefaultCosignerSignatureMaxSize; got != want {
		t.Fatalf("spend argument bytes = %d, want %d", got, want)
	}
	if _, err := provider.BuildHostMetadata(
		cosignerPublicKey,
		map[string]string{CosignerPublicKeyParameter: hex.EncodeToString(cosignerPublicKey)},
		[]byte{1},
	); err == nil || !strings.Contains(err.Error(), "must differ from the spending key") {
		t.Fatalf("collision error = %v", err)
	}
}

func TestBoundedComposerEmitsOrderedEnvelope(t *testing.T) {
	provider := newBoundedTestProvider(&HostProfile{
		Contract: BoundedContract,
		Bounds:   &ProfileBounds{SpendEffects: []txeffects.SpendEffect{txeffects.SpendEffectAxfer, txeffects.SpendEffectPay}, MaxFee: new(uint64(7_000))},
		Rekey:    hostmeta.RekeySpendingKey,
	})
	teal, err := provider.GenerateTEAL([]byte{1}, nil)
	if err != nil {
		t.Fatalf("GenerateTEAL() error = %v", err)
	}

	assertOrderedMarkers(t, teal,
		"// BOUNDED_TEST_VERIFIER",
		"// === bounded transaction envelope ===",
		"txn Fee\npushint 7000\n<=\nassert",
		"txn RekeyTo\nglobal ZeroAddress\n!=\nbnz "+hostRekeyLabel,
		hostRekeyLabel+":",
		hostSpendLabel+":",
		"// LAYER3_TEST_POLICY",
		hostAcceptLabel+":",
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
	provider := newBoundedTestProvider(&HostProfile{
		Contract: BoundedContract, Bounds: &ProfileBounds{SpendEffects: []txeffects.SpendEffect{txeffects.SpendEffectPay}, MaxFee: new(uint64(1_000))},
		Rekey: hostmeta.RekeyRefused,
	})
	teal, err := provider.GenerateTEAL([]byte{1}, nil)
	if err != nil {
		t.Fatalf("GenerateTEAL() error = %v", err)
	}
	if !strings.Contains(teal, hostRekeyLabel+":\nerr") {
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
	provider := newBoundedTestProvider(&HostProfile{
		Contract: BoundedContract, Bounds: &ProfileBounds{SpendEffects: []txeffects.SpendEffect{txeffects.SpendEffectPay}, MaxFee: new(uint64(1_000))},
		Rekey: hostmeta.RekeySpendingKey,
	})
	teal, err := provider.GenerateTEAL([]byte{1}, nil)
	if err != nil {
		t.Fatalf("GenerateTEAL() error = %v", err)
	}
	rekey := strings.Index(teal, hostRekeyLabel+":")
	spend := strings.Index(teal, hostSpendLabel+":")
	policy := strings.Index(teal, "// LAYER3_TEST_POLICY")
	if rekey < 0 || spend < 0 || rekey >= spend || policy < spend {
		t.Fatalf("rekey path at %d, spend path at %d, Layer 3 at %d:\n%s", rekey, spend, policy, teal)
	}
	branch := teal[rekey:spend]
	if !strings.HasPrefix(branch, hostRekeyLabel+":\ntxn TypeEnum\npushint 1\n==\nassert\n") ||
		!strings.HasSuffix(branch, "b "+hostAcceptLabel+"\n\n") {
		t.Fatalf("spending-key rekey does not check a pure payment and accept:\n%s", branch)
	}
	for _, field := range []string{"CloseRemainderTo", "AssetCloseTo", "AssetSender"} {
		if !strings.Contains(branch, "txn "+field+"\nglobal ZeroAddress\n==\nassert") {
			t.Fatalf("spending-key rekey does not require a zero %s:\n%s", field, branch)
		}
	}
	if strings.Contains(branch, hostSpendLabel) || strings.Contains(branch, boundedLayer3Label) || strings.Contains(branch, "LAYER3_TEST_POLICY") {
		t.Fatalf("spending-key rekey reaches the spend path:\n%s", branch)
	}
}

// A cosigned spending-key rekey needs the cosigner, named in the record, and
// calls the same cosigner check the spend path does: the cosigner's key compiles
// once.
func TestBoundedCosignedRekeyCallsTheCosignerCheck(t *testing.T) {
	cosignerKey := strings.Repeat("42", hostmeta.DefaultCosignerPublicKeySize)
	profile := &HostProfile{
		Contract: BoundedContract, Bounds: &ProfileBounds{SpendEffects: []txeffects.SpendEffect{txeffects.SpendEffectPay}, MaxFee: new(uint64(1_000))},
		Rekey: hostmeta.RekeySpendingKey,
		Cosigner: &hostmeta.CosignerAuthorization{
			Contract: hostmeta.CosignerContractV1, ComponentKeyType: hostmeta.DefaultCosignerComponentKeyType,
			SignatureMaxSize: hostmeta.DefaultCosignerSignatureMaxSize, RequiredOn: []string{hostmeta.PathSpend},
		},
	}
	params := map[string]string{CosignerPublicKeyParameter: cosignerKey}
	if _, err := newBoundedTestProvider(profile).GenerateTEAL([]byte{1}, params); err == nil ||
		!strings.Contains(err.Error(), "exactly [spend, spending_rekey] with rekey spending_key") {
		t.Fatalf("a spend-only cosigner beside a spending-key rekey: error = %v", err)
	}
	profile.Cosigner.RequiredOn = hostmeta.CosignerRequiredOn(hostmeta.RekeySpendingKey)
	teal, err := newBoundedTestProvider(profile).GenerateTEAL([]byte{1}, params)
	if err != nil {
		t.Fatalf("GenerateTEAL() error = %v", err)
	}
	rekey := strings.Index(teal, hostRekeyLabel+":")
	check := strings.Index(teal, hostCosignerLabel+":")
	spend := strings.Index(teal, hostSpendLabel+":")
	if rekey < 0 || check < rekey || spend < check {
		t.Fatalf("rekey at %d, cosigner check at %d, spend at %d:\n%s", rekey, check, spend, teal)
	}
	if branch := teal[rekey:check]; !strings.HasSuffix(branch, "callsub "+hostCosignerLabel+"\nb "+hostAcceptLabel+"\n\n") {
		t.Fatalf("the cosigned rekey does not call the cosigner check and accept:\n%s", branch)
	}
	if !strings.HasSuffix(teal[check:spend], "assert\nretsub\n\n") {
		t.Fatalf("the cosigner check is not a subroutine:\n%s", teal[check:spend])
	}
	if !strings.HasPrefix(teal[spend:], hostSpendLabel+":\ncallsub "+hostCosignerLabel+"\n") {
		t.Fatalf("the spend path does not call the cosigner check:\n%s", teal[spend:])
	}
	if n := strings.Count(teal, cosignerKey); n != 1 {
		t.Fatalf("the cosigner key compiles %d times, want once", n)
	}
}

func TestBoundedRejectsInvalidProfilesAndCapabilities(t *testing.T) {
	valid := &HostProfile{
		Contract: BoundedContract, Bounds: &ProfileBounds{SpendEffects: []txeffects.SpendEffect{txeffects.SpendEffectPay}, MaxFee: new(uint64(1_000))},
		Rekey: hostmeta.RekeyRefused,
	}
	tests := []struct {
		name string
		make func() *ComposedDSA
		want string
	}{
		{
			name: "no fee ceiling",
			make: func() *ComposedDSA {
				profile := cloneHostProfile(valid)
				profile.Bounds.MaxFee = nil
				return newBoundedTestProvider(profile)
			},
			want: BoundedContract + " requires max_fee",
		},
		{
			name: "denied spend effect",
			make: func() *ComposedDSA {
				profile := cloneHostProfile(valid)
				profile.Bounds.SpendEffects = []txeffects.SpendEffect{txeffects.SpendEffect("appl")}
				return newBoundedTestProvider(profile)
			},
			want: "unsupported spend effect",
		},
		{
			name: "missing rekey setting",
			make: func() *ComposedDSA {
				profile := cloneHostProfile(valid)
				profile.Rekey = ""
				return newBoundedTestProvider(profile)
			},
			want: `unsupported rekey setting ""`,
		},
		{
			name: "unknown rekey setting",
			make: func() *ComposedDSA {
				profile := cloneHostProfile(valid)
				profile.Rekey = "admin_key"
				return newBoundedTestProvider(profile)
			},
			want: `unsupported rekey setting "admin_key"`,
		},
		{
			name: "reserved label",
			make: func() *ComposedDSA {
				provider := newBoundedTestProvider(valid)
				provider.tealSuffix = hostSpendLabel + ":\nint 1\nassert"
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
	for _, ceiling := range []uint64{0, 1_000, 10_000, 10_001, 20_000, hostmeta.MaxFeeLimit} {
		t.Run(strconv.FormatUint(ceiling, 10), func(t *testing.T) {
			provider := newBoundedTestProvider(&HostProfile{
				Contract: BoundedContract, Bounds: &ProfileBounds{SpendEffects: []txeffects.SpendEffect{txeffects.SpendEffectPay}, MaxFee: new(ceiling)},
				Rekey: hostmeta.RekeyRefused,
			})
			teal, err := provider.GenerateTEAL([]byte{1}, nil)
			if err != nil {
				t.Fatalf("GenerateTEAL() error = %v", err)
			}
			if want := fmt.Sprintf("txn Fee\npushint %d\n<=\nassert\n", ceiling); !strings.Contains(teal, want) {
				t.Fatalf("fee check %q missing:\n%s", want, teal)
			}
			metadata := provider.HostMetadata()
			if metadata == nil || metadata.FeeCeiling() == nil || *metadata.FeeCeiling() != ceiling {
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
	if hostmeta.MaxFeeLimit != 9007199254740991 {
		t.Fatalf("MaxFeeLimit = %d", hostmeta.MaxFeeLimit)
	}
	for _, ceiling := range []uint64{hostmeta.MaxFeeLimit + 1, 1 << 63, math.MaxUint64} {
		t.Run(strconv.FormatUint(ceiling, 10), func(t *testing.T) {
			profile := &HostProfile{
				Contract: BoundedContract, Bounds: &ProfileBounds{SpendEffects: []txeffects.SpendEffect{txeffects.SpendEffectPay}, MaxFee: new(ceiling)},
				Rekey: hostmeta.RekeyRefused,
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
	profileA := &HostProfile{
		Contract: BoundedContract, Bounds: &ProfileBounds{SpendEffects: []txeffects.SpendEffect{txeffects.SpendEffectAxfer, txeffects.SpendEffectPay}, MaxFee: new(uint64(1_000))},
		Rekey: hostmeta.RekeyRefused,
	}
	profileB := cloneHostProfile(profileA)
	profileB.Bounds.SpendEffects = []txeffects.SpendEffect{txeffects.SpendEffectPay, txeffects.SpendEffectAxfer}
	if got, want := newBoundedTestProvider(profileA).CompatibilityFingerprint(), newBoundedTestProvider(profileB).CompatibilityFingerprint(); got != want {
		t.Fatalf("profile order changed fingerprint: %s != %s", got, want)
	}
	profileB.Bounds.MaxFee = new(*profileB.Bounds.MaxFee + 1)
	if newBoundedTestProvider(profileA).CompatibilityFingerprint() == newBoundedTestProvider(profileB).CompatibilityFingerprint() {
		t.Fatal("max_fee did not change fingerprint")
	}
	profileC := cloneHostProfile(profileA)
	profileC.Rekey = hostmeta.RekeySpendingKey
	if newBoundedTestProvider(profileA).CompatibilityFingerprint() == newBoundedTestProvider(profileC).CompatibilityFingerprint() {
		t.Fatal("rekey setting did not change fingerprint")
	}
}

// A bounded account's arguments come from its stored layout, which the signer
// fills, so a bounded composer assembles none, cosigned or not.
func TestBoundedBuildArgsRefuses(t *testing.T) {
	for name, profile := range map[string]*HostProfile{
		"refused rekey": {
			Contract: BoundedContract, Bounds: &ProfileBounds{SpendEffects: []txeffects.SpendEffect{txeffects.SpendEffectPay}, MaxFee: new(uint64(1_000))},
			Rekey: hostmeta.RekeyRefused,
		},
		"cosigned": {
			Contract: BoundedContract, Bounds: &ProfileBounds{SpendEffects: []txeffects.SpendEffect{txeffects.SpendEffectPay}, MaxFee: new(uint64(1_000))},
			Rekey: hostmeta.RekeyRefused,
			Cosigner: &hostmeta.CosignerAuthorization{
				Contract: hostmeta.CosignerContractV1, ComponentKeyType: hostmeta.DefaultCosignerComponentKeyType,
				SignatureMaxSize: hostmeta.DefaultCosignerSignatureMaxSize, RequiredOn: []string{hostmeta.PathSpend},
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			provider := newBoundedTestProvider(profile)
			for _, signature := range [][]byte{{1, 2, 3, 4}, nil} {
				args, err := provider.BuildArgs(signature, nil)
				if !errors.Is(err, errHostBuildArgs) || args != nil {
					t.Fatalf("BuildArgs(%x) = %v, %v, want %v", signature, args, err, errHostBuildArgs)
				}
			}
			if got, want := errHostBuildArgs.Error(), "bounded accounts are assembled from their stored metadata"; got != want {
				t.Fatalf("refusal = %q, want %q", got, want)
			}
		})
	}
}

// The stored layout keeps a derived slot ahead of a runtime argument, so the
// runtime argument's index does not depend on whether a proof is supplied.
func TestBoundedLayoutPutsDerivedSlotBeforeRuntimeArg(t *testing.T) {
	provider := NewComposedDSA(Config{
		KeyType:      "aplane.test-bounded-args.v1",
		BaseKeyType:  "aplane.falcon1024.v1",
		FamilyName:   "aplane.test",
		Version:      1,
		Ops:          boundedTestOps{},
		SaltStyle:    lsigsalt.StyleNone,
		TemplateMode: "generated",
		TEALSuffix:   "int 1\nassert",
		Params: []lsigprovider.ParameterDef{{
			Name: "recipients", Type: "address[]", Required: true, MinItems: 1, MaxItems: 30,
		}},
		RuntimeArgs: []lsigprovider.RuntimeArgDef{{
			Name: "preimage", Type: "bytes", Required: true, MaxSize: 64,
		}},
		DerivedArgs: []hostmeta.DerivedArg{{
			Name: "merkle_proof", Kind: hostmeta.DerivedArgMerkleProof,
			Parameter: "recipients", MaxSize: hostmeta.MerkleProofSize,
		}},
		Host: &HostProfile{
			Contract: BoundedContract, Bounds: &ProfileBounds{SpendEffects: []txeffects.SpendEffect{txeffects.SpendEffectPay}, MaxFee: new(uint64(1_000))},
			Rekey: hostmeta.RekeyRefused,
		},
	})

	metadata := provider.HostMetadata()
	if metadata == nil {
		t.Fatal("HostMetadata() = nil")
	}
	var got []string
	for i, slot := range metadata.ArgumentLayout {
		if slot.Index != i {
			t.Fatalf("slot %q has index %d at position %d", slot.Name, slot.Index, i)
		}
		got = append(got, slot.Name+":"+slot.Source)
	}
	want := []string{"base_signature_0:" + hostmeta.ArgSourceBaseSignature, "merkle_proof:" + hostmeta.ArgSourceDerived, "preimage:" + hostmeta.ArgSourceRuntime}
	if !slices.Equal(got, want) {
		t.Fatalf("argument layout = %v, want %v", got, want)
	}
}

func TestBoundedDefaultsHaveOneProgramAndBehaviorEncoding(t *testing.T) {
	provider := NewComposedDSA(Config{
		KeyType:      "aplane.test-bounded-default.v1",
		BaseKeyType:  "aplane.falcon1024.v1",
		FamilyName:   "aplane.test",
		Version:      1,
		Ops:          boundedTestOps{},
		SaltStyle:    lsigsalt.StyleNone,
		TemplateMode: "generated",
		TEALSuffix:   "txn Fee\nint @limit\n<=\nassert",
		Params: []lsigprovider.ParameterDef{{
			Name: "limit", Type: "uint64", Default: "100",
		}},
		Host: &HostProfile{
			Contract: BoundedContract,
			Bounds:   &ProfileBounds{SpendEffects: []txeffects.SpendEffect{txeffects.SpendEffectPay}, MaxFee: new(uint64(1_000))},
			Rekey:    hostmeta.RekeySpendingKey,
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
		if _, err := provider.BuildHostMetadata([]byte{1}, params, []byte{1, 2, 3}); err != nil {
			t.Fatalf("BuildHostMetadata(input %d) error = %v", i, err)
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
		TemplateMode: "generated",
		TEALSuffix:   "// LEGACY_POLICY\nint 1\nassert",
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

func newBoundedTestProvider(profile *HostProfile) *ComposedDSA {
	return NewComposedDSA(Config{
		KeyType:      "aplane.test-bounded.v1",
		BaseKeyType:  "aplane.falcon1024.v1",
		FamilyName:   "aplane.test",
		Version:      1,
		Ops:          boundedTestOps{},
		SaltStyle:    lsigsalt.StyleNone,
		TemplateMode: "generated",
		TEALSuffix:   "// LAYER3_TEST_POLICY\nint 1\nassert",
		Host:         profile,
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

// The framework's names are refused wherever a template could use one: the
// bounded_ prefix, and the rekey-to list root, which has no prefix and is
// reserved by name. Only key generation writes the root.
func TestReservedFrameworkNamesAreRefusedEverywhere(t *testing.T) {
	profile := &HostProfile{
		Contract: BoundedContract, Rekey: hostmeta.RekeyRefused,
		Bounds: &ProfileBounds{SpendEffects: []txeffects.SpendEffect{txeffects.SpendEffectPay}, MaxFee: new(uint64(1_000))},
	}
	check := func(params []lsigprovider.ParameterDef, runtimeArgs []lsigprovider.RuntimeArgDef, variables []tealtemplate.TemplateVariable, teal string) error {
		return validateHostReservedNames(profile, params, runtimeArgs, nil, variables, teal)
	}
	for name, reason := range map[string]string{
		hostmeta.RekeyListRootParameter: "the reserved rekey-to list root name",
		"bounded_example":               "reserved bounded_ prefix",
	} {
		for place, err := range map[string]error{
			"parameter":                     check([]lsigprovider.ParameterDef{{Name: name}}, nil, nil, ""),
			"runtime argument":              check(nil, []lsigprovider.RuntimeArgDef{{Name: name}}, nil, ""),
			"template variable":             check(nil, nil, []tealtemplate.TemplateVariable{{Name: name}}, ""),
			"template variable's parameter": check(nil, nil, []tealtemplate.TemplateVariable{{Name: "TMPL_ROOT", Parameter: name}}, ""),
			"author TEAL":                   check(nil, nil, nil, "byte @"+name+"\npop"),
			"author TEAL list reference":    check(nil, nil, nil, "{{range @"+name+"}}\naddr {{.}}\n{{end}}"),
		} {
			if err == nil || !strings.Contains(err.Error(), name) || !strings.Contains(err.Error(), reason) {
				t.Errorf("%s named %s: error = %v, want it refused as %s", place, name, err, reason)
			}
		}
	}
	// The reservation is the exact name, not everything that starts with it.
	if err := check([]lsigprovider.ParameterDef{{Name: hostmeta.RekeyListRootParameter + "s"}}, nil, nil, ""); err != nil {
		t.Fatalf("a name that only starts with the root's: error = %v", err)
	}
	if hostmeta.RekeyListRootParameter != "rekey_to_root" {
		t.Fatalf("the root parameter is %q; key files and /keys carry it as rekey_to_root", hostmeta.RekeyListRootParameter)
	}
}

// A bounded profile needs its bounds, and the metadata a composer stores must
// carry the same envelope as the profile it compiled: a metadata record whose
// fee ceiling or spend effects differ, or that has none, is not that
// profile's.
func TestBoundedProfileAndMetadataAgreeOnTheBounds(t *testing.T) {
	if _, err := canonicalBoundedProfile(&HostProfile{Contract: BoundedContract, Rekey: hostmeta.RekeyRefused}); err == nil ||
		!strings.Contains(err.Error(), "bounded2 requires bounds") {
		t.Fatalf("a bounded profile without bounds: error = %v", err)
	}
	provider := newBoundedTestProvider(&HostProfile{
		Contract: BoundedContract, Rekey: hostmeta.RekeyRefused,
		Bounds: &ProfileBounds{SpendEffects: []txeffects.SpendEffect{txeffects.SpendEffectPay}, MaxFee: new(uint64(1_000))},
	})
	profile := provider.HostProfile()
	if _, err := CanonicalBoundedProfile(profile, provider.HostMetadata()); err != nil {
		t.Fatalf("CanonicalBoundedProfile() error = %v", err)
	}
	for name, mutate := range map[string]func(*hostmeta.Metadata){
		"another fee ceiling":  func(m *hostmeta.Metadata) { *m.Bounds.MaxFee++ },
		"another spend effect": func(m *hostmeta.Metadata) { m.Bounds.SpendEffects = []string{hostmeta.SpendEffectAssetOptIn} },
		"one more spend effect": func(m *hostmeta.Metadata) {
			m.Bounds.SpendEffects = append(m.Bounds.SpendEffects, hostmeta.SpendEffectAssetOptIn)
		},
	} {
		t.Run(name, func(t *testing.T) {
			metadata := hostmeta.Clone(provider.HostMetadata())
			mutate(metadata)
			if _, err := CanonicalBoundedProfile(profile, metadata); err == nil || !strings.Contains(err.Error(), "does not match the authorization profile") {
				t.Fatalf("CanonicalBoundedProfile() error = %v, want the mismatch refused", err)
			}
		})
	}
}
