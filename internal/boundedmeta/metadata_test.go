// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package boundedmeta

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/witness"
)

func TestMetadataValidateRejectsInvalidContracts(t *testing.T) {
	base := Metadata{
		Contract:               Contract,
		BaseSignatureArgLayout: SignatureArgLayout{Count: 1, MaxSizes: []int{64}},
		ArgumentLayout:         BaseArgumentLayout(SignatureArgLayout{Count: 1, MaxSizes: []int{64}}),
		SpendEffects:           []string{"pay"},
		MaxFee:                 1_000,
		Rekey:                  RekeyRefused,
		Layer3Policy:           Layer3PolicyCustom,
	}
	tests := []struct {
		name   string
		mutate func(*Metadata)
		want   string
	}{
		{name: "derived args", mutate: func(m *Metadata) { m.DerivedArgs = []DerivedArg{{Name: "proof", Kind: "unknown"}} }, want: "invalid derived arg"},
		{name: "runtime args", mutate: func(m *Metadata) { m.RuntimeArgs = []RuntimeArg{{Name: "proof"}} }, want: "invalid runtime arg"},
		{name: "unknown spend", mutate: func(m *Metadata) { m.SpendEffects = []string{"appl"} }, want: "unsupported spend effect"},
		{name: "duplicate spend", mutate: func(m *Metadata) { m.SpendEffects = []string{"pay", "pay"} }, want: "duplicate spend effect"},
		{name: "fee ceiling", mutate: func(m *Metadata) { m.MaxFee = MaximumProfileFee + 1 }, want: "exceeds"},
		{name: "unknown Layer-3 policy", mutate: func(m *Metadata) { m.Layer3Policy = "open" }, want: "layer3_policy"},
		{name: "Merkle policy without proof", mutate: func(m *Metadata) { m.Layer3Policy = Layer3PolicyMerkleAllowlist }, want: "exactly one"},
		{name: "missing rekey setting", mutate: func(m *Metadata) { m.Rekey = "" }, want: `unsupported rekey setting ""`},
		{name: "unknown rekey setting", mutate: func(m *Metadata) { m.Rekey = "admin_key" }, want: `unsupported rekey setting "admin_key"`},
		// An account that refuses rekeys can't close either, so a transfer is the only way out.
		{name: "refused without pay", mutate: func(m *Metadata) { m.SpendEffects = []string{"axfer"} }, want: "needs pay in spend_effects"},
		{name: "refused opt-in without axfer", mutate: func(m *Metadata) { m.SpendEffects = []string{"pay", "asset_opt_in"} }, want: "needs axfer in spend_effects"},
		// No host rule gates a rekey, so this would leave the lock before the unlock round.
		{name: "timelock with a spending-key rekey", mutate: func(m *Metadata) {
			m.Layer3Policy, m.Rekey = Layer3PolicyTimelock, RekeySpendingKey
		}, want: "timelock requires rekey refused"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metadata := Clone(&base)
			tt.mutate(metadata)
			if err := metadata.Validate(); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestMetadataValidateCombinedLayer3Policies(t *testing.T) {
	layout := SignatureArgLayout{Count: 1, MaxSizes: []int{64}}
	proof := DerivedArg{Name: "merkle_proof", Kind: DerivedArgMerkleProof, Parameter: "recipients", MaxSize: MerkleProofSize}
	metadata := func(policy string, derived ...DerivedArg) *Metadata {
		slots := BaseArgumentLayout(layout)
		for _, arg := range derived {
			slots = append(slots, ArgumentSlot{
				Index: len(slots), Name: arg.Name, Source: ArgSourceDerived, MaxSize: arg.MaxSize,
				Paths: ArgumentPathMask{Spend: ArgOptional, SpendingRekey: ArgForbidden},
			})
		}
		return &Metadata{
			Contract: Contract, BaseSignatureArgLayout: layout, ArgumentLayout: slots,
			SpendEffects: []string{"pay"}, MaxFee: 1_000, Rekey: RekeyRefused, Layer3Policy: policy, DerivedArgs: derived,
		}
	}
	withRuntimeArg := func(input *Metadata) *Metadata {
		input.RuntimeArgs = []RuntimeArg{{Name: "extra", Type: "bytes", Required: true, MaxSize: 8}}
		input.ArgumentLayout = append(input.ArgumentLayout, ArgumentSlot{
			Index: len(input.ArgumentLayout), Name: "extra", Source: ArgSourceRuntime, MaxSize: 8,
			Paths: ArgumentPathMask{Spend: ArgRequired, SpendingRekey: ArgForbidden},
		})
		return input
	}
	for _, test := range []struct {
		name    string
		input   *Metadata
		wantErr string
	}{
		{name: "fixed", input: metadata(Layer3PolicyFixedAllowlistCustom)},
		{name: "merkle", input: metadata(Layer3PolicyMerkleAllowlistCustom, proof)},
		{name: "fixed takes no proof", input: metadata(Layer3PolicyFixedAllowlistCustom, proof), wantErr: "must not declare derived arguments"},
		{name: "merkle needs a proof", input: metadata(Layer3PolicyMerkleAllowlistCustom), wantErr: "requires exactly one derived"},
		{name: "vocabulary stays closed", input: metadata("timelock_custom"), wantErr: "unsupported bounded2 layer3_policy"},
		{name: "timelock", input: metadata(Layer3PolicyTimelock)},
		{name: "fixed timelock", input: metadata(Layer3PolicyFixedAllowlistTimelock)},
		{name: "merkle timelock", input: metadata(Layer3PolicyMerkleAllowlistTimelock, proof)},
		{name: "timelock takes no proof", input: metadata(Layer3PolicyTimelock, proof), wantErr: "must not declare derived arguments"},
		{name: "fixed timelock takes no proof", input: metadata(Layer3PolicyFixedAllowlistTimelock, proof), wantErr: "must not declare derived arguments"},
		{name: "merkle timelock needs a proof", input: metadata(Layer3PolicyMerkleAllowlistTimelock), wantErr: "requires exactly one derived"},
		{name: "timelock takes no runtime argument", input: withRuntimeArg(metadata(Layer3PolicyTimelock)), wantErr: "must not declare runtime arguments"},
		{name: "fixed timelock takes no runtime argument", input: withRuntimeArg(metadata(Layer3PolicyFixedAllowlistTimelock)), wantErr: "must not declare runtime arguments"},
		{name: "merkle timelock takes no runtime argument", input: withRuntimeArg(metadata(Layer3PolicyMerkleAllowlistTimelock, proof)), wantErr: "must not declare runtime arguments"},
		{name: "combined allowlist keeps its runtime argument", input: withRuntimeArg(metadata(Layer3PolicyFixedAllowlistCustom))},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := test.input.ValidateProfile()
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateProfile() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("ValidateProfile() error = %v, want %q", err, test.wantErr)
			}
		})
	}
}

func TestMetadataArgumentLayoutPathSizes(t *testing.T) {
	metadata := &Metadata{
		Contract:               Contract,
		BaseSignatureArgLayout: SignatureArgLayout{Count: 1, MaxSizes: []int{64}},
		SpendEffects:           []string{SpendEffectPay},
		MaxFee:                 2_000,
		Rekey:                  RekeySpendingKey,
		DerivedArgs:            []DerivedArg{{Name: "proof", Kind: DerivedArgMerkleProof, Parameter: "recipients", MaxSize: MerkleProofSize}},
		RuntimeArgs:            []RuntimeArg{{Name: "preimage", Type: "bytes", Required: true, ByteLength: 32, MaxSize: 32}},
		Layer3Policy:           Layer3PolicyCustom,
		ArgumentLayout: []ArgumentSlot{
			{Index: 0, Name: "base_signature_0", Source: ArgSourceBaseSignature, MaxSize: 64, Paths: ArgumentPathMask{Spend: ArgRequired, SpendingRekey: ArgRequired}},
			{Index: 1, Name: "proof", Source: ArgSourceDerived, MaxSize: MerkleProofSize, Paths: ArgumentPathMask{Spend: ArgOptional, SpendingRekey: ArgForbidden}},
			{Index: 2, Name: "preimage", Source: ArgSourceRuntime, MaxSize: 32, Paths: ArgumentPathMask{Spend: ArgRequired, SpendingRekey: ArgForbidden}},
		},
	}
	if err := metadata.ValidateProfile(); err != nil {
		t.Fatalf("ValidateProfile() error = %v", err)
	}
	if got, want := metadata.ArgumentBytesForPath(PathSpend), 64+MerkleProofSize+32; got != want {
		t.Fatalf("spend argument bytes = %d, want %d", got, want)
	}
	if got, want := metadata.ArgumentBytesForPath(PathSpendingRekey), 64; got != want {
		t.Fatalf("spending-rekey argument bytes = %d, want %d", got, want)
	}
	// bounded1's admin_rekey path is gone: it names no path, so it has no bytes.
	if got := metadata.ArgumentBytesForPath("admin_rekey"); got != 0 {
		t.Fatalf("admin_rekey argument bytes = %d, want 0", got)
	}
}

func TestMetadataValidateCosignerAuthorization(t *testing.T) {
	publicKey := bytes.Repeat([]byte{0x6b}, CosignerPublicKeySizeV1)
	componentKeyID, err := witness.ID(CosignerComponentKeyTypeV1, publicKey)
	if err != nil {
		t.Fatalf("witness.ID() error = %v", err)
	}
	metadata := &Metadata{
		Contract:               Contract,
		BaseSignatureArgLayout: SignatureArgLayout{Count: 1, MaxSizes: []int{1280}},
		SpendEffects:           []string{SpendEffectPay},
		MaxFee:                 1_000,
		Rekey:                  RekeyRefused,
		Layer3Policy:           Layer3PolicyCustom,
		Cosigner: &CosignerAuthorization{
			Contract: CosignerContractV1, ComponentKeyType: CosignerComponentKeyTypeV1,
			PublicKeyHex: hex.EncodeToString(publicKey), ComponentKeyID: componentKeyID,
			SignatureMaxSize: CosignerSignatureMaxSizeV1, RequiredOn: []string{PathSpend},
		},
		ArgumentLayout: []ArgumentSlot{
			{Index: 0, Name: "base_signature_0", Source: ArgSourceBaseSignature, MaxSize: 1280, Paths: ArgumentPathMask{Spend: ArgRequired, SpendingRekey: ArgRequired}},
			{Index: 1, Name: CosignerSignatureSlot, Source: ArgSourceCosigner, MaxSize: CosignerSignatureMaxSizeV1, Paths: ArgumentPathMask{Spend: ArgRequired, SpendingRekey: ArgForbidden}},
		},
	}
	if err := metadata.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if got, want := metadata.ArgumentBytesForPath(PathSpend), 1280+CosignerSignatureMaxSizeV1; got != want {
		t.Fatalf("spend argument bytes = %d, want %d", got, want)
	}
	if got, want := metadata.ArgumentBytesForPath(PathSpendingRekey), 1280; got != want {
		t.Fatalf("spending-rekey argument bytes = %d, want %d", got, want)
	}

	cloned := Clone(metadata)
	if !metadata.Equal(cloned) || cloned.Cosigner == metadata.Cosigner {
		t.Fatalf("Clone() did not deep-copy cosigner metadata: %#v", cloned.Cosigner)
	}
	cloned.Cosigner.RequiredOn[0] = PathSpendingRekey
	if metadata.Equal(cloned) {
		t.Fatal("cosigner RequiredOn change not detected")
	}

	badID := Clone(metadata)
	badID.Cosigner.ComponentKeyID = strings.Repeat("A", len(componentKeyID))
	if err := badID.Validate(); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("Validate() error = %v, want cosigner key-ID mismatch", err)
	}
	badPath := Clone(metadata)
	badPath.Cosigner.RequiredOn = []string{PathSpendingRekey}
	if err := badPath.ValidateProfile(); err == nil || !strings.Contains(err.Error(), "exactly [spend]") {
		t.Fatalf("ValidateProfile() error = %v, want path rejection", err)
	}
	spendingRekey := Clone(metadata)
	spendingRekey.Rekey = RekeySpendingKey
	if err := spendingRekey.ValidateProfile(); err == nil || !strings.Contains(err.Error(), "bounded cosigner profiles do not support a spending_key rekey") {
		t.Fatalf("ValidateProfile() error = %v, want bounded-cosigner spending-rekey rejection", err)
	}
}

func TestMetadataEqual(t *testing.T) {
	base := func() *Metadata {
		return &Metadata{
			Contract:               Contract,
			BaseSignatureArgLayout: SignatureArgLayout{Count: 1, MaxSizes: []int{1280}},
			ArgumentLayout:         BaseArgumentLayout(SignatureArgLayout{Count: 1, MaxSizes: []int{1280}}),
			SpendEffects:           []string{"pay"},
			MaxFee:                 5000,
			Rekey:                  RekeySpendingKey,
			Layer3Policy:           Layer3PolicyCustom,
		}
	}

	if !base().Equal(base()) {
		t.Fatal("identical metadata records compare unequal")
	}

	// nil and empty slices must compare equal: JSON-decoded records carry nil,
	// Clone-normalized records carry empty.
	jsonLike := base()
	jsonLike.RuntimeArgs = nil
	cloned := Clone(base())
	if !jsonLike.Equal(cloned) {
		t.Fatal("nil vs Clone-normalized empty slices compare unequal")
	}

	changed := base()
	changed.MaxFee = 4999
	if base().Equal(changed) {
		t.Fatal("MaxFee change not detected")
	}
	changed = base()
	changed.Rekey = RekeyRefused
	if base().Equal(changed) {
		t.Fatal("Rekey change not detected")
	}
	changed = base()
	changed.ArgumentLayout[0].Paths.Spend = ArgForbidden
	if base().Equal(changed) {
		t.Fatal("ArgumentLayout change not detected")
	}
	var nilMeta *Metadata
	if nilMeta.Equal(base()) || base().Equal(nilMeta) {
		t.Fatal("nil vs non-nil compare equal")
	}
	if !nilMeta.Equal(nil) {
		t.Fatal("nil vs nil compare unequal")
	}
}

// TestMetadataEqualCoversAllFields forces Equal to be updated when the
// Metadata struct grows a field: bump the count only alongside Equal.
func TestMetadataEqualCoversAllFields(t *testing.T) {
	if n := reflect.TypeOf(Metadata{}).NumField(); n != 10 {
		t.Fatalf("Metadata has %d fields; update Equal and this count together", n)
	}
}
