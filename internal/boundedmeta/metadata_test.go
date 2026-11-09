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
				Paths: ArgumentPathMask{Spend: ArgOptional, SpendingRekey: ArgForbidden, ListedRekey: ArgForbidden},
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
			Paths: ArgumentPathMask{Spend: ArgRequired, SpendingRekey: ArgForbidden, ListedRekey: ArgForbidden},
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
			{Index: 0, Name: "base_signature_0", Source: ArgSourceBaseSignature, MaxSize: 64, Paths: ArgumentPathMask{Spend: ArgRequired, SpendingRekey: ArgRequired, ListedRekey: ArgRequired}},
			{Index: 1, Name: "proof", Source: ArgSourceDerived, MaxSize: MerkleProofSize, Paths: ArgumentPathMask{Spend: ArgOptional, SpendingRekey: ArgForbidden, ListedRekey: ArgForbidden}},
			{Index: 2, Name: "preimage", Source: ArgSourceRuntime, MaxSize: 32, Paths: ArgumentPathMask{Spend: ArgRequired, SpendingRekey: ArgForbidden, ListedRekey: ArgForbidden}},
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
			{Index: 0, Name: "base_signature_0", Source: ArgSourceBaseSignature, MaxSize: 1280, Paths: ArgumentPathMask{Spend: ArgRequired, SpendingRekey: ArgRequired, ListedRekey: ArgRequired}},
			{Index: 1, Name: CosignerSignatureSlot, Source: ArgSourceCosigner, MaxSize: CosignerSignatureMaxSizeV1, Paths: ArgumentPathMask{Spend: ArgRequired, SpendingRekey: ArgForbidden, ListedRekey: ArgForbidden}},
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
	if err := badPath.ValidateProfile(); err == nil || !strings.Contains(err.Error(), "exactly [spend] with rekey refused") {
		t.Fatalf("ValidateProfile() error = %v, want path rejection", err)
	}
	// A cosigned spending-key rekey needs the cosigner on that path too, in the
	// record and in the slot's mask.
	spendingRekey := Clone(metadata)
	spendingRekey.Rekey = RekeySpendingKey
	if err := spendingRekey.ValidateProfile(); err == nil || !strings.Contains(err.Error(), "exactly [spend, spending_rekey] with rekey spending_key") {
		t.Fatalf("ValidateProfile() error = %v, want the cosigned rekey's required_on", err)
	}
	spendingRekey.Cosigner.RequiredOn = CosignerRequiredOn(RekeySpendingKey)
	if err := spendingRekey.ValidateProfile(); err == nil || !strings.Contains(err.Error(), "cosigner's required_on paths") {
		t.Fatalf("ValidateProfile() error = %v, want the cosigner slot's mask", err)
	}
	spendingRekey.ArgumentLayout[1].Paths = CosignerSlotPaths(spendingRekey.Cosigner)
	if err := spendingRekey.Validate(); err != nil {
		t.Fatalf("cosigned spending-key rekey: Validate() error = %v", err)
	}
	if got, want := spendingRekey.ArgumentBytesForPath(PathSpendingRekey), 1280+CosignerSignatureMaxSizeV1; got != want {
		t.Fatalf("cosigned spending-rekey argument bytes = %d, want %d", got, want)
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
	if n := reflect.TypeOf(Metadata{}).NumField(); n != 11 {
		t.Fatalf("Metadata has %d fields; update Equal and this count together", n)
	}
}

func listMetadata() *Metadata {
	layout := SignatureArgLayout{Count: 1, MaxSizes: []int{64}}
	slots := BaseArgumentLayout(layout)
	slots = append(slots, ArgumentSlot{
		Index: 1, Name: "rekey_list_proof", Source: ArgSourceDerived, MaxSize: RekeyListProofSize,
		Paths: ArgumentPathMask{Spend: ArgForbidden, SpendingRekey: ArgForbidden, ListedRekey: ArgRequired},
	})
	return &Metadata{
		Contract: Contract, BaseSignatureArgLayout: layout, ArgumentLayout: slots,
		SpendEffects: []string{"axfer"}, MaxFee: 1_000, Rekey: RekeyRefused, Layer3Policy: Layer3PolicyCustom,
		RekeyList:   &RekeyList{Contract: RekeyListContractV1, Depth: 4, RootHex: strings.Repeat("ab", 32)},
		DerivedArgs: []DerivedArg{{Name: "rekey_list_proof", Kind: DerivedArgRekeyListProof, Parameter: RekeyListEntriesParameter, MaxSize: RekeyListProofSize}},
	}
}

// A listed address is a way out, so "only these" needs no pay to hold assets.
// The list must be at the contract's depth, with its one proof slot used on the
// listed rekey alone.
func TestMetadataValidateRekeyList(t *testing.T) {
	if err := listMetadata().Validate(); err != nil {
		t.Fatalf("valid list metadata: %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*Metadata)
		want   string
	}{
		// Plus cosigned needs the cosigner: alone, the spending key already rekeys
		// anywhere.
		{"spending-key rekey without a cosigner", func(m *Metadata) { m.Rekey = RekeySpendingKey }, "(plus_cosigned) needs a cosigner"},
		{"unknown contract", func(m *Metadata) { m.RekeyList.Contract = "rekey_list2" }, "unsupported rekey-to list contract"},
		{"other depth", func(m *Metadata) { m.RekeyList.Depth = 16 }, "depth 16, want 4"},
		{"bad root", func(m *Metadata) { m.RekeyList.RootHex = "ab" }, "expected 32 bytes"},
		{"upper-case root", func(m *Metadata) { m.RekeyList.RootHex = strings.Repeat("AB", 32) }, "lowercase hex"},
		// A stored account's root is what every listed rekey is checked against.
		{"stored without a root", func(m *Metadata) { m.RekeyList.RootHex = "" }, "rekey-to list root must be non-empty"},
		{"no proof", func(m *Metadata) { m.DerivedArgs = nil; m.ArgumentLayout = m.ArgumentLayout[:1] }, "exactly one rekey-list proof"},
		{"proof over another parameter", func(m *Metadata) { m.DerivedArgs[0].Parameter = "recipients" }, "needs the rekey-to list"},
		{"proof without a list", func(m *Metadata) { m.RekeyList = nil }, "needs the rekey-to list"},
		{"proof on the spend path", func(m *Metadata) { m.ArgumentLayout[1].Paths.Spend = ArgOptional }, "path rules"},
		{"base signature skips the listed rekey", func(m *Metadata) { m.ArgumentLayout[0].Paths.ListedRekey = ArgForbidden }, "required on every path"},
	} {
		t.Run(test.name, func(t *testing.T) {
			metadata := listMetadata()
			test.mutate(metadata)
			if err := metadata.Validate(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Validate() error = %v, want %q", err, test.want)
			}
		})
	}
	// Without its list, the same account would trap its ALGO, and is refused.
	bare := listMetadata()
	bare.RekeyList, bare.DerivedArgs, bare.ArgumentLayout = nil, nil, bare.ArgumentLayout[:1]
	if err := bare.Validate(); err == nil || !strings.Contains(err.Error(), "needs pay") {
		t.Fatalf("a bare refused assets-only account: error = %v", err)
	}
	if !listMetadata().Equal(listMetadata()) || listMetadata().Equal(bare) {
		t.Fatal("Equal ignores the rekey-to list")
	}
	declaration, err := listMetadata().Declaration()
	if err != nil || !declaration.RekeyList {
		t.Fatalf("declaration %+v, %v", declaration, err)
	}
}

// cosignedListMetadata is listMetadata with a cosigner, under the given rekey
// setting: only these (refused) or plus cosigned (spending key).
func cosignedListMetadata(t *testing.T, rekey RekeySetting) *Metadata {
	t.Helper()
	publicKey := bytes.Repeat([]byte{0x6b}, CosignerPublicKeySizeV1)
	componentKeyID, err := witness.ID(CosignerComponentKeyTypeV1, publicKey)
	if err != nil {
		t.Fatalf("witness.ID() error = %v", err)
	}
	metadata := listMetadata()
	metadata.Rekey = rekey
	metadata.Cosigner = &CosignerAuthorization{
		Contract: CosignerContractV1, ComponentKeyType: CosignerComponentKeyTypeV1,
		PublicKeyHex: hex.EncodeToString(publicKey), ComponentKeyID: componentKeyID,
		SignatureMaxSize: CosignerSignatureMaxSizeV1, RequiredOn: CosignerRequiredOn(rekey),
	}
	metadata.ArgumentLayout = append(metadata.ArgumentLayout, ArgumentSlot{
		Index: 2, Name: CosignerSignatureSlot, Source: ArgSourceCosigner, MaxSize: CosignerSignatureMaxSizeV1,
		Paths: CosignerSlotPaths(metadata.Cosigner),
	})
	return metadata
}

// A cosigned account takes a list both ways. Under only these the cosigner signs
// spends alone; under plus cosigned it also signs every unlisted rekey. Neither
// asks it for a listed rekey, so the proof and the cosigner never share a path.
func TestMetadataValidateCosignedRekeyLists(t *testing.T) {
	for _, test := range []struct {
		rekey        RekeySetting
		spendingRule string
	}{
		{RekeyRefused, ArgForbidden},
		{RekeySpendingKey, ArgRequired},
	} {
		metadata := cosignedListMetadata(t, test.rekey)
		if err := metadata.Validate(); err != nil {
			t.Fatalf("rekey %s: Validate() error = %v", test.rekey, err)
		}
		cosignerSlot := metadata.ArgumentLayout[2]
		if cosignerSlot.Paths.Spend != ArgRequired || cosignerSlot.Paths.SpendingRekey != test.spendingRule || cosignerSlot.Paths.ListedRekey != ArgForbidden {
			t.Fatalf("rekey %s: cosigner mask %+v", test.rekey, cosignerSlot.Paths)
		}
		if got, want := metadata.ArgumentBytesForPath(PathListedRekey), 64+RekeyListProofSize; got != want {
			t.Fatalf("rekey %s: listed-rekey bytes = %d, want %d (no cosigner)", test.rekey, got, want)
		}
		asked := cosignedListMetadata(t, test.rekey)
		asked.ArgumentLayout[2].Paths.ListedRekey = ArgRequired
		if err := asked.Validate(); err == nil || !strings.Contains(err.Error(), "required_on paths") {
			t.Fatalf("rekey %s: a cosigner on the listed rekey: error = %v", test.rekey, err)
		}
	}
	// The record names the cosigned rekey, so a plus-cosigned account that
	// leaves it out is refused rather than read as only these.
	plus := cosignedListMetadata(t, RekeySpendingKey)
	plus.Cosigner.RequiredOn = []string{PathSpend}
	if err := plus.Validate(); err == nil || !strings.Contains(err.Error(), "exactly [spend, spending_rekey]") {
		t.Fatalf("plus cosigned with a spend-only cosigner: error = %v", err)
	}
}
