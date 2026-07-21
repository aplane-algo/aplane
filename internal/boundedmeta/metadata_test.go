// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package boundedmeta

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
)

func TestMetadataValidateAdminBinding(t *testing.T) {
	publicKey := bytes.Repeat([]byte{0x5a}, FalconAdminPublicKeySize)
	keyID, err := AdminKeyID(publicKey)
	if err != nil {
		t.Fatalf("AdminKeyID() error = %v", err)
	}
	metadata := &Metadata{
		Contract:               ContractV1,
		BaseSignatureArgLayout: SignatureArgLayout{Count: 1, MaxSizes: []int{1280}},
		ArgumentLayout:         BaseArgumentLayout(SignatureArgLayout{Count: 1, MaxSizes: []int{1280}}, true),
		SpendEffects:           []string{"pay", "axfer"},
		MaxFee:                 1_000,
		AdminOperations: []AdminOperation{{
			Kind: AdminOperationRekey, Authorization: AdminAuthorizationAdmin, PolicyGate: PolicyGateNone,
		}},
		Layer3Policy:            Layer3PolicyCustom,
		AdminPublicKeyHex:       hex.EncodeToString(publicKey),
		AdminKeyID:              keyID,
		ProgramBindingHex:       strings.Repeat("ab", ProgramBindingSize),
		PostSigningLogicSigSize: 4_000,
	}
	if err := metadata.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	metadata.AdminKeyID = strings.Repeat("A", len(keyID))
	if err := metadata.Validate(); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("Validate() error = %v, want key-ID mismatch", err)
	}
}

func TestMetadataValidateRejectsInvalidContracts(t *testing.T) {
	base := Metadata{
		Contract:                ContractV1,
		BaseSignatureArgLayout:  SignatureArgLayout{Count: 1, MaxSizes: []int{64}},
		ArgumentLayout:          BaseArgumentLayout(SignatureArgLayout{Count: 1, MaxSizes: []int{64}}, false),
		SpendEffects:            []string{"pay"},
		MaxFee:                  1_000,
		AdminOperations:         []AdminOperation{},
		Layer3Policy:            Layer3PolicyCustom,
		PostSigningLogicSigSize: 100,
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
		{name: "missing policy gate", mutate: func(m *Metadata) {
			m.AdminOperations = []AdminOperation{{Kind: AdminOperationRekey, Authorization: AdminAuthorizationSpend}}
		}, want: "unsupported policy gate"},
		{name: "admin key Layer-3 gate", mutate: func(m *Metadata) {
			m.AdminOperations = []AdminOperation{{Kind: AdminOperationRekey, Authorization: AdminAuthorizationAdmin, PolicyGate: PolicyGateLayer3}}
		}, want: "requires policy_gate"},
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

func TestMetadataArgumentLayoutPathSizes(t *testing.T) {
	metadata := &Metadata{
		Contract:               ContractV1,
		BaseSignatureArgLayout: SignatureArgLayout{Count: 1, MaxSizes: []int{64}},
		SpendEffects:           []string{SpendEffectPay},
		MaxFee:                 2_000,
		AdminOperations: []AdminOperation{{
			Kind: AdminOperationRekey, Authorization: AdminAuthorizationAdmin, PolicyGate: PolicyGateNone,
		}},
		DerivedArgs:  []DerivedArg{{Name: "proof", Kind: DerivedArgMerkleProof, Parameter: "recipients", MaxSize: MerkleProofSize}},
		RuntimeArgs:  []RuntimeArg{{Name: "preimage", Type: "bytes", Required: true, ByteLength: 32, MaxSize: 32}},
		Layer3Policy: Layer3PolicyCustom,
		ArgumentLayout: []ArgumentSlot{
			{Index: 0, Name: "base_signature_0", Source: ArgSourceBaseSignature, MaxSize: 64, Paths: ArgumentPathMask{Spend: ArgRequired, SpendingRekey: ArgRequired, AdminRekey: ArgRequired}},
			{Index: 1, Name: "proof", Source: ArgSourceDerived, MaxSize: MerkleProofSize, Paths: ArgumentPathMask{Spend: ArgOptional, SpendingRekey: ArgForbidden, AdminRekey: ArgForbidden}},
			{Index: 2, Name: "preimage", Source: ArgSourceRuntime, MaxSize: 32, Paths: ArgumentPathMask{Spend: ArgRequired, SpendingRekey: ArgForbidden, AdminRekey: ArgForbidden}},
			{Index: 3, Name: "admin_signature", Source: ArgSourceAdmin, MaxSize: FalconAdminSignatureSize, Paths: ArgumentPathMask{Spend: ArgForbidden, SpendingRekey: ArgForbidden, AdminRekey: ArgRequired}},
		},
		PostSigningLogicSigSize: 10 + 64 + MerkleProofSize + 32 + FalconAdminSignatureSize,
	}
	if err := metadata.ValidateProfile(); err != nil {
		t.Fatalf("ValidateProfile() error = %v", err)
	}
	if got, want := metadata.LogicSigSizeForPath(PathSpend), 10+64+MerkleProofSize+32; got != want {
		t.Fatalf("spend size = %d, want %d", got, want)
	}
	if got, want := metadata.LogicSigSizeForPath(PathSpendingRekey), 10+64; got != want {
		t.Fatalf("spending-rekey size = %d, want %d", got, want)
	}
	if got, want := metadata.LogicSigSizeForPath(PathAdminRekey), 10+64+FalconAdminSignatureSize; got != want {
		t.Fatalf("admin-rekey size = %d, want %d", got, want)
	}
}

func TestMetadataEqual(t *testing.T) {
	base := func() *Metadata {
		return &Metadata{
			Contract:                ContractV1,
			BaseSignatureArgLayout:  SignatureArgLayout{Count: 1, MaxSizes: []int{1280}},
			ArgumentLayout:          BaseArgumentLayout(SignatureArgLayout{Count: 1, MaxSizes: []int{1280}}, false),
			SpendEffects:            []string{"pay"},
			MaxFee:                  5000,
			AdminOperations:         []AdminOperation{{Kind: AdminOperationRekey, Authorization: AdminAuthorizationSpend, PolicyGate: PolicyGateNone}},
			Layer3Policy:            Layer3PolicyCustom,
			PostSigningLogicSigSize: 2000,
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
	changed.AdminOperations[0].Authorization = AdminAuthorizationAdmin
	if base().Equal(changed) {
		t.Fatal("AdminOperations change not detected")
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
	if n := reflect.TypeOf(Metadata{}).NumField(); n != 13 {
		t.Fatalf("Metadata has %d fields; update Equal and this count together", n)
	}
}
