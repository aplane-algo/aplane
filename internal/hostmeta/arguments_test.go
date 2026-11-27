// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package hostmeta

import (
	"fmt"
	"testing"
)

// layoutTestMetadata is a valid layout with one slot of every source: a base
// signature, a derived recipient proof, a runtime argument, and a cosigner
// signature required on the spend path.
func layoutTestMetadata() *Metadata {
	cosigner := &CosignerAuthorization{SignatureMaxSize: 64, RequiredOn: []string{PathSpend}}
	return &Metadata{
		BaseSignatureArgLayout: SignatureArgLayout{Count: 1, MaxSizes: []int{64}},
		DerivedArgs:            []DerivedArg{{Name: "proof", Kind: DerivedArgMerkleProof, Parameter: "allowlist", MaxSize: MerkleProofSize}},
		RuntimeArgs:            []RuntimeArg{{Name: "note", Type: "bytes", MaxSize: 32}},
		Cosigner:               cosigner,
		ArgumentLayout: []ArgumentSlot{
			{Index: 0, Name: "base_signature_0", Source: ArgSourceBaseSignature, MaxSize: 64,
				Paths: ArgumentPathMask{Spend: ArgRequired, SpendingRekey: ArgRequired, ListedRekey: ArgRequired}},
			{Index: 1, Name: "proof", Source: ArgSourceDerived, MaxSize: MerkleProofSize, Paths: merkleProofPaths},
			{Index: 2, Name: "note", Source: ArgSourceRuntime, MaxSize: 32,
				Paths: ArgumentPathMask{Spend: ArgOptional, SpendingRekey: ArgForbidden, ListedRekey: ArgForbidden}},
			{Index: 3, Name: CosignerSignatureSlot, Source: ArgSourceCosigner, MaxSize: 64, Paths: CosignerSlotPaths(cosigner)},
		},
	}
}

var (
	merkleProofPaths = ArgumentPathMask{Spend: ArgOptional, SpendingRekey: ArgForbidden, ListedRekey: ArgForbidden}
	listProofPaths   = ArgumentPathMask{Spend: ArgForbidden, SpendingRekey: ArgForbidden, ListedRekey: ArgRequired}
)

// Slot positions in layoutTestMetadata.
const (
	slotBase = iota
	slotDerived
	slotRuntime
	slotCosigner
)

// makeListProof turns the derived arg and its slot into a rekey list proof,
// keeping the slot's path mask as it is.
func makeListProof(m *Metadata) {
	m.DerivedArgs[0] = DerivedArg{Name: "proof", Kind: DerivedArgRekeyListProof, Parameter: "rekey_to", MaxSize: RekeyListProofSize}
	m.ArgumentLayout[slotDerived].MaxSize = RekeyListProofSize
}

func TestValidateArgumentLayoutAccepts(t *testing.T) {
	tests := []struct {
		name  string
		build func() *Metadata
	}{
		{"every source", layoutTestMetadata},
		{"base slots only", func() *Metadata {
			layout := SignatureArgLayout{Count: 2, MaxSizes: []int{64, 32}}
			return &Metadata{BaseSignatureArgLayout: layout, ArgumentLayout: BaseArgumentLayout(layout)}
		}},
		{"rekey list proof on the listed rekey alone", func() *Metadata {
			m := layoutTestMetadata()
			makeListProof(m)
			m.ArgumentLayout[slotDerived].Paths = listProofPaths
			return m
		}},
		{"runtime argument required on spend", func() *Metadata {
			m := layoutTestMetadata()
			m.ArgumentLayout[slotRuntime].Paths.Spend = ArgRequired
			return m
		}},
		{"cosigner required on no path", func() *Metadata {
			m := layoutTestMetadata()
			m.Cosigner.RequiredOn = nil
			m.ArgumentLayout[slotCosigner].Paths = CosignerSlotPaths(m.Cosigner)
			return m
		}},
		{"cosigner required on spend and spending rekey", func() *Metadata {
			m := layoutTestMetadata()
			m.Cosigner.RequiredOn = []string{PathSpend, PathSpendingRekey}
			m.ArgumentLayout[slotCosigner].Paths = CosignerSlotPaths(m.Cosigner)
			return m
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateArgumentLayout(tt.build()); err != nil {
				t.Fatalf("validateArgumentLayout() error = %v, want nil", err)
			}
		})
	}
}

// Each case breaks the valid layout and gives the exact error it must
// produce. The single-fault cases cover every refusal; the two-fault cases
// pin which check runs first.
func TestValidateArgumentLayoutRefusals(t *testing.T) {
	const (
		cosignerMismatch = "bounded cosigner signature slot must be required on exactly the cosigner's required_on paths and match cosigner metadata"
		uncovered        = "argument layout does not cover every declared Layer-3 argument"
		baseRequired     = "base signature slot 0 must be required on every path"
		baseMismatch     = "base signature slot 0 does not match base_signature_arg_layout"
	)
	invalidDerived := func(name, kind string) string {
		return fmt.Sprintf("invalid derived arg %q of kind %q", name, kind)
	}
	pathRule := func(slot int, path string) string {
		return fmt.Sprintf("argument slot %d has invalid %s path rule %q", slot, path, "sometimes")
	}
	derivedPaths := func(got, want ArgumentPathMask) string {
		return fmt.Sprintf("derived argument slot 1 has path rules %+v, want %+v", got, want)
	}
	tests := []struct {
		name   string
		mutate func(*Metadata)
		want   string
	}{
		{"empty layout", func(m *Metadata) { m.ArgumentLayout = nil }, "bounded argument_layout must not be empty"},

		// Derived declarations.
		{"derived arg wrong size", func(m *Metadata) { m.DerivedArgs[0].MaxSize = 1 }, invalidDerived("proof", DerivedArgMerkleProof)},
		{"derived arg unknown kind", func(m *Metadata) { m.DerivedArgs[0].Kind = "x" }, invalidDerived("proof", "x")},
		{"derived arg without name", func(m *Metadata) { m.DerivedArgs[0].Name = "" }, invalidDerived("", DerivedArgMerkleProof)},
		{"derived arg without parameter", func(m *Metadata) { m.DerivedArgs[0].Parameter = "" }, invalidDerived("proof", DerivedArgMerkleProof)},
		{"duplicate derived arg", func(m *Metadata) { m.DerivedArgs = append(m.DerivedArgs, m.DerivedArgs[0]) }, `duplicate derived arg "proof"`},

		// Runtime declarations.
		{"runtime arg no size", func(m *Metadata) { m.RuntimeArgs[0].MaxSize = 0 }, `invalid runtime arg "note" maximum size 0`},
		{"runtime arg without name", func(m *Metadata) { m.RuntimeArgs[0].Name = "" }, `invalid runtime arg "" maximum size 32`},
		{"runtime arg negative length", func(m *Metadata) { m.RuntimeArgs[0].ByteLength = -1 }, `invalid runtime arg "note" maximum size 32`},
		{"runtime arg length over size", func(m *Metadata) { m.RuntimeArgs[0].ByteLength = 33 }, `invalid runtime arg "note" maximum size 32`},
		{"runtime arg bad type", func(m *Metadata) { m.RuntimeArgs[0].Type = "blob" }, `invalid runtime arg "note" type "blob"`},
		{"duplicate runtime arg", func(m *Metadata) { m.RuntimeArgs = append(m.RuntimeArgs, m.RuntimeArgs[0]) }, `duplicate runtime arg "note"`},

		// Checks every slot gets.
		{"non-canonical index", func(m *Metadata) { m.ArgumentLayout[slotDerived].Index = 5 }, "argument slot 1 has non-canonical index 5"},
		{"slot without size", func(m *Metadata) { m.ArgumentLayout[slotDerived].MaxSize = 0 }, "argument slot 1 has invalid name or maximum size"},
		{"slot without name", func(m *Metadata) { m.ArgumentLayout[slotDerived].Name = "" }, "argument slot 1 has invalid name or maximum size"},
		{"duplicate slot name", func(m *Metadata) { m.ArgumentLayout[slotRuntime].Name = "proof" }, `duplicate argument slot name "proof"`},
		{"unknown source", func(m *Metadata) { m.ArgumentLayout[slotRuntime].Source = "x" }, `argument slot 2 source "x" is invalid or out of order`},
		{"source out of order", func(m *Metadata) { m.ArgumentLayout[slotRuntime].Source = ArgSourceBaseSignature },
			fmt.Sprintf("argument slot 2 source %q is invalid or out of order", ArgSourceBaseSignature)},
		{"invalid spend rule", func(m *Metadata) { m.ArgumentLayout[slotRuntime].Paths.Spend = "sometimes" }, pathRule(2, PathSpend)},
		{"invalid spending rekey rule", func(m *Metadata) { m.ArgumentLayout[slotRuntime].Paths.SpendingRekey = "sometimes" }, pathRule(2, PathSpendingRekey)},
		{"invalid listed rekey rule", func(m *Metadata) { m.ArgumentLayout[slotRuntime].Paths.ListedRekey = "sometimes" }, pathRule(2, PathListedRekey)},

		// Base signature slots.
		{"base slot optional on spend", func(m *Metadata) { m.ArgumentLayout[slotBase].Paths.Spend = ArgOptional }, baseRequired},
		{"base slot optional on spending rekey", func(m *Metadata) { m.ArgumentLayout[slotBase].Paths.SpendingRekey = ArgOptional }, baseRequired},
		{"base slot forbidden on listed rekey", func(m *Metadata) { m.ArgumentLayout[slotBase].Paths.ListedRekey = ArgForbidden }, baseRequired},
		{"base slot wrong size", func(m *Metadata) { m.ArgumentLayout[slotBase].MaxSize = 65 }, baseMismatch},
		{"base slot beyond the declared sizes", func(m *Metadata) { m.BaseSignatureArgLayout = SignatureArgLayout{} }, baseMismatch},
		{"base count below the slots", func(m *Metadata) { m.BaseSignatureArgLayout.Count = 0 }, "argument layout has 1 base slots, want 0"},
		{"base count above the slots", func(m *Metadata) { m.BaseSignatureArgLayout = SignatureArgLayout{Count: 2, MaxSizes: []int{64, 64}} }, "argument layout has 1 base slots, want 2"},

		// Derived slots.
		{"undeclared derived slot", func(m *Metadata) { m.ArgumentLayout[slotDerived].Name = "other" }, `argument slot 1 references undeclared derived arg "other"`},
		{"derived slot size mismatch", func(m *Metadata) { m.ArgumentLayout[slotDerived].MaxSize = 100 }, "derived argument slot 1 maximum size does not match declaration"},
		{"recipient proof on a rekey path", func(m *Metadata) { m.ArgumentLayout[slotDerived].Paths.SpendingRekey = ArgOptional },
			derivedPaths(ArgumentPathMask{Spend: ArgOptional, SpendingRekey: ArgOptional, ListedRekey: ArgForbidden}, merkleProofPaths)},
		{"list proof with the recipient proof's paths", makeListProof, derivedPaths(merkleProofPaths, listProofPaths)},

		// Runtime slots.
		{"undeclared runtime slot", func(m *Metadata) { m.ArgumentLayout[slotRuntime].Name = "other" }, `argument slot 2 references undeclared runtime arg "other"`},
		{"runtime slot size mismatch", func(m *Metadata) { m.ArgumentLayout[slotRuntime].MaxSize = 16 }, "runtime argument slot 2 maximum size does not match declaration"},
		{"runtime slot on the spending rekey", func(m *Metadata) { m.ArgumentLayout[slotRuntime].Paths.SpendingRekey = ArgOptional }, "runtime argument slot 2 must be forbidden on every rekey path"},
		{"runtime slot on the listed rekey", func(m *Metadata) { m.ArgumentLayout[slotRuntime].Paths.ListedRekey = ArgOptional }, "runtime argument slot 2 must be forbidden on every rekey path"},

		// The cosigner slot.
		{"cosigner slot without cosigner", func(m *Metadata) { m.Cosigner = nil }, cosignerMismatch},
		{"cosigner slot wrong size", func(m *Metadata) { m.ArgumentLayout[slotCosigner].MaxSize = 32 }, cosignerMismatch},
		{"cosigner slot wrong name", func(m *Metadata) { m.ArgumentLayout[slotCosigner].Name = "other" }, cosignerMismatch},
		{"cosigner slot wrong paths", func(m *Metadata) { m.ArgumentLayout[slotCosigner].Paths.Spend = ArgForbidden }, cosignerMismatch},

		// Coverage, checked after every slot.
		{"uncovered derived arg", func(m *Metadata) {
			m.DerivedArgs = append(m.DerivedArgs, DerivedArg{Name: "proof2", Kind: DerivedArgMerkleProof, Parameter: "allowlist", MaxSize: MerkleProofSize})
		}, uncovered},
		{"uncovered runtime arg", func(m *Metadata) {
			m.RuntimeArgs = append(m.RuntimeArgs, RuntimeArg{Name: "memo", Type: "bytes", MaxSize: 8})
		}, uncovered},
		{"missing cosigner slot", func(m *Metadata) { m.ArgumentLayout = m.ArgumentLayout[:slotCosigner] }, "argument layout has 0 cosigner slots, want 1"},

		// Two faults: the first check in order reports.
		{"empty layout before declarations", func(m *Metadata) {
			m.ArgumentLayout = nil
			m.RuntimeArgs[0].Type = "blob"
		}, "bounded argument_layout must not be empty"},
		{"derived declarations before runtime declarations", func(m *Metadata) {
			m.DerivedArgs[0].Kind = "x"
			m.RuntimeArgs[0].Type = "blob"
		}, invalidDerived("proof", "x")},
		{"declarations before slots", func(m *Metadata) {
			m.RuntimeArgs = append(m.RuntimeArgs, m.RuntimeArgs[0])
			m.ArgumentLayout[slotBase].Index = 9
		}, `duplicate runtime arg "note"`},
		{"index before name and size", func(m *Metadata) {
			m.ArgumentLayout[slotDerived].Index = 5
			m.ArgumentLayout[slotDerived].Name = ""
		}, "argument slot 1 has non-canonical index 5"},
		{"duplicate name before source", func(m *Metadata) {
			m.ArgumentLayout[slotRuntime].Name = "proof"
			m.ArgumentLayout[slotRuntime].Source = "x"
		}, `duplicate argument slot name "proof"`},
		{"source before path rules", func(m *Metadata) {
			m.ArgumentLayout[slotRuntime].Source = "x"
			m.ArgumentLayout[slotRuntime].Paths.Spend = "sometimes"
		}, `argument slot 2 source "x" is invalid or out of order`},
		{"path rules before the source's own checks", func(m *Metadata) {
			m.ArgumentLayout[slotBase].Paths.Spend = "sometimes"
			m.ArgumentLayout[slotBase].MaxSize = 65
		}, pathRule(0, PathSpend)},
		{"an earlier slot before a later one", func(m *Metadata) {
			m.ArgumentLayout[slotDerived].MaxSize = 100
			m.ArgumentLayout[slotRuntime].Name = "other"
		}, "derived argument slot 1 maximum size does not match declaration"},
		{"slots before coverage", func(m *Metadata) {
			m.BaseSignatureArgLayout.Count = 0
			m.ArgumentLayout[slotCosigner].MaxSize = 32
		}, cosignerMismatch},
		{"base count before coverage and the cosigner slot", func(m *Metadata) {
			m.BaseSignatureArgLayout.Count = 0
			m.RuntimeArgs = append(m.RuntimeArgs, RuntimeArg{Name: "memo", Type: "bytes", MaxSize: 8})
			m.ArgumentLayout = m.ArgumentLayout[:slotCosigner]
		}, "argument layout has 1 base slots, want 0"},
		{"coverage before the cosigner slot", func(m *Metadata) {
			m.RuntimeArgs = append(m.RuntimeArgs, RuntimeArg{Name: "memo", Type: "bytes", MaxSize: 8})
			m.ArgumentLayout = m.ArgumentLayout[:slotCosigner]
		}, uncovered},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metadata := layoutTestMetadata()
			tt.mutate(metadata)
			err := validateArgumentLayout(metadata)
			if err == nil || err.Error() != tt.want {
				t.Fatalf("validateArgumentLayout() error = %v, want %q", err, tt.want)
			}
		})
	}
}
