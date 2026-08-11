// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package boundedmeta

import "fmt"

const (
	PathSpend         = "spend"
	PathSpendingRekey = "spending_rekey"
	PathAdminRekey    = "admin_rekey"

	ArgSourceBaseSignature = "base_signature"
	ArgSourceDerived       = "derived"
	ArgSourceRuntime       = "runtime"
	ArgSourceSentry        = "sentry"
	ArgSourceAdmin         = "admin"

	ArgRequired  = "required"
	ArgOptional  = "optional"
	ArgForbidden = "forbidden"

	DerivedArgMerkleProof = "merkle_allowlist_proof"
	MerkleProofSize       = 512
)

// ArgumentPathMask freezes one slot's use on every bounded1 path.
type ArgumentPathMask struct {
	Spend         string `json:"spend"`
	SpendingRekey string `json:"spending_rekey"`
	AdminRekey    string `json:"admin_rekey"`
}

// ArgumentSlot is one position in the final LogicSig argument array.
type ArgumentSlot struct {
	Index   int              `json:"index"`
	Name    string           `json:"name"`
	Source  string           `json:"source"`
	MaxSize int              `json:"max_size"`
	Paths   ArgumentPathMask `json:"paths"`
}

// DerivedArg declares signer-generated Layer-3 material.
type DerivedArg struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	Parameter string `json:"parameter"`
	MaxSize   int    `json:"max_size"`
}

// BaseArgumentLayout builds the canonical layout for profiles that have no
// Layer-3 arguments. Richer profiles insert derived and runtime slots between
// these base slots and the optional admin slot.
func BaseArgumentLayout(layout SignatureArgLayout, requiresAdmin bool) []ArgumentSlot {
	slots := make([]ArgumentSlot, 0, layout.Count+1)
	for i, maxSize := range layout.MaxSizes {
		slots = append(slots, ArgumentSlot{
			Index: i, Name: fmt.Sprintf("base_signature_%d", i), Source: ArgSourceBaseSignature, MaxSize: maxSize,
			Paths: ArgumentPathMask{Spend: ArgRequired, SpendingRekey: ArgRequired, AdminRekey: ArgRequired},
		})
	}
	if requiresAdmin {
		slots = append(slots, ArgumentSlot{
			Index: len(slots), Name: "admin_signature", Source: ArgSourceAdmin, MaxSize: FalconAdminSignatureSize,
			Paths: ArgumentPathMask{Spend: ArgForbidden, SpendingRekey: ArgForbidden, AdminRekey: ArgRequired},
		})
	}
	return slots
}

// ArgumentBytesForPath returns the maximum aggregate LogicSig argument bytes
// for one bounded authorization path. Program bytes are deliberately excluded.
func (metadata *Metadata) ArgumentBytesForPath(path string) int {
	if metadata == nil || (path != PathSpend && path != PathSpendingRekey && path != PathAdminRekey) {
		return 0
	}
	size := 0
	for _, slot := range metadata.ArgumentLayout {
		if slotRequirement(slot.Paths, path) != ArgForbidden {
			size += slot.MaxSize
		}
	}
	return size
}

func slotRequirement(paths ArgumentPathMask, path string) string {
	switch path {
	case PathSpend:
		return paths.Spend
	case PathSpendingRekey:
		return paths.SpendingRekey
	case PathAdminRekey:
		return paths.AdminRekey
	default:
		return ""
	}
}

func validateArgumentLayout(metadata *Metadata) error {
	if len(metadata.ArgumentLayout) == 0 {
		return fmt.Errorf("bounded1 argument_layout must not be empty")
	}
	sourceOrder := map[string]int{
		ArgSourceBaseSignature: 0,
		ArgSourceDerived:       1,
		ArgSourceRuntime:       2,
		ArgSourceSentry:        3,
		ArgSourceAdmin:         4,
	}
	lastSource := -1
	baseCount := 0
	derivedNames := make(map[string]struct{}, len(metadata.DerivedArgs))
	for _, arg := range metadata.DerivedArgs {
		if arg.Name == "" || arg.Kind != DerivedArgMerkleProof || arg.Parameter == "" || arg.MaxSize != MerkleProofSize {
			return fmt.Errorf("invalid derived arg %q of kind %q", arg.Name, arg.Kind)
		}
		if _, duplicate := derivedNames[arg.Name]; duplicate {
			return fmt.Errorf("duplicate derived arg %q", arg.Name)
		}
		derivedNames[arg.Name] = struct{}{}
	}
	runtimeNames := make(map[string]struct{}, len(metadata.RuntimeArgs))
	for _, arg := range metadata.RuntimeArgs {
		if arg.Name == "" || arg.MaxSize <= 0 || arg.ByteLength < 0 || arg.ByteLength > arg.MaxSize {
			return fmt.Errorf("invalid runtime arg %q maximum size %d", arg.Name, arg.MaxSize)
		}
		if arg.Type != "bytes" && arg.Type != "string" && arg.Type != "uint64" {
			return fmt.Errorf("invalid runtime arg %q type %q", arg.Name, arg.Type)
		}
		if _, duplicate := runtimeNames[arg.Name]; duplicate {
			return fmt.Errorf("duplicate runtime arg %q", arg.Name)
		}
		runtimeNames[arg.Name] = struct{}{}
	}
	seenNames := make(map[string]struct{}, len(metadata.ArgumentLayout))
	seenDerived := make(map[string]struct{}, len(derivedNames))
	seenRuntime := make(map[string]struct{}, len(runtimeNames))
	adminSlots := 0
	sentrySlots := 0
	for i, slot := range metadata.ArgumentLayout {
		if slot.Index != i {
			return fmt.Errorf("argument slot %d has non-canonical index %d", i, slot.Index)
		}
		if slot.Name == "" || slot.MaxSize <= 0 {
			return fmt.Errorf("argument slot %d has invalid name or maximum size", i)
		}
		if _, duplicate := seenNames[slot.Name]; duplicate {
			return fmt.Errorf("duplicate argument slot name %q", slot.Name)
		}
		seenNames[slot.Name] = struct{}{}
		order, ok := sourceOrder[slot.Source]
		if !ok || order < lastSource {
			return fmt.Errorf("argument slot %d source %q is invalid or out of order", i, slot.Source)
		}
		lastSource = order
		for _, pathRule := range []struct {
			path string
			rule string
		}{
			{path: PathSpend, rule: slot.Paths.Spend},
			{path: PathSpendingRekey, rule: slot.Paths.SpendingRekey},
			{path: PathAdminRekey, rule: slot.Paths.AdminRekey},
		} {
			path, rule := pathRule.path, pathRule.rule
			if rule != ArgRequired && rule != ArgOptional && rule != ArgForbidden {
				return fmt.Errorf("argument slot %d has invalid %s path rule %q", i, path, rule)
			}
		}
		switch slot.Source {
		case ArgSourceBaseSignature:
			if slot.Paths.Spend != ArgRequired || slot.Paths.SpendingRekey != ArgRequired || slot.Paths.AdminRekey != ArgRequired {
				return fmt.Errorf("base signature slot %d must be required on every path", i)
			}
			if baseCount >= len(metadata.BaseSignatureArgLayout.MaxSizes) || slot.MaxSize != metadata.BaseSignatureArgLayout.MaxSizes[baseCount] {
				return fmt.Errorf("base signature slot %d does not match base_signature_arg_layout", i)
			}
			baseCount++
		case ArgSourceDerived:
			if _, ok := derivedNames[slot.Name]; !ok {
				return fmt.Errorf("argument slot %d references undeclared derived arg %q", i, slot.Name)
			}
			for _, arg := range metadata.DerivedArgs {
				if arg.Name == slot.Name && arg.MaxSize != slot.MaxSize {
					return fmt.Errorf("derived argument slot %d maximum size does not match declaration", i)
				}
			}
			seenDerived[slot.Name] = struct{}{}
		case ArgSourceRuntime:
			if _, ok := runtimeNames[slot.Name]; !ok {
				return fmt.Errorf("argument slot %d references undeclared runtime arg %q", i, slot.Name)
			}
			for _, arg := range metadata.RuntimeArgs {
				if arg.Name == slot.Name && arg.MaxSize != slot.MaxSize {
					return fmt.Errorf("runtime argument slot %d maximum size does not match declaration", i)
				}
			}
			seenRuntime[slot.Name] = struct{}{}
		case ArgSourceSentry:
			sentrySlots++
			if slot.Name != SentrySignatureSlot || metadata.Sentry == nil || slot.MaxSize != metadata.Sentry.SignatureMaxSize ||
				slot.Paths.Spend != ArgRequired || slot.Paths.SpendingRekey != ArgForbidden || slot.Paths.AdminRekey != ArgForbidden {
				return fmt.Errorf("bounded sentry signature slot must be spend-only and match sentry metadata")
			}
		case ArgSourceAdmin:
			adminSlots++
			if i != len(metadata.ArgumentLayout)-1 || slot.Name != "admin_signature" || slot.MaxSize != FalconAdminSignatureSize ||
				slot.Paths.Spend != ArgForbidden || slot.Paths.SpendingRekey != ArgForbidden || slot.Paths.AdminRekey != ArgRequired {
				return fmt.Errorf("contract-admin signature slot must be last and admin-rekey-only")
			}
		}
	}
	if baseCount != metadata.BaseSignatureArgLayout.Count {
		return fmt.Errorf("argument layout has %d base slots, want %d", baseCount, metadata.BaseSignatureArgLayout.Count)
	}
	if len(seenDerived) != len(derivedNames) || len(seenRuntime) != len(runtimeNames) {
		return fmt.Errorf("argument layout does not cover every declared Layer-3 argument")
	}
	wantAdminSlots := 0
	if metadata.RequiresAdminKey() {
		wantAdminSlots = 1
	}
	if adminSlots != wantAdminSlots {
		return fmt.Errorf("argument layout has %d admin slots, want %d", adminSlots, wantAdminSlots)
	}
	wantSentrySlots := 0
	if metadata.Sentry != nil {
		wantSentrySlots = 1
	}
	if sentrySlots != wantSentrySlots {
		return fmt.Errorf("argument layout has %d sentry slots, want %d", sentrySlots, wantSentrySlots)
	}
	return nil
}
