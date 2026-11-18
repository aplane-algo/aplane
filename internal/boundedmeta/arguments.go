// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package boundedmeta

import (
	"fmt"
	"slices"

	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/rekeylist"
)

const (
	PathSpend         = "spend"
	PathSpendingRekey = "spending_rekey"
	// PathListedRekey is a pure rekey to an address on the account's rekey-to
	// list, authorized by the spending key and a list proof.
	PathListedRekey = "listed_rekey"

	ArgSourceBaseSignature = "base_signature"
	ArgSourceDerived       = "derived"
	ArgSourceRuntime       = "runtime"
	ArgSourceCosigner      = "cosigner"

	ArgRequired  = "required"
	ArgOptional  = "optional"
	ArgForbidden = "forbidden"

	DerivedArgMerkleProof = "merkle_allowlist_proof"
	MerkleProofSize       = 512

	// DerivedArgRekeyListProof is the signer-built proof that a rekey target is
	// on the account's rekey-to list.
	DerivedArgRekeyListProof = "rekey_list_proof"
	RekeyListProofSize       = rekeylist.ProofSize
)

// ArgumentPathMask freezes one slot's use on every bounded path.
type ArgumentPathMask struct {
	Spend         string `json:"spend"`
	SpendingRekey string `json:"spending_rekey"`
	ListedRekey   string `json:"listed_rekey"`
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
// Layer-3 arguments. Richer profiles insert derived, runtime and cosigner slots
// after these base slots.
func BaseArgumentLayout(layout SignatureArgLayout) []ArgumentSlot {
	slots := make([]ArgumentSlot, 0, layout.Count)
	for i, maxSize := range layout.MaxSizes {
		slots = append(slots, ArgumentSlot{
			Index: i, Name: fmt.Sprintf("base_signature_%d", i), Source: ArgSourceBaseSignature, MaxSize: maxSize,
			Paths: ArgumentPathMask{Spend: ArgRequired, SpendingRekey: ArgRequired, ListedRekey: ArgRequired},
		})
	}
	return slots
}

// ArgumentBytesForPath returns the maximum aggregate LogicSig argument bytes
// for one bounded authorization path. Program bytes are deliberately excluded.
func (metadata *Metadata) ArgumentBytesForPath(path string) int {
	if metadata == nil || (path != PathSpend && path != PathSpendingRekey && path != PathListedRekey) {
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
	case PathListedRekey:
		return paths.ListedRekey
	default:
		return ""
	}
}

// ValidateNetworkLimits refuses an argument layout the network would refuse on
// any transaction: more arguments than one LogicSig carries, or one larger than
// a LogicSig argument may be. No group shape lifts either.
//
// It is a check for when a template is installed and when a key is generated, not
// part of durable validation: a stored account past a limit still loads, since
// a path that doesn't use the oversized argument, such as a rekey, may still
// work.
func (metadata *Metadata) ValidateNetworkLimits() error {
	if metadata == nil {
		return nil
	}
	if len(metadata.ArgumentLayout) > lsigresource.MaxLogicSigArgs {
		return fmt.Errorf("bounded argument_layout has %d arguments: a LogicSig carries at most %d", len(metadata.ArgumentLayout), lsigresource.MaxLogicSigArgs)
	}
	for i, slot := range metadata.ArgumentLayout {
		if slot.MaxSize > lsigresource.MaxLogicSigArgBytes {
			return fmt.Errorf("argument slot %d (%s) is %d bytes: a LogicSig argument is at most %d", i, slot.Name, slot.MaxSize, lsigresource.MaxLogicSigArgBytes)
		}
	}
	return nil
}

func validateArgumentLayout(metadata *Metadata) error {
	if len(metadata.ArgumentLayout) == 0 {
		return fmt.Errorf("bounded argument_layout must not be empty")
	}
	derivedKinds, err := validateDerivedArgDeclarations(metadata.DerivedArgs)
	if err != nil {
		return err
	}
	runtimeNames, err := validateRuntimeArgDeclarations(metadata.RuntimeArgs)
	if err != nil {
		return err
	}
	check := argumentLayoutCheck{
		metadata:     metadata,
		derivedKinds: derivedKinds,
		runtimeNames: runtimeNames,
		lastSource:   -1,
		seenNames:    make(map[string]struct{}, len(metadata.ArgumentLayout)),
		seenDerived:  make(map[string]struct{}, len(derivedKinds)),
		seenRuntime:  make(map[string]struct{}, len(runtimeNames)),
	}
	for i, slot := range metadata.ArgumentLayout {
		if err := check.slot(i, slot); err != nil {
			return err
		}
	}
	return check.complete()
}

// argumentSourceOrder is the order slot sources must appear in.
var argumentSourceOrder = map[string]int{
	ArgSourceBaseSignature: 0,
	ArgSourceDerived:       1,
	ArgSourceRuntime:       2,
	ArgSourceCosigner:      3,
}

// validateDerivedArgDeclarations checks each derived arg against its kind's
// exact size and returns each name's kind.
func validateDerivedArgDeclarations(args []DerivedArg) (map[string]string, error) {
	kinds := make(map[string]string, len(args))
	for _, arg := range args {
		size, known := derivedArgSizes[arg.Kind]
		if arg.Name == "" || !known || arg.Parameter == "" || arg.MaxSize != size {
			return nil, fmt.Errorf("invalid derived arg %q of kind %q", arg.Name, arg.Kind)
		}
		if _, duplicate := kinds[arg.Name]; duplicate {
			return nil, fmt.Errorf("duplicate derived arg %q", arg.Name)
		}
		kinds[arg.Name] = arg.Kind
	}
	return kinds, nil
}

// validateRuntimeArgDeclarations checks each runtime arg's size and type and
// returns the declared names.
func validateRuntimeArgDeclarations(args []RuntimeArg) (map[string]struct{}, error) {
	names := make(map[string]struct{}, len(args))
	for _, arg := range args {
		if arg.Name == "" || arg.MaxSize <= 0 || arg.ByteLength < 0 || arg.ByteLength > arg.MaxSize {
			return nil, fmt.Errorf("invalid runtime arg %q maximum size %d", arg.Name, arg.MaxSize)
		}
		if arg.Type != "bytes" && arg.Type != "string" && arg.Type != "uint64" {
			return nil, fmt.Errorf("invalid runtime arg %q type %q", arg.Name, arg.Type)
		}
		if _, duplicate := names[arg.Name]; duplicate {
			return nil, fmt.Errorf("duplicate runtime arg %q", arg.Name)
		}
		names[arg.Name] = struct{}{}
	}
	return names, nil
}

// argumentLayoutCheck walks the argument layout once, slot by slot, and then
// checks that the layout covered every declaration.
type argumentLayoutCheck struct {
	metadata     *Metadata
	derivedKinds map[string]string
	runtimeNames map[string]struct{}

	lastSource    int
	baseCount     int
	cosignerSlots int
	seenNames     map[string]struct{}
	seenDerived   map[string]struct{}
	seenRuntime   map[string]struct{}
}

func (c *argumentLayoutCheck) slot(i int, slot ArgumentSlot) error {
	if slot.Index != i {
		return fmt.Errorf("argument slot %d has non-canonical index %d", i, slot.Index)
	}
	if slot.Name == "" || slot.MaxSize <= 0 {
		return fmt.Errorf("argument slot %d has invalid name or maximum size", i)
	}
	if _, duplicate := c.seenNames[slot.Name]; duplicate {
		return fmt.Errorf("duplicate argument slot name %q", slot.Name)
	}
	c.seenNames[slot.Name] = struct{}{}
	order, ok := argumentSourceOrder[slot.Source]
	if !ok || order < c.lastSource {
		return fmt.Errorf("argument slot %d source %q is invalid or out of order", i, slot.Source)
	}
	c.lastSource = order
	if err := validateSlotPathRules(i, slot.Paths); err != nil {
		return err
	}
	switch slot.Source {
	case ArgSourceBaseSignature:
		return c.baseSlot(i, slot)
	case ArgSourceDerived:
		return c.derivedSlot(i, slot)
	case ArgSourceRuntime:
		return c.runtimeSlot(i, slot)
	case ArgSourceCosigner:
		return c.cosignerSlot(slot)
	}
	return nil
}

func validateSlotPathRules(i int, paths ArgumentPathMask) error {
	for _, pathRule := range []struct {
		path string
		rule string
	}{
		{path: PathSpend, rule: paths.Spend},
		{path: PathSpendingRekey, rule: paths.SpendingRekey},
		{path: PathListedRekey, rule: paths.ListedRekey},
	} {
		if rule := pathRule.rule; rule != ArgRequired && rule != ArgOptional && rule != ArgForbidden {
			return fmt.Errorf("argument slot %d has invalid %s path rule %q", i, pathRule.path, rule)
		}
	}
	return nil
}

func (c *argumentLayoutCheck) baseSlot(i int, slot ArgumentSlot) error {
	if slot.Paths.Spend != ArgRequired || slot.Paths.SpendingRekey != ArgRequired || slot.Paths.ListedRekey != ArgRequired {
		return fmt.Errorf("base signature slot %d must be required on every path", i)
	}
	sizes := c.metadata.BaseSignatureArgLayout.MaxSizes
	if c.baseCount >= len(sizes) || slot.MaxSize != sizes[c.baseCount] {
		return fmt.Errorf("base signature slot %d does not match base_signature_arg_layout", i)
	}
	c.baseCount++
	return nil
}

func (c *argumentLayoutCheck) derivedSlot(i int, slot ArgumentSlot) error {
	kind, ok := c.derivedKinds[slot.Name]
	if !ok {
		return fmt.Errorf("argument slot %d references undeclared derived arg %q", i, slot.Name)
	}
	for _, arg := range c.metadata.DerivedArgs {
		if arg.Name == slot.Name && arg.MaxSize != slot.MaxSize {
			return fmt.Errorf("derived argument slot %d maximum size does not match declaration", i)
		}
	}
	// A rekey never reaches Layer 3, so a recipient proof is spend-only, and a
	// list proof serves the listed rekey alone.
	want := ArgumentPathMask{Spend: ArgOptional, SpendingRekey: ArgForbidden, ListedRekey: ArgForbidden}
	if kind == DerivedArgRekeyListProof {
		want = ArgumentPathMask{Spend: ArgForbidden, SpendingRekey: ArgForbidden, ListedRekey: ArgRequired}
	}
	if slot.Paths != want {
		return fmt.Errorf("derived argument slot %d has path rules %+v, want %+v", i, slot.Paths, want)
	}
	c.seenDerived[slot.Name] = struct{}{}
	return nil
}

func (c *argumentLayoutCheck) runtimeSlot(i int, slot ArgumentSlot) error {
	if _, ok := c.runtimeNames[slot.Name]; !ok {
		return fmt.Errorf("argument slot %d references undeclared runtime arg %q", i, slot.Name)
	}
	for _, arg := range c.metadata.RuntimeArgs {
		if arg.Name == slot.Name && arg.MaxSize != slot.MaxSize {
			return fmt.Errorf("runtime argument slot %d maximum size does not match declaration", i)
		}
	}
	if slot.Paths.SpendingRekey != ArgForbidden || slot.Paths.ListedRekey != ArgForbidden {
		return fmt.Errorf("runtime argument slot %d must be forbidden on every rekey path", i)
	}
	c.seenRuntime[slot.Name] = struct{}{}
	return nil
}

func (c *argumentLayoutCheck) cosignerSlot(slot ArgumentSlot) error {
	c.cosignerSlots++
	cosigner := c.metadata.Cosigner
	if slot.Name != CosignerSignatureSlot || cosigner == nil || slot.MaxSize != cosigner.SignatureMaxSize ||
		slot.Paths != CosignerSlotPaths(cosigner) {
		return fmt.Errorf("bounded cosigner signature slot must be required on exactly the cosigner's required_on paths and match cosigner metadata")
	}
	return nil
}

// complete checks that the layout has the base slot count, a slot for every
// declared Layer-3 argument, and the cosigner slot exactly when there is a
// cosigner.
func (c *argumentLayoutCheck) complete() error {
	if c.baseCount != c.metadata.BaseSignatureArgLayout.Count {
		return fmt.Errorf("argument layout has %d base slots, want %d", c.baseCount, c.metadata.BaseSignatureArgLayout.Count)
	}
	if len(c.seenDerived) != len(c.derivedKinds) || len(c.seenRuntime) != len(c.runtimeNames) {
		return fmt.Errorf("argument layout does not cover every declared Layer-3 argument")
	}
	wantCosignerSlots := 0
	if c.metadata.Cosigner != nil {
		wantCosignerSlots = 1
	}
	if c.cosignerSlots != wantCosignerSlots {
		return fmt.Errorf("argument layout has %d cosigner slots, want %d", c.cosignerSlots, wantCosignerSlots)
	}
	return nil
}

// CosignerSlotPaths is the cosigner signature slot's path mask: required on
// every path the cosigner signs, forbidden on the rest. The listed rekey is never
// one of them.
func CosignerSlotPaths(cosigner *CosignerAuthorization) ArgumentPathMask {
	rule := func(path string) string {
		if cosigner != nil && slices.Contains(cosigner.RequiredOn, path) {
			return ArgRequired
		}
		return ArgForbidden
	}
	return ArgumentPathMask{Spend: rule(PathSpend), SpendingRekey: rule(PathSpendingRekey), ListedRekey: ArgForbidden}
}

// derivedArgSizes is each signer-derived argument kind's exact size.
var derivedArgSizes = map[string]int{
	DerivedArgMerkleProof:    MerkleProofSize,
	DerivedArgRekeyListProof: RekeyListProofSize,
}
