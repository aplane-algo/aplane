// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package sigconstruction describes signature authorization as a construction: an
// ordered list of primitive components that must all verify. A single algorithm
// is a construction of one. A construction has no primary component: order sets
// the encoding and argument positions, and every component is required.
//
// This package holds the facts a program needs, such as key and signature shapes
// and verification sequences. It is linked into clients, so it must not import
// signing or verification implementations. Which constructions a contract
// supports is decided by that contract's integration, not here.
package sigconstruction

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/keytypecatalog"
	"github.com/aplane-algo/aplane/internal/witness"
)

// ConstructionID names an immutable construction: its components, their order and
// their encodings. Changing any of those requires a new identity.
type ConstructionID string

// ComponentSpec is one required component of a definition.
type ComponentSpec struct {
	Name      string
	Primitive PrimitiveID
}

// Definition is the input to New. Every component is required.
type Definition struct {
	ID         ConstructionID
	Components []ComponentSpec
}

type component struct {
	name      string
	primitive PrimitiveID
	profile   *primitiveProfile
}

// Construction is a validated, immutable construction.
type Construction struct {
	id         ConstructionID
	components []component
	// layout is computed once at construction. ArgLayout's accessors copy, so
	// sharing it across callers can't let one mutate another's view.
	layout ArgLayout
}

// New validates a definition and returns an independent construction.
func New(definition Definition) (Construction, error) {
	return newConstruction(definition, primitiveProfiles)
}

func newConstruction(definition Definition, profiles map[PrimitiveID]*primitiveProfile) (Construction, error) {
	if definition.ID == "" {
		return Construction{}, fmt.Errorf("construction identifier is required")
	}
	if len(definition.Components) == 0 {
		return Construction{}, fmt.Errorf("construction %q has no components", definition.ID)
	}
	names := make(map[string]struct{}, len(definition.Components))
	components := make([]component, 0, len(definition.Components))
	for _, spec := range definition.Components {
		if spec.Name == "" {
			return Construction{}, fmt.Errorf("construction %q has an unnamed component", definition.ID)
		}
		if _, duplicate := names[spec.Name]; duplicate {
			return Construction{}, fmt.Errorf("construction %q repeats component %q", definition.ID, spec.Name)
		}
		names[spec.Name] = struct{}{}
		profile, ok := profiles[spec.Primitive]
		if !ok {
			return Construction{}, fmt.Errorf("construction %q component %q uses unknown primitive %q", definition.ID, spec.Name, spec.Primitive)
		}
		components = append(components, component{name: spec.Name, primitive: spec.Primitive, profile: profile})
	}
	return Construction{id: definition.ID, components: components, layout: buildLayout(components)}, nil
}

// ID returns the construction's identifier.
func (c Construction) ID() ConstructionID { return c.id }

// Layout returns the construction's argument layout: its components' layouts,
// concatenated in order.
func (c Construction) Layout() ArgLayout { return c.layout }

func buildLayout(components []component) ArgLayout {
	layout := ArgLayout{components: make([]ComponentLayout, 0, len(components))}
	start := 0
	for _, part := range components {
		sizes := make([]int, len(part.profile.slots))
		for i, slot := range part.profile.slots {
			sizes[i] = slot.maxSize
		}
		layout.components = append(layout.components, ComponentLayout{Name: part.name, Primitive: part.primitive, Start: start, maxSizes: sizes})
		start += len(sizes)
	}
	return layout
}

// PublicKeySize returns the size of the canonical public key: the components'
// keys, concatenated in order.
func (c Construction) PublicKeySize() int {
	total := 0
	for _, part := range c.components {
		total += part.profile.publicKeySize
	}
	return total
}

// SplitPublicKey cuts a canonical public key into its components' keys. The result
// aliases publicKey.
func (c Construction) SplitPublicKey(publicKey []byte) ([][]byte, error) {
	if len(c.components) == 0 {
		return nil, fmt.Errorf("construction has no components")
	}
	if want := c.PublicKeySize(); len(publicKey) != want {
		return nil, fmt.Errorf("invalid public key size: expected %d, got %d", want, len(publicKey))
	}
	keys := make([][]byte, 0, len(c.components))
	offset := 0
	for _, part := range c.components {
		keys = append(keys, publicKey[offset:offset+part.profile.publicKeySize])
		offset += part.profile.publicKeySize
	}
	return keys, nil
}

// VerifyTEAL renders the verification of every component and leaves one boolean
// on the stack. message is trusted TEAL from the owning contract that pushes the
// signed bytes; firstArg is the argument slot of the first component.
//
// It renders only the verification. Each caller keeps what surrounds it, such as
// argument length checks and the final assert, because a plain LogicSig uses the
// remaining boolean as its result.
func (c Construction) VerifyTEAL(publicKey []byte, message string, firstArg int) (string, error) {
	keys, err := c.SplitPublicKey(publicKey)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	layout := c.Layout()
	for i, part := range c.components {
		if i > 0 {
			b.WriteString("assert\n")
		}
		b.WriteString(message)
		b.WriteString("\n")
		b.WriteString(part.profile.render(keys[i], firstArg+layout.components[i].Start))
	}
	return b.String(), nil
}

// PackSignature maps a signature to its argument slots. Only a single-component
// construction has a signature encoding today, and it stays the raw signature.
// A multi-component construction must define its own before it can be used.
func (c Construction) PackSignature(signature []byte) ([][]byte, error) {
	if len(c.components) != 1 {
		return nil, fmt.Errorf("construction %q defines no signature encoding", c.id)
	}
	return c.components[0].profile.pack(signature)
}

// SharesComponentKey reports whether two bindings hold the same key in components of
// the same primitive. This catches a witness key reused inside a larger construction.
// It compares known keys only, so it says nothing about custody or seed independence.
// A key that doesn't parse shares nothing here: parsing is its owner's check.
func SharesComponentKey(a Construction, aKey []byte, b Construction, bKey []byte) bool {
	aParts, err := a.SplitPublicKey(aKey)
	if err != nil {
		return false
	}
	bParts, err := b.SplitPublicKey(bKey)
	if err != nil {
		return false
	}
	for i, left := range a.components {
		for j, right := range b.components {
			if left.primitive == right.primitive && bytes.Equal(aParts[i], bParts[j]) {
				return true
			}
		}
	}
	return false
}

// Production catalog. It is closed and compiled: there is no runtime registration,
// and tests build their own definitions with New.
var (
	falcon1024Construction = mustConstruction(Definition{ID: "falcon1024", Components: []ComponentSpec{{Name: "falcon", Primitive: PrimitiveFalcon1024}}})
	ed25519Construction    = mustConstruction(Definition{ID: "ed25519", Components: []ComponentSpec{{Name: "ed25519", Primitive: PrimitiveEd25519}}})

	baseConstructions = map[string]Construction{
		"aplane.falcon1024.v1": falcon1024Construction,
		"aplane.ed25519.v1":    ed25519Construction,
	}
	witnessConstructions = map[string]Construction{
		witness.Falcon1024V1: falcon1024Construction,
	}
)

func mustConstruction(definition Definition) Construction {
	construction, err := New(definition)
	if err != nil {
		panic(fmt.Sprintf("invalid built-in signature construction: %v", err))
	}
	return construction
}

// Falcon1024 returns the single-component Falcon-1024 construction.
func Falcon1024() Construction { return falcon1024Construction }

// Ed25519 returns the single-component Ed25519 construction.
func Ed25519() Construction { return ed25519Construction }

// ForBaseKeyType resolves a spending base through the production catalog. Both
// lookups apply keytypecatalog.Canonicalize, the one key-type normalization the
// signer and clients share, so a spelling resolves the same way on every path.
func ForBaseKeyType(baseKeyType string) (Construction, bool) {
	construction, ok := baseConstructions[keytypecatalog.Canonicalize(baseKeyType)]
	return construction, ok
}

// ForWitnessKeyType resolves a witness key type through the production catalog.
func ForWitnessKeyType(keyType string) (Construction, bool) {
	construction, ok := witnessConstructions[keytypecatalog.Canonicalize(keyType)]
	return construction, ok
}
