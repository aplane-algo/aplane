// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package lsigprovider

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// CanonicalParameter is the shape of a creation parameter as it appears in
// compatibility fingerprints. Field order, JSON tags, and omitempty flags are
// part of the fingerprint format.
type CanonicalParameter struct {
	Name      string  `json:"name"`
	Type      string  `json:"type"`
	Required  bool    `json:"required"`
	MaxLength int     `json:"max_length"`
	MinItems  int     `json:"min_items"`
	MaxItems  int     `json:"max_items"`
	Min       *uint64 `json:"min,omitempty"`
	Max       *uint64 `json:"max,omitempty"`
	Default   string  `json:"default,omitempty"`
}

// CanonicalRuntimeArg is the shape of a runtime arg as it appears in
// compatibility fingerprints. See CanonicalParameter for stability notes.
type CanonicalRuntimeArg struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	Required   bool   `json:"required"`
	ByteLength int    `json:"byte_length"`
}

// ProjectParameterDef projects a provider parameter definition into its
// compatibility-bearing canonical form. Display-only fields are intentionally
// dropped.
func ProjectParameterDef(p ParameterDef) CanonicalParameter {
	return CanonicalParameter{
		Name:      p.Name,
		Type:      p.Type,
		Required:  p.Required,
		MaxLength: p.MaxLength,
		MinItems:  p.MinItems,
		MaxItems:  p.MaxItems,
		Min:       p.Min,
		Max:       p.Max,
		Default:   p.Default,
	}
}

// ProjectRuntimeArgDef projects a provider runtime arg definition into its
// compatibility-bearing canonical form. Display-only fields are intentionally
// dropped.
func ProjectRuntimeArgDef(a RuntimeArgDef) CanonicalRuntimeArg {
	return CanonicalRuntimeArg{
		Name:       a.Name,
		Type:       a.Type,
		Required:   a.Required,
		ByteLength: a.ByteLength,
	}
}

// HashCompatibilitySpec returns the hex-encoded sha256 of the JSON encoding
// of the supplied canonical spec. The caller owns the canonical spec's shape
// and field order; this helper only centralizes marshal-and-digest plumbing.
//
// json.Marshal should not fail for compatibility fingerprint canonical specs.
// If it does, that is a programmer error and must not silently produce a
// misleading fingerprint.
func HashCompatibilitySpec(canonicalSpec any) string {
	payload, err := json.Marshal(canonicalSpec)
	if err != nil {
		panic("lsigprovider: invalid compatibility fingerprint canonical spec: " + err.Error())
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}
