// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package lsigprovider

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// CompatibilityFingerprintVersion is the format version emitted by
// HashCompatibilitySpec. It is the major contract version of the *fingerprint
// formula* (the canonical field set and hashing rules), not of any provider or
// template. Bump it only when the formula itself changes (field set / hashing /
// projection rules) so old keys read as incompatible-format rather than as a
// behavior conflict. An identifier rename (key_type, family, base key type) is
// NOT a formula change and must never bump this.
const CompatibilityFingerprintVersion = 1

// ParsedFingerprint is the decomposed form of a versioned compatibility
// fingerprint string ("<version>:<hash>").
type ParsedFingerprint struct {
	Version int
	Hash    string
}

// ParseCompatibilityFingerprint splits a versioned fingerprint string into its
// version and hash. A well-formed "<n>:<hash>" (n a positive integer) returns
// {n, hash}, true. Any string without a valid positive-integer version prefix
// (unprefixed legacy/garbage) parses as version 0 with the whole string as the
// hash and ok=false; version 0 is never comparable. A valid version prefix whose
// hash is not 64-char sha256 hex also returns ok=false (malformed → not
// comparable).
func ParseCompatibilityFingerprint(s string) (ParsedFingerprint, bool) {
	idx := strings.IndexByte(s, ':')
	if idx <= 0 {
		return ParsedFingerprint{Version: 0, Hash: s}, false
	}
	version, err := strconv.Atoi(s[:idx])
	if err != nil || version <= 0 {
		return ParsedFingerprint{Version: 0, Hash: s}, false
	}
	hash := s[idx+1:]
	if !isSHA256Hex(hash) {
		// A well-formed version prefix with a malformed (non-sha256-hex) hash is
		// treated as not comparable, never as a behavior match or conflict.
		return ParsedFingerprint{Version: version, Hash: hash}, false
	}
	return ParsedFingerprint{Version: version, Hash: hash}, true
}

// isSHA256Hex reports whether s is exactly 64 hexadecimal characters — the shape
// HashCompatibilitySpec always produces. Anything else is malformed.
func isSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// FingerprintsMatch reports whether a durable (stored) fingerprint and a freshly
// computed (live) fingerprint describe the same behavior, and whether they were
// even comparable.
//
//   - empty stored                     -> (false, false)  no provenance to compare
//   - either side fails to parse        -> (false, false)  unparseable / legacy
//   - recognized but differing versions -> (false, false)  incompatible format
//   - same version                      -> (stored.hash == live.hash, true)
//
// A (false, false) result is benign: callers must treat "not comparable" as
// "no behavior conflict", never as a conflict. Only (false, true) — same
// version, different hash — is a real behavior conflict.
func FingerprintsMatch(stored, live string) (match bool, comparable bool) {
	if stored == "" {
		return false, false
	}
	ps, okStored := ParseCompatibilityFingerprint(stored)
	pl, okLive := ParseCompatibilityFingerprint(live)
	if !okStored || !okLive {
		return false, false
	}
	if ps.Version != pl.Version {
		return false, false
	}
	return ps.Hash == pl.Hash, true
}

// fingerprintBasePrimitives projects a raw, renameable base key type onto a
// stable behavior token for the compatibility fingerprint. Hashing this token
// instead of the raw base_key_type keeps the fingerprint stable across pure
// base-identifier renames (a renamed base adds a new raw->token row pointing at
// the *existing* token).
//
// FROZEN NAMESPACE — add rows, never rename tokens. These tokens exist only
// inside the hash; renaming one would re-introduce exactly the cross-rename
// drift this projection removes and would false-conflict every key in the
// field. A genuine base behavior change gets a *new* token (different hash),
// which is the correct conflict signal.
var fingerprintBasePrimitives = map[string]string{
	"aplane.falcon1024.v1": "falcon1024-v1",
	"aplane.ed25519.v1":    "ed25519-lsig-v1",
	// Pre-rename spelling of the Ed25519 LogicSig base maps to the same token so
	// a base-identifier rename never changes the fingerprint. No keys of this
	// name exist in a fresh deployment; the row documents the projection's intent
	// and future-proofs the rename case.
	"aplane.ed25519lsig.v1":        "ed25519-lsig-v1",
	"aplane.ecdsak1.v1":            "ecdsak1-v1",
	"aplane.falcon1024_ed25519.v1": "falcon1024-ed25519-v1",
}

// FingerprintBasePrimitive maps a raw base key type to its frozen behavior
// token. Built-in bases use the frozen table above; any other base falls back to
// a normalized (trimmed, lowercased) raw base key type, so rename-stability
// holds for built-ins only — a documented limitation for custom primitives.
func FingerprintBasePrimitive(baseKeyType string) string {
	// Normalize first so spelling variants (case/whitespace) of a built-in base
	// resolve to its frozen token instead of falling through to the raw form.
	normalized := strings.ToLower(strings.TrimSpace(baseKeyType))
	if token, ok := fingerprintBasePrimitives[normalized]; ok {
		return token
	}
	return normalized
}

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
	MaxSize    int    `json:"max_size,omitempty"`
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
		MaxSize:    a.MaxSize,
	}
}

// HashCompatibilitySpec returns the versioned compatibility fingerprint of the
// supplied canonical spec: "<CompatibilityFingerprintVersion>:" followed by the
// hex-encoded sha256 of the spec's JSON encoding. The caller owns the canonical
// spec's shape and field order; this helper only centralizes the version prefix
// plus marshal-and-digest plumbing.
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
	return fmt.Sprintf("%d:", CompatibilityFingerprintVersion) + hex.EncodeToString(sum[:])
}
