// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keys

import (
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/signingargs"
)

// ImportKeyResult contains the results of importing a key.
type ImportKeyResult struct {
	Address     string
	LsigFile    string
	PublicFile  string
	PrivateFile string
}

const (
	CategoryEd25519         = "ed25519"
	CategoryDSALsig         = "dsa_lsig"
	CategoryGenericLsig     = "generic_lsig"
	CategoryComponent       = "component"
	CurrentKeyFormatVersion = 1
)

const CurrentSigningMetadataVersion = 1

const (
	TemplateProvenanceStatusConflict    = "conflict"
	TemplateProvenanceStatusUnavailable = "unavailable"
)

// StoredSigningArg records the signing-time LogicSig arg contract captured
// into a key file. Keys use this at signing time so installed template metadata
// cannot change the behavior or usability of an existing key.
type StoredSigningArg = signingargs.Info

// KeyPair represents a cryptographic key pair (Ed25519 or post-quantum).
type KeyPair struct {
	FormatVersion   int    `json:"format_version"`
	Category        string `json:"category"`
	KeyType         string `json:"key_type"`
	PublicKeyHex    string `json:"public_key"`
	PrivateKeyHex   string `json:"private_key"`
	EntropyHex      string `json:"entropy,omitempty"`
	Derivation      string `json:"derivation,omitempty"`
	LsigBytecodeHex string `json:"lsig_bytecode,omitempty"`
	// SaltCounter is nil for non-LogicSig keys and required for DSA LogicSig
	// key files; zero is a valid persisted counter and must stay non-nil.
	SaltCounter            *byte              `json:"salt_counter,omitempty"`
	Params                 map[string]string  `json:"params,omitempty"`
	TEALSource             string             `json:"teal_source,omitempty"`
	SigningMetadataVersion int                `json:"signing_metadata_version,omitempty"`
	BaseKeyType            string             `json:"base_key_type,omitempty"`
	SigningArgs            []StoredSigningArg `json:"signing_args,omitempty"`
	TemplateFingerprint    string             `json:"template_fingerprint,omitempty"`
	CreatedAt              string             `json:"created_at,omitempty"`
}

// SaltCounterPtr returns a pointer to counter for DSA LogicSig key files, where
// zero is a valid persisted salt counter and must not be omitted.
func SaltCounterPtr(counter byte) *byte {
	return &counter
}

// TemplateFingerprintForKeyType returns the semantic compatibility fingerprint
// of the currently registered provider/template, when that provider exposes one.
func TemplateFingerprintForKeyType(keyType string) string {
	provider := lsigprovider.Get(keyType)
	if provider == nil {
		return ""
	}
	fingerprint, ok := lsigprovider.CompatibilityFingerprintOf(provider)
	if !ok {
		return ""
	}
	return fingerprint
}

// CompareTemplateFingerprint compares durable key-file template provenance with
// the provider/template currently registered in this signer process.
func CompareTemplateFingerprint(keyType, storedFingerprint string) (status, note string) {
	if storedFingerprint == "" {
		return "", ""
	}
	provider := lsigprovider.Get(keyType)
	if provider == nil {
		return TemplateProvenanceStatusUnavailable, "creation template is not registered in this signer"
	}
	liveFingerprint, ok := lsigprovider.CompatibilityFingerprintOf(provider)
	if !ok {
		return TemplateProvenanceStatusUnavailable, "registered key type does not expose a template fingerprint"
	}
	match, comparable := lsigprovider.FingerprintsMatch(storedFingerprint, liveFingerprint)
	if !comparable {
		// Different fingerprint formats (a future formula version, or an
		// unparseable/legacy value) are not a behavior conflict — provenance
		// simply cannot be established across formats.
		return TemplateProvenanceStatusUnavailable, "stored template fingerprint uses an incompatible format and cannot be compared to the currently registered definition"
	}
	if !match {
		return TemplateProvenanceStatusConflict, "creation template fingerprint differs from the currently registered definition"
	}
	return "", ""
}

// StoreSigningArgs projects provider runtime args into their durable key-file
// representation.
func StoreSigningArgs(defs []lsigprovider.RuntimeArgDef) []StoredSigningArg {
	return signingargs.FromRuntimeDefs(defs)
}

// SigningArgDefs converts durable key-file signing args back to provider args.
func SigningArgDefs(stored []StoredSigningArg) []lsigprovider.RuntimeArgDef {
	return signingargs.ToRuntimeDefs(stored)
}
