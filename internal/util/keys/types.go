// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package keys

// ImportKeyResult contains the results of importing a key
type ImportKeyResult struct {
	Address     string
	LsigFile    string
	PublicFile  string
	PrivateFile string
}

// Key categories
const (
	CategoryEd25519     = "ed25519"      // Standard Algorand Ed25519 keys
	CategoryDSALsig     = "dsa_lsig"     // DSA-based LogicSigs (falcon1024, etc.) - has key material
	CategoryGenericLsig = "generic_lsig" // Generic LogicSigs (timelock, etc.) - no key material
)

// CurrentKeyFormatVersion is the current version of the key file format
const CurrentKeyFormatVersion = 1

// KeyPair represents a cryptographic key pair (Ed25519 or post-quantum)
// Supports both Ed25519 and DSA LogicSig-based signature schemes (Falcon-1024, etc.)
type KeyPair struct {
	FormatVersion   int    `json:"format_version"`          // Key file format version
	Category        string `json:"category"`                // Key category: "ed25519", "dsa_lsig"
	KeyType         string `json:"key_type"`                // Full versioned type: "ed25519", "falcon1024-v1", etc.
	PublicKeyHex    string `json:"public_key"`              // Hex-encoded public key
	PrivateKeyHex   string `json:"private_key"`             // Hex-encoded private key
	EntropyHex      string `json:"entropy,omitempty"`       // BIP-39 entropy for mnemonic export (optional)
	Derivation      string `json:"derivation,omitempty"`    // Derivation method: "pbkdf2-100k", "bip39-standard" (optional)
	LsigBytecodeHex string `json:"lsig_bytecode,omitempty"` // Hex-encoded LogicSig bytecode (DSA LogicSigs only)

	// Params holds additional creation parameters for hybrid DSA LSigs.
	// For pure DSA (falcon1024-v1): empty/nil
	// For hybrid (falcon-timelock-v1): contains unlock_round, recipient, etc.
	Params map[string]string `json:"params,omitempty"`

	// TEALSource stores the original TEAL source for DSA LogicSigs.
	// Present for keys generated with ComposedDSA architecture.
	TEALSource string `json:"teal_source,omitempty"`

	CreatedAt string `json:"created_at,omitempty"` // RFC 3339 creation timestamp
}
