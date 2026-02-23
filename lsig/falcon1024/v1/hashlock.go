// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package v1

import (
	"sync"

	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/lsig/falcon1024/family"
)

// FalconHashlockV1 is a composed LogicSig that combines Falcon-1024 signature
// verification with SHA256 hash preimage verification.
//
// The LogicSig requires two arguments at signing time:
//   - arg 0: Falcon-1024 signature of the transaction ID
//   - arg 1: Preimage whose SHA256 hash matches the stored hash
//
// Creation parameters:
//   - hash: SHA256 hash (32 bytes, hex-encoded) that must be satisfied
//
// Note: SetAlgodClient must be called before DeriveLsig.
var FalconHashlockV1 = NewComposedDSA(ComposedDSAConfig{
	KeyType:     "falcon1024-hashlock-v1",
	FamilyName:  family.Name,
	Version:     1,
	DisplayName: "Falcon-1024 Hashlock",
	Description: "Falcon-1024 signature with SHA256 hash verification (requires preimage to spend)",

	Base: family.FalconBase,
	Params: []lsigprovider.ParameterDef{{
		Name:      "hash",
		Label:     "SHA256 Hash",
		Type:      "bytes",
		Required:  true,
		MaxLength: 64,
		Example:   "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		InputModes: []lsigprovider.InputMode{
			{
				Name:       "hash",
				Label:      "SHA256 Hash (hex)",
				ByteLength: 32,
			},
			{
				Name:      "preimage",
				Label:     "Preimage (will be hashed)",
				Transform: "sha256",
				InputType: "string",
			},
		},
	}},
	RuntimeArgs: []lsigprovider.RuntimeArgDef{{
		Name:        "preimage",
		Label:       "Secret Preimage",
		Description: "The secret value whose SHA256 hash matches the stored hash",
		Type:        "bytes",
		Required:    true,
	}},
	TEALSuffix: `// Prevent rekeying
txn RekeyTo
global ZeroAddress
==
assert
// Prevent closing account
txn CloseRemainderTo
global ZeroAddress
==
assert
// Prevent clawback (AssetSender must be ZeroAddress)
txn AssetSender
global ZeroAddress
==
assert
// Hash verification: sha256(arg 1) == stored hash
arg 1
sha256
byte @hash
==
assert`,
})

var registerHashlockOnce sync.Once

// RegisterFalconHashlockV1 registers FalconHashlockV1 with the logicsigdsa registry.
// This is idempotent and safe to call multiple times.
func RegisterFalconHashlockV1() {
	registerHashlockOnce.Do(func() {
		logicsigdsa.Register(FalconHashlockV1)
	})
}
