// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

// Package falcon provides Falcon-1024 post-quantum signature support.
//
// This package provides a convenient single import for all Falcon-1024 DSA components:
//   - Key generation (from seed, mnemonic, random)
//   - Mnemonic handling (BIP-39, 24 words)
//   - Cryptographic signing operations
//   - LogicSig derivation and transaction construction
//   - Key processing and address derivation
//   - Algorithm metadata (including display color)
//
// Usage:
//
//	import "github.com/aplane-algo/aplane/lsig/falcon1024"
//
//	func init() {
//	    falcon.RegisterAll()
//	}
//
// Registrations:
//   - Falcon1024V1 registers with internal/logicsigdsa (unified DSA, versioned key type)
//   - Supporting registries use "falcon1024" (keygen, mnemonic, signing, algorithm)
package falcon

import (
	"sync"

	"github.com/aplane-algo/aplane/lsig/falcon1024/keygen"
	falconkeys "github.com/aplane-algo/aplane/lsig/falcon1024/keys"
	"github.com/aplane-algo/aplane/lsig/falcon1024/mnemonic"
	falconsigning "github.com/aplane-algo/aplane/lsig/falcon1024/signing"
	v1 "github.com/aplane-algo/aplane/lsig/falcon1024/v1"
)

var registerAllOnce sync.Once

// RegisterAll registers all Falcon-1024 components with their respective registries.
// This is idempotent and safe to call multiple times.
//
// Registration order is significant:
// 1. LogicSigDSA - MUST be first, others depend on logicsigdsa.Get()
// 2. Metadata - algorithm metadata for display
// 3. Signing provider - for transaction signing
// 4. Key generator - for key creation
// 5. Mnemonic handler - for BIP-39 mnemonic handling
// 6. Key processors - for key file processing and address derivation
func RegisterAll() {
	registerAllOnce.Do(func() {
		// 1. LogicSigDSA MUST be registered first - other components call logicsigdsa.Get()
		v1.RegisterLogicSigDSA()

		// 1b. Hybrid Falcon providers
		v1.RegisterFalconTimelockV1()
		v1.RegisterFalconHashlockV1()

		// 2. Algorithm metadata (display color, signature size, etc.)
		RegisterMetadata()

		// 3. Signing provider for transaction signing
		falconsigning.RegisterProvider()

		// 4. Key generator for creating new keys
		keygen.RegisterGenerator()

		// 5. Mnemonic handler for BIP-39 word handling
		mnemonic.RegisterHandler()

		// 6. Key processors for key file handling and address derivation
		falconkeys.RegisterProcessors()
	})
}
