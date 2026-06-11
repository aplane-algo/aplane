// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package falcon provides Falcon-1024 post-quantum signature support.
//
// This package provides a convenient single import for client-safe Falcon-1024
// DSA metadata, LogicSig derivation, address derivation, and algorithm metadata.
// Signer-side key generation, mnemonic handling, signing, and key processors
// are registered by lsig/falcon1024/signerreg.
//
// Usage:
//
//	import "github.com/aplane-algo/aplane/lsig/falcon1024"
//
//	func init() {
//	    falcon.RegisterClient()
//	}
//
// Registrations:
//   - Falcon1024V1 registers with internal/logicsigdsa (unified DSA, versioned key type)
//   - Supporting registries use "falcon1024" (keygen, mnemonic, signing, algorithm)
package falcon

import (
	"sync"

	"github.com/aplane-algo/aplane/internal/addressderive"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	"github.com/aplane-algo/aplane/lsig/dsafamily"
	"github.com/aplane-algo/aplane/lsig/falcon1024/family"
	falconkeys "github.com/aplane-algo/aplane/lsig/falcon1024/keys"
	v1 "github.com/aplane-algo/aplane/lsig/falcon1024/v1"
)

var (
	registerClientOnce sync.Once
)

// RegisterClient registers client-safe Falcon-1024 metadata and derivation.
// This is idempotent and safe to call multiple times.
//
// Registration includes:
// - LogicSigDSA metadata and derivation
// - Algorithm metadata for display
// - Pure address derivation
func RegisterClient() {
	registerClientOnce.Do(func() {
		dsafamily.RegisterClient(dsafamily.ClientRegistration{
			Family:   family.Name,
			Metadata: &FalconMetadata{},
			KeyTypes: []dsafamily.KeyType{{
				KeyType:        "aplane.falcon1024.v1",
				DSA:            &v1.Falcon1024V1{},
				AddressDeriver: falconkeys.GetFalconAddressDeriverForType("aplane.falcon1024.v1"),
			}},
			Extra: []func(){func() {
				composeddsa.RegisterBase(composeddsa.BaseRegistration{
					BaseKeyType: "aplane.falcon1024.v1",
					FamilyName:  family.Name,
					Version:     1,
					Ops:         v1.NewFalconOps(family.FalconBase),
					NewAddressDeriver: func(templateKeyType string) addressderive.Deriver {
						return falconkeys.GetFalconAddressDeriverForType(templateKeyType)
					},
				})
			}},
		})
	})
}
