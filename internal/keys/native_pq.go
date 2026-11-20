// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keys

import (
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/types"
	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"
)

// A native PQ key file stores neither its protocol scheme nor its address
// salt: the key type fixes the scheme, and the salt follows from the public
// key. These two functions are the one place that maps a key type to either,
// for the payload validator and the fee planner alike, so a second native PQ
// key type adds one case to each. The Falcon-only signed envelope reads
// nativefalcon.Scheme, the constant the falcon1024 case returns.

// NativePQScheme is the protocol PQ scheme a native PQ key type signs with,
// and false for a key type that is not native PQ.
func NativePQScheme(keyType string) (types.PQScheme, bool) {
	switch keyType {
	case nativefalcon.KeyType:
		return types.PQScheme{nativefalcon.Scheme[0], nativefalcon.Scheme[1]}, true
	default:
		return types.PQScheme{}, false
	}
}

// NativePQAddress derives a native PQ key's canonical address salt and its
// account address from its public key.
func NativePQAddress(keyType string, publicKey []byte) (byte, types.Address, error) {
	switch keyType {
	case nativefalcon.KeyType:
		return nativefalcon.CanonicalAddress(publicKey)
	default:
		return 0, types.Address{}, fmt.Errorf("unsupported native PQ key type %q", keyType)
	}
}
