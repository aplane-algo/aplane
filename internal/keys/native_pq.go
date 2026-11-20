// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keys

import (
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/types"
	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"
)

// A native PQ key file stores neither its protocol scheme nor its address
// salt: both follow from its key type and public key. These two functions are
// the one place that derives them, so a second native PQ key type adds one
// case to each.

// nativePQScheme is the protocol PQ scheme a native PQ key type signs with.
func nativePQScheme(keyType string) (string, error) {
	switch keyType {
	case nativefalcon.KeyType:
		return nativefalcon.Scheme, nil
	default:
		return "", fmt.Errorf("unsupported native PQ key type %q", keyType)
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
