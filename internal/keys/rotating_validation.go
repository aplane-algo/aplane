// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keys

import (
	"fmt"
	"sync"
)

// RotatingCodec is a rotating LogicSig family's signer-side registration. The
// key file stores a seed, the network's genesis hash, and stage 0's public
// keys; the account address is stage 0's program address. Only the family
// knows its program and derivation, so both checks are registered here rather
// than linked into storage code.
type RotatingCodec struct {
	// AccountAddress derives the account address from stage 0's public keys.
	AccountAddress func(stageZeroPublicKey []byte) (string, error)

	// ValidateSeed reports whether seed derives stageZeroPublicKey on the
	// network identified by genesisHash.
	ValidateSeed func(seed, genesisHash, stageZeroPublicKey []byte) error
}

var rotatingCodecs = struct {
	sync.RWMutex
	byKeyType map[string]RotatingCodec
}{byKeyType: make(map[string]RotatingCodec)}

// RegisterRotatingCodec registers the codec for one rotating key type.
// Duplicate registration is a programming error.
func RegisterRotatingCodec(keyType string, codec RotatingCodec) {
	if keyType == "" || codec.AccountAddress == nil || codec.ValidateSeed == nil {
		panic("rotating codec requires a key type and both functions")
	}
	rotatingCodecs.Lock()
	defer rotatingCodecs.Unlock()
	if _, exists := rotatingCodecs.byKeyType[keyType]; exists {
		panic("duplicate rotating codec for key type: " + keyType)
	}
	rotatingCodecs.byKeyType[keyType] = codec
}

func rotatingCodec(keyType string) (RotatingCodec, error) {
	rotatingCodecs.RLock()
	codec, ok := rotatingCodecs.byKeyType[keyType]
	rotatingCodecs.RUnlock()
	if !ok {
		return RotatingCodec{}, fmt.Errorf("rotating key type %q is not registered in this signer", keyType)
	}
	return codec, nil
}
