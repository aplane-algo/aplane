// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"fmt"
	"sync"

	"github.com/aplane-algo/aplane/internal/crypto"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// RotatingKeyMaterial is the loaded secret of a rotating account: the seed
// every stage is derived from, and the genesis hash it is bound to. It is the
// Value of a KeyMaterial whose Category is rotating_lsig.
type RotatingKeyMaterial struct {
	Seed        []byte
	GenesisHash []byte
}

// Zero clears the seed.
func (m *RotatingKeyMaterial) Zero() {
	if m == nil {
		return
	}
	crypto.ZeroBytes(m.Seed)
	m.Seed = nil
}

// RotatingStageSignature is one stage's authorization of a transaction: the
// stage program and its arguments, ready to attach as a LogicSig.
type RotatingStageSignature struct {
	Program []byte
	Args    [][]byte
}

// RotatingStageOps is a rotating family's stage cryptography. Signing code
// owns the protocol (which stage is live, what the next target is); the
// family owns how a stage is derived and signs. Every method derives the stage it needs from
// the key material and zeroes the stage keys before returning.
type RotatingStageOps interface {
	// StageAddress returns stage i's program address.
	StageAddress(key *RotatingKeyMaterial, stage uint64) (types.Address, error)

	// CheckStageOpens signs a fixed test message with stage i's derived keys
	// and verifies it against the keys embedded in stage i's program, proving
	// a rotation target can authorize the account once it is live.
	CheckStageOpens(key *RotatingKeyMaterial, stage uint64) error

	// SignStage signs message with stage i, verifies every signature against
	// the stage program's keys, and returns the program and arguments. index
	// selects the one-time leaf for families whose stage holds several (the
	// signing flow chooses it); a family with one key per stage ignores it.
	SignStage(key *RotatingKeyMaterial, stage uint64, index uint32, message []byte) (RotatingStageSignature, error)
}

var rotatingStageOps = struct {
	sync.RWMutex
	byKeyType map[string]RotatingStageOps
}{byKeyType: make(map[string]RotatingStageOps)}

// RegisterRotatingStageOps registers one rotating key type's stage
// cryptography. Duplicate registration is a programming error.
func RegisterRotatingStageOps(keyType string, ops RotatingStageOps) {
	if keyType == "" || ops == nil {
		panic("rotating stage ops require a key type and an implementation")
	}
	rotatingStageOps.Lock()
	defer rotatingStageOps.Unlock()
	if _, exists := rotatingStageOps.byKeyType[keyType]; exists {
		panic("duplicate rotating stage ops for key type: " + keyType)
	}
	rotatingStageOps.byKeyType[keyType] = ops
}

// GetRotatingStageOps returns the stage cryptography for a rotating key type.
func GetRotatingStageOps(keyType string) (RotatingStageOps, error) {
	rotatingStageOps.RLock()
	defer rotatingStageOps.RUnlock()
	ops, ok := rotatingStageOps.byKeyType[keyType]
	if !ok {
		return nil, fmt.Errorf("rotating key type %q has no registered stage operations", keyType)
	}
	return ops, nil
}
