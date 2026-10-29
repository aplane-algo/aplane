// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package signerreg registers the XMSS triple rotating key type's
// signer-side hooks: the key file codec, the stage cryptography and the
// generator.
package signerreg

import (
	"fmt"
	"sync"

	"github.com/aplane-algo/aplane/internal/crypto/rotatinghybrid"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/rotatingkey"
	rotatingfamilyreg "github.com/aplane-algo/aplane/lsig/rotatingfamily/signerreg"
	"github.com/aplane-algo/aplane/lsig/rotatingfamily/stagesign"
	"github.com/aplane-algo/aplane/lsig/rotatingtriplexmss/signerops"
	"github.com/aplane-algo/aplane/lsig/rotatingtriplexmss/stage"
)

var registerOnce sync.Once

// stageOps is the process's one stage cryptography for this key type. Its
// tree cache is shared by key generation, validation and signing, so a tree
// built for one of them serves the others.
var stageOps = signerops.NewStageOps()

// StageOps returns the registered stage cryptography, for callers that
// pre-build trees or inspect the cache.
func StageOps() *signerops.StageOps { return stageOps }

// Register installs the key file codec, the stage cryptography and the
// generator. It is safe to call more than once. The registered stage
// cryptography is stageOps itself, so its tree cache and its
// signing.RotatingTreeOps methods reach the signing flow.
func Register() {
	registerOnce.Do(func() {
		rotatingfamilyreg.Register(rotatingfamilyreg.Descriptor{
			KeyType:        rotatingkey.RotatingTripleXmssV1,
			Family:         rotatingkey.RotatingTripleXmssFamily,
			NewKeyPayload:  NewKeyPayload,
			AccountAddress: accountAddress,
			ValidateSeed:   validateSeed,
			StageOps:       stageOps,
		})
	})
}

// NewKeyPayload derives stage 0 from seed on the network named by
// genesisHash, building tree 0 (seconds), and returns the key file payload
// and the account address. The caller owns the payload and must zero it.
func NewKeyPayload(seed *rotatinghybrid.Seed, genesisHash [rotatinghybrid.GenesisHashSize]byte) (*keys.Payload, string, error) {
	d, err := signerops.NewDeriver(seed, genesisHash)
	if err != nil {
		return nil, "", err
	}
	defer d.Zero()
	tag, err := signerops.AccountTag(d)
	if err != nil {
		return nil, "", err
	}
	stageKeys, program, err := stageOps.Derive(d, 0)
	if err != nil {
		return nil, "", err
	}
	defer stageKeys.Zero()
	payload := keys.NewRotatingLSigPayload(rotatingkey.RotatingTripleXmssV1, seed[:], genesisHash[:], packPublicKeys(tag, stageKeys.PublicKeys()))
	return payload, program.Address.String(), nil
}

// packedSize is the key file's stage 0 record size.
const packedSize = signerops.AccountTagSize + stage.FalconPublicKeySize + 3*stage.ConstantSize

// packPublicKeys lays out the key file's stage 0 record: the public account
// tag, the Falcon-1024 public key, tree 0's root and public seed, and the
// Ed25519 public key. Stage 0's range is fixed, so it is not stored.
func packPublicKeys(tag [signerops.AccountTagSize]byte, pk *stage.PublicKeys) []byte {
	packed := make([]byte, 0, packedSize)
	packed = append(packed, tag[:]...)
	packed = append(packed, pk.Falcon[:]...)
	packed = append(packed, pk.Root[:]...)
	packed = append(packed, pk.Seed[:]...)
	return append(packed, pk.Ed25519[:]...)
}

func unpackPublicKeys(packed []byte) ([signerops.AccountTagSize]byte, *stage.PublicKeys, error) {
	var tag [signerops.AccountTagSize]byte
	if len(packed) != packedSize {
		return tag, nil, fmt.Errorf("stage public key length %d invalid", len(packed))
	}
	pk := &stage.PublicKeys{}
	_, pk.Lo, pk.Hi = stage.RangeFor(0)
	rest := packed[copy(tag[:], packed):]
	rest = rest[copy(pk.Falcon[:], rest):]
	rest = rest[copy(pk.Root[:], rest):]
	rest = rest[copy(pk.Seed[:], rest):]
	copy(pk.Ed25519[:], rest)
	return tag, pk, nil
}

func accountAddress(stageZeroPublicKey []byte) (string, error) {
	_, pk, err := unpackPublicKeys(stageZeroPublicKey)
	if err != nil {
		return "", err
	}
	program, err := stage.Build(pk)
	if err != nil {
		return "", err
	}
	return program.Address.String(), nil
}

// validateSeed checks that the seed derives the stored stage 0 record. It
// runs on every key file parse, so it checks what is cheap to derive: the
// account tag, tree 0's public seed and stage 0's Ed25519 and Falcon keys.
// Tree 0's root takes seconds to recompute; it is compared only when the
// tree is already cached. A wrong root is still caught before any signing,
// because the stage program the signer derives would not match the
// account's on-chain authorizer.
func validateSeed(seed, genesisHash, stageZeroPublicKey []byte) error {
	tag, want, err := unpackPublicKeys(stageZeroPublicKey)
	if err != nil {
		return err
	}
	d, err := rotatinghybrid.OpenDeriver(seed, genesisHash, signerops.DerivationLabel)
	if err != nil {
		return err
	}
	defer d.Zero()
	gotTag, err := signerops.AccountTag(d)
	if err != nil {
		return err
	}
	if gotTag != tag {
		return fmt.Errorf("account tag mismatch")
	}
	treeSeeds, err := signerops.TreeSeeds(d, 0)
	if err != nil {
		return err
	}
	defer treeSeeds.Zero()
	if treeSeeds.PubSeed != want.Seed {
		return fmt.Errorf("tree 0 public seed mismatch")
	}
	classical, err := stagesign.DeriveClassicalKeys(d, 0, signerops.Ed25519InfoTag, signerops.FalconInfoTag)
	if err != nil {
		return err
	}
	edKey, falconKey := classical.PublicKeys()
	classical.Zero()
	if edKey != want.Ed25519 {
		return fmt.Errorf("stage 0 Ed25519 public key mismatch")
	}
	if falconKey != want.Falcon {
		return fmt.Errorf("stage 0 Falcon public key mismatch")
	}
	if tree, ok := stageOps.CachedTree(d, 0); ok && tree.PK.Root != want.Root {
		return fmt.Errorf("tree 0 root mismatch")
	}
	return nil
}
