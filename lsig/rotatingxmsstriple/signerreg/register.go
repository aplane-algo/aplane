// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package signerreg registers the XMSS triple rotating key type's
// signer-side hooks: the key file codec, the stage cryptography and the
// generator.
package signerreg

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"sync"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/crypto/rotatinghybrid"
	"github.com/aplane-algo/aplane/internal/keygen"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/rotatingkey"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/lsig/rotatingxmsstriple/signerops"
	"github.com/aplane-algo/aplane/lsig/rotatingxmsstriple/stage"

	"github.com/algorandfoundation/falcon-signatures/falcongo"
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
// generator. It is safe to call more than once.
func Register() {
	registerOnce.Do(func() {
		keys.RegisterRotatingCodec(rotatingkey.RotatingXmssTripleV1, keys.RotatingCodec{
			AccountAddress: accountAddress,
			ValidateSeed:   validateSeed,
		})
		signing.RegisterRotatingStageOps(rotatingkey.RotatingXmssTripleV1, stageOps)
		keygen.Register(generator{})
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
	payload := keys.NewRotatingLSigPayload(rotatingkey.RotatingXmssTripleV1, seed[:], genesisHash[:], packPublicKeys(tag, stageKeys.PublicKeys()))
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
func validateSeed(seedBytes, genesisHashBytes, stageZeroPublicKey []byte) error {
	tag, want, err := unpackPublicKeys(stageZeroPublicKey)
	if err != nil {
		return err
	}
	var seed rotatinghybrid.Seed
	var genesisHash [rotatinghybrid.GenesisHashSize]byte
	if len(seedBytes) != len(seed) || len(genesisHashBytes) != len(genesisHash) {
		return fmt.Errorf("seed or genesis hash has the wrong length")
	}
	copy(seed[:], seedBytes)
	defer seed.Zero()
	copy(genesisHash[:], genesisHashBytes)
	d, err := signerops.NewDeriver(&seed, genesisHash)
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
	var edSeed [rotatinghybrid.Ed25519SeedSize]byte
	if err := d.ExpandStage(signerops.Ed25519InfoTag, 0, edSeed[:]); err != nil {
		return err
	}
	edKey := ed25519.NewKeyFromSeed(edSeed[:])
	crypto.ZeroBytes(edSeed[:])
	edMatch := bytes.Equal(edKey.Public().(ed25519.PublicKey), want.Ed25519[:])
	crypto.ZeroBytes(edKey)
	if !edMatch {
		return fmt.Errorf("stage 0 Ed25519 public key mismatch")
	}
	var falconSeed [rotatinghybrid.FalconSeedSize]byte
	if err := d.ExpandStage(signerops.FalconInfoTag, 0, falconSeed[:]); err != nil {
		return err
	}
	kp, err := falcongo.GenerateKeyPair(falconSeed[:])
	crypto.ZeroBytes(falconSeed[:])
	if err != nil {
		return fmt.Errorf("generate stage 0 Falcon key: %w", err)
	}
	falconMatch := bytes.Equal(kp.PublicKey[:], want.Falcon[:])
	crypto.ZeroBytes(kp.PrivateKey[:])
	if !falconMatch {
		return fmt.Errorf("stage 0 Falcon public key mismatch")
	}
	if tree, ok := stageOps.CachedTree(d, 0); ok && tree.PK.Root != want.Root {
		return fmt.Errorf("tree 0 root mismatch")
	}
	return nil
}
