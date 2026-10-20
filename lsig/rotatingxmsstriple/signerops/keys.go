// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package signerops holds the signer-side private-key operations of the
// aplane.rotating-xmss-triple.v1 key type: tree and stage key derivation and
// the XMSS, Ed25519 and Falcon-1024 signatures over a transaction ID.
//
// Every key derives from the account seed under the key type's own HKDF
// label. Per tree (a run of stage.StagesPerTree stages) the three XMSS seeds:
// the WOTS+ secret seed, the PRF key for message randomization and the
// public seed. Per stage the Ed25519 seed and the Falcon-1024 seed. The
// public account tag once. The deriver binds every expansion to the
// network's genesis hash, so one seed is a different account on every
// network.
package signerops

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/crypto/rotatinghybrid"
	"github.com/aplane-algo/aplane/internal/crypto/xmss"
	"github.com/aplane-algo/aplane/lsig/rotatingxmsstriple/stage"

	"github.com/algorand/falcon"
	"github.com/algorandfoundation/falcon-signatures/falcongo"
)

const (
	// DerivationLabel is the HKDF salt of this key type.
	DerivationLabel = "APLANE_ROTATING_XMSS_V1"

	// FalconInfoTag selects a stage's Falcon-1024 seed, Ed25519InfoTag its
	// Ed25519 seed and TagInfoTag the public account tag; the values match
	// the other rotating key types and the label keeps the keys apart.
	// TreeSecretSeedTag, TreePRFKeyTag and TreePublicSeedTag select a
	// tree's XMSS seeds, with the tree number as the expansion counter.
	FalconInfoTag     byte = 0x01
	Ed25519InfoTag    byte = 0x02
	TagInfoTag        byte = 0x10
	TreeSecretSeedTag byte = 0x20
	TreePRFKeyTag     byte = 0x21
	TreePublicSeedTag byte = 0x22

	// AccountTagSize is the public account tag.
	AccountTagSize = 32
)

// NewDeriver binds a seed to a network under this key type's label.
func NewDeriver(seed *rotatinghybrid.Seed, genesisHash [rotatinghybrid.GenesisHashSize]byte) (*rotatinghybrid.Deriver, error) {
	return rotatinghybrid.NewDeriverWithLabel(seed, genesisHash, DerivationLabel)
}

// AccountTag derives the public account tag: HKDF(0x10 || G), 32 bytes. It
// names the account in caches before stage 0's address is known.
func AccountTag(d *rotatinghybrid.Deriver) ([AccountTagSize]byte, error) {
	var tag [AccountTagSize]byte
	if err := d.ExpandAccount(TagInfoTag, tag[:]); err != nil {
		return tag, err
	}
	return tag, nil
}

// TreeSeeds derives tree n's XMSS seeds. The caller must Zero them.
func TreeSeeds(d *rotatinghybrid.Deriver, tree uint64) (*xmss.Seeds, error) {
	if d == nil {
		return nil, errors.New("rotating xmss deriver is nil")
	}
	s := &xmss.Seeds{}
	for _, part := range []struct {
		tag byte
		dst []byte
	}{
		{TreeSecretSeedTag, s.SKSeed[:]},
		{TreePRFKeyTag, s.SKPRF[:]},
		{TreePublicSeedTag, s.PubSeed[:]},
	} {
		if err := d.ExpandStage(part.tag, tree, part.dst); err != nil {
			s.Zero()
			return nil, err
		}
	}
	return s, nil
}

// PublicTree is the public half of one XMSS tree: its number, its nodes
// (reconstructible from the seed, about 4 MiB) and its public key. It holds
// no secret.
type PublicTree struct {
	Number uint64
	Tree   *xmss.Tree
	PK     xmss.PublicKey
}

// GenerateTree builds tree n's public nodes from the seed. It walks all
// 65,536 leaves (seconds) and is the only operation that does.
func GenerateTree(d *rotatinghybrid.Deriver, tree uint64) (*PublicTree, error) {
	seeds, err := TreeSeeds(d, tree)
	if err != nil {
		return nil, err
	}
	defer seeds.Zero()
	t := xmss.GenerateTree(seeds)
	return &PublicTree{Number: tree, Tree: t, PK: xmss.PublicKey{Root: t.Root(), Seed: seeds.PubSeed}}, nil
}

// StageKeys are the private keys of one stage: its own Ed25519 and
// Falcon-1024 keys and the seeds of the tree whose leaves it signs with.
// Callers must Zero them.
type StageKeys struct {
	stage   uint64
	tree    *PublicTree
	seeds   *xmss.Seeds
	ed25519 ed25519.PrivateKey
	falcon  falcongo.KeyPair
	lo, hi  uint64
}

// DeriveStage derives stage i's keys and program. tree must be the public
// tree of i's run (stage.RangeFor).
func DeriveStage(d *rotatinghybrid.Deriver, i uint64, tree *PublicTree) (*StageKeys, stage.Program, error) {
	if d == nil {
		return nil, stage.Program{}, errors.New("rotating xmss deriver is nil")
	}
	treeNo, lo, hi := stage.RangeFor(i)
	if tree == nil || tree.Tree == nil || tree.Number != treeNo {
		return nil, stage.Program{}, fmt.Errorf("stage %d needs tree %d", i, treeNo)
	}
	keys := &StageKeys{stage: i, tree: tree, lo: lo, hi: hi}
	seeds, err := TreeSeeds(d, treeNo)
	if err != nil {
		return nil, stage.Program{}, err
	}
	keys.seeds = seeds
	if seeds.PubSeed != tree.PK.Seed {
		keys.Zero()
		return nil, stage.Program{}, fmt.Errorf("tree %d does not derive from this seed", treeNo)
	}
	var edSeed [rotatinghybrid.Ed25519SeedSize]byte
	if err := d.ExpandStage(Ed25519InfoTag, i, edSeed[:]); err != nil {
		keys.Zero()
		return nil, stage.Program{}, err
	}
	keys.ed25519 = ed25519.NewKeyFromSeed(edSeed[:])
	crypto.ZeroBytes(edSeed[:])
	var falconSeed [rotatinghybrid.FalconSeedSize]byte
	if err := d.ExpandStage(FalconInfoTag, i, falconSeed[:]); err != nil {
		keys.Zero()
		return nil, stage.Program{}, err
	}
	keys.falcon, err = falcongo.GenerateKeyPair(falconSeed[:])
	crypto.ZeroBytes(falconSeed[:])
	if err != nil {
		keys.Zero()
		return nil, stage.Program{}, fmt.Errorf("generate stage %d Falcon key: %w", i, err)
	}
	program, err := stage.Build(keys.PublicKeys())
	if err != nil {
		keys.Zero()
		return nil, stage.Program{}, fmt.Errorf("build stage %d program: %w", i, err)
	}
	return keys, program, nil
}

// PublicKeys returns the constants a stage program embeds.
func (k *StageKeys) PublicKeys() *stage.PublicKeys {
	pub := &stage.PublicKeys{Root: k.tree.PK.Root, Seed: k.tree.PK.Seed, Lo: k.lo, Hi: k.hi}
	copy(pub.Ed25519[:], k.ed25519.Public().(ed25519.PublicKey))
	copy(pub.Falcon[:], k.falcon.PublicKey[:])
	return pub
}

// Range returns the stage's leaf index range, Lo <= index < Hi.
func (k *StageKeys) Range() (lo, hi uint64) { return k.lo, k.hi }

// Sign returns the stage's argument 0 (XMSS, with leaf index), argument 1
// (Ed25519) and argument 2 (Falcon-1024) signatures over message, which for
// a spend is the raw 32-byte transaction ID. The leaf must lie in the
// stage's range; the caller chooses it and tracks its use.
func (k *StageKeys) Sign(message []byte, index uint32) (xmssSig, ed25519Sig, falconSig []byte, err error) {
	if uint64(index) < k.lo || uint64(index) >= k.hi {
		return nil, nil, nil, fmt.Errorf("leaf %d is outside stage %d's range [%d, %d)", index, k.stage, k.lo, k.hi)
	}
	xmssSig, err = xmss.Sign(k.seeds, k.tree.Tree, index, message)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("sign with stage XMSS leaf: %w", err)
	}
	falconSig, err = k.falcon.Sign(message)
	if err != nil {
		crypto.ZeroBytes(xmssSig)
		return nil, nil, nil, fmt.Errorf("sign with stage Falcon key: %w", err)
	}
	return xmssSig, ed25519.Sign(k.ed25519, message), falconSig, nil
}

// Zero overwrites every private key.
func (k *StageKeys) Zero() {
	if k == nil {
		return
	}
	if k.seeds != nil {
		k.seeds.Zero()
	}
	crypto.ZeroBytes(k.ed25519)
	crypto.ZeroBytes(k.falcon.PrivateKey[:])
}

// Verify checks the three signatures against the constants embedded in a
// stage program, as the AVM program will, including the leaf range.
func Verify(keys *stage.PublicKeys, message, xmssSig, ed25519Sig, falconSig []byte) error {
	if keys == nil {
		return errors.New("stage public keys are nil")
	}
	if !ed25519.Verify(keys.Ed25519[:], message, ed25519Sig) {
		return errors.New("stage Ed25519 signature is invalid")
	}
	if len(falconSig) > stage.FalconSignatureMaxSize {
		return fmt.Errorf("stage Falcon signature is %d bytes, maximum is %d", len(falconSig), stage.FalconSignatureMaxSize)
	}
	if err := falcongo.Verify(message, falcon.CompressedSignature(falconSig), falcon.PublicKey(keys.Falcon)); err != nil {
		return fmt.Errorf("stage Falcon signature: %w", err)
	}
	index, err := xmss.Index(xmssSig)
	if err != nil {
		return fmt.Errorf("stage XMSS signature: %w", err)
	}
	if uint64(index) < keys.Lo || uint64(index) >= keys.Hi {
		return fmt.Errorf("stage XMSS signature uses leaf %d outside [%d, %d)", index, keys.Lo, keys.Hi)
	}
	pk := xmss.PublicKey{Root: keys.Root, Seed: keys.Seed}
	if err := xmss.Verify(&pk, message, xmssSig); err != nil {
		return fmt.Errorf("stage XMSS signature: %w", err)
	}
	return nil
}

// signOpenTest signs the open-test message with the stage's Ed25519 and
// Falcon keys only.
func (k *StageKeys) signOpenTest() (ed25519Sig, falconSig []byte, err error) {
	falconSig, err = k.falcon.Sign(openTestMessage)
	if err != nil {
		return nil, nil, fmt.Errorf("sign open test with stage Falcon key: %w", err)
	}
	return ed25519.Sign(k.ed25519, openTestMessage), falconSig, nil
}

// verifyOpenTest checks the open-test signatures against a program's keys.
func verifyOpenTest(keys *stage.PublicKeys, ed25519Sig, falconSig []byte) error {
	if !ed25519.Verify(keys.Ed25519[:], openTestMessage, ed25519Sig) {
		return errors.New("stage Ed25519 signature is invalid")
	}
	if err := falcongo.Verify(openTestMessage, falcon.CompressedSignature(falconSig), falcon.PublicKey(keys.Falcon)); err != nil {
		return fmt.Errorf("stage Falcon signature: %w", err)
	}
	return nil
}
