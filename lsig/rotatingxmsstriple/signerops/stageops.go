// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerops

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/crypto/rotatinghybrid"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/lsig/rotatingxmsstriple/stage"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// openTestMessage is the fixed 32-byte message CheckStageOpens signs with a
// target stage's Ed25519 and Falcon keys: the hash of a label, not a
// transaction ID, so a signature over it cannot authorize anything. The XMSS
// half of the check is a constant comparison; no leaf is signed with.
var openTestMessage = func() []byte {
	sum := sha256.Sum256([]byte("APLANE_ROTATING_XMSS_V1 stage open test"))
	return sum[:]
}()

// treeKey names one tree of one account on one network.
type treeKey struct {
	tag     [AccountTagSize]byte
	genesis [rotatinghybrid.GenesisHashSize]byte
	tree    uint64
}

// StageOps implements signing.RotatingStageOps for
// aplane.rotating-xmss-triple.v1. Unlike the triple's, it has state: a cache
// of public trees, because a tree takes seconds to build and serves 1,024
// stages. The cache holds public nodes only; every secret is derived from
// the key material per call and zeroed before returning. Generation of one
// tree is serialized so concurrent callers share the result.
type StageOps struct {
	mu       sync.Mutex
	trees    map[treeKey]*PublicTree
	building map[treeKey]*sync.Mutex
}

var _ signing.RotatingStageOps = (*StageOps)(nil)

// NewStageOps returns stage cryptography with an empty tree cache.
func NewStageOps() *StageOps {
	return &StageOps{trees: make(map[treeKey]*PublicTree), building: make(map[treeKey]*sync.Mutex)}
}

// StageAddress derives stage i and returns its program address.
func (o *StageOps) StageAddress(key *signing.RotatingKeyMaterial, i uint64) (types.Address, error) {
	keys, program, err := o.deriveFromMaterial(key, i)
	if err != nil {
		return types.Address{}, err
	}
	keys.Zero()
	return program.Address, nil
}

// CheckStageOpens proves stage i's derived keys match the constants embedded
// in its program: it test-signs with the stage's Ed25519 and Falcon keys and
// verifies against the program, and checks the program's root, seed and
// range against the cached tree. It never signs with an XMSS leaf, so a
// target stage keeps every leaf for spends.
func (o *StageOps) CheckStageOpens(key *signing.RotatingKeyMaterial, i uint64) error {
	keys, program, err := o.deriveFromMaterial(key, i)
	if err != nil {
		return err
	}
	defer keys.Zero()
	embedded, _, err := stage.Parse(program.Bytecode)
	if err != nil {
		return fmt.Errorf("parse stage %d program: %w", i, err)
	}
	if embedded.Root != keys.tree.PK.Root || embedded.Seed != keys.tree.PK.Seed || embedded.Lo != keys.lo || embedded.Hi != keys.hi {
		return fmt.Errorf("stage %d program does not embed its tree", i)
	}
	edSig, falconSig, err := keys.signOpenTest()
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(falconSig)
	if err := verifyOpenTest(embedded, edSig, falconSig); err != nil {
		return fmt.Errorf("stage %d open test: %w", i, err)
	}
	return nil
}

// SignStage signs message with stage i's leaf index and returns the program
// with [xmss_sig, ed25519_sig, falcon_sig] as its arguments. The caller
// chooses the leaf inside the stage's range and records its use.
func (o *StageOps) SignStage(key *signing.RotatingKeyMaterial, i uint64, index uint32, message []byte) (signing.RotatingStageSignature, error) {
	keys, program, err := o.deriveFromMaterial(key, i)
	if err != nil {
		return signing.RotatingStageSignature{}, err
	}
	defer keys.Zero()
	xmssSig, edSig, falconSig, err := keys.Sign(message, index)
	if err != nil {
		return signing.RotatingStageSignature{}, fmt.Errorf("sign with stage %d: %w", i, err)
	}
	args := [][]byte{xmssSig, edSig, falconSig}
	embedded, _, err := stage.Parse(program.Bytecode)
	if err != nil {
		zeroArgs(args)
		return signing.RotatingStageSignature{}, fmt.Errorf("parse stage %d program: %w", i, err)
	}
	if err := Verify(embedded, message, xmssSig, edSig, falconSig); err != nil {
		zeroArgs(args)
		return signing.RotatingStageSignature{}, fmt.Errorf("stage %d signature does not verify: %w", i, err)
	}
	return signing.RotatingStageSignature{Program: program.Bytecode, Args: args}, nil
}

// Prepare builds and caches the tree that serves stage i, so a later
// StageAddress, CheckStageOpens or SignStage for that run does not block on
// generation. It is the hook for background root generation.
func (o *StageOps) Prepare(key *signing.RotatingKeyMaterial, i uint64) error {
	d, tag, err := deriverFor(key)
	if err != nil {
		return err
	}
	defer d.Zero()
	treeNo, _, _ := stage.RangeFor(i)
	_, err = o.tree(d, tag, treeNo)
	return err
}

// CachedTrees reports how many trees the cache holds, for status and tests.
func (o *StageOps) CachedTrees() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.trees)
}

// Forget drops every cached tree of the account with key, for example when
// the key is deleted. Dropping a tree costs its regeneration, nothing else.
func (o *StageOps) Forget(key *signing.RotatingKeyMaterial) error {
	d, tag, err := deriverFor(key)
	if err != nil {
		return err
	}
	d.Zero()
	genesis := d.GenesisHash()
	o.mu.Lock()
	defer o.mu.Unlock()
	for k := range o.trees {
		if k.tag == tag && k.genesis == genesis {
			delete(o.trees, k)
		}
	}
	return nil
}

// tree returns the cached public tree n of the account, generating it on
// first use. Concurrent requests for the same tree wait for one generation.
func (o *StageOps) tree(d *rotatinghybrid.Deriver, tag [AccountTagSize]byte, n uint64) (*PublicTree, error) {
	k := treeKey{tag: tag, genesis: d.GenesisHash(), tree: n}
	o.mu.Lock()
	if t, ok := o.trees[k]; ok {
		o.mu.Unlock()
		return t, nil
	}
	gate, ok := o.building[k]
	if !ok {
		gate = &sync.Mutex{}
		o.building[k] = gate
	}
	o.mu.Unlock()

	gate.Lock()
	defer gate.Unlock()
	o.mu.Lock()
	if t, ok := o.trees[k]; ok {
		o.mu.Unlock()
		return t, nil
	}
	o.mu.Unlock()
	t, err := GenerateTree(d, n)
	if err != nil {
		return nil, fmt.Errorf("generate tree %d: %w", n, err)
	}
	o.mu.Lock()
	o.trees[k] = t
	delete(o.building, k)
	o.mu.Unlock()
	return t, nil
}

func (o *StageOps) deriveFromMaterial(key *signing.RotatingKeyMaterial, i uint64) (*StageKeys, stage.Program, error) {
	d, tag, err := deriverFor(key)
	if err != nil {
		return nil, stage.Program{}, err
	}
	defer d.Zero()
	treeNo, _, _ := stage.RangeFor(i)
	t, err := o.tree(d, tag, treeNo)
	if err != nil {
		return nil, stage.Program{}, err
	}
	return DeriveStage(d, i, t)
}

// deriverFor opens the key material's deriver and account tag. The caller
// must Zero the deriver.
func deriverFor(key *signing.RotatingKeyMaterial) (*rotatinghybrid.Deriver, [AccountTagSize]byte, error) {
	var tag [AccountTagSize]byte
	if key == nil {
		return nil, tag, errors.New("rotating key material is nil")
	}
	var seed rotatinghybrid.Seed
	var genesisHash [rotatinghybrid.GenesisHashSize]byte
	if len(key.Seed) != len(seed) || len(key.GenesisHash) != len(genesisHash) {
		return nil, tag, errors.New("rotating key material has the wrong size")
	}
	copy(seed[:], key.Seed)
	defer seed.Zero()
	copy(genesisHash[:], key.GenesisHash)
	d, err := NewDeriver(&seed, genesisHash)
	if err != nil {
		return nil, tag, err
	}
	tag, err = AccountTag(d)
	if err != nil {
		d.Zero()
		return nil, tag, err
	}
	return d, tag, nil
}

// zeroArgs overwrites every argument buffer.
func zeroArgs(args [][]byte) {
	for _, a := range args {
		crypto.ZeroBytes(a)
	}
}

// Derive derives stage i with the cached tree of its run, generating the
// tree on first use. It is StageOps' counterpart of DeriveStage for callers
// that already hold a deriver, such as key generation and validation.
func (o *StageOps) Derive(d *rotatinghybrid.Deriver, i uint64) (*StageKeys, stage.Program, error) {
	tag, err := AccountTag(d)
	if err != nil {
		return nil, stage.Program{}, err
	}
	treeNo, _, _ := stage.RangeFor(i)
	t, err := o.tree(d, tag, treeNo)
	if err != nil {
		return nil, stage.Program{}, err
	}
	return DeriveStage(d, i, t)
}

// CachedTree returns tree n of the deriver's account if the cache holds
// it, without generating it.
func (o *StageOps) CachedTree(d *rotatinghybrid.Deriver, n uint64) (*PublicTree, bool) {
	tag, err := AccountTag(d)
	if err != nil {
		return nil, false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	t, ok := o.trees[treeKey{tag: tag, genesis: d.GenesisHash(), tree: n}]
	return t, ok
}
