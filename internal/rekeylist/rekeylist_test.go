// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rekeylist

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/merkleallowlist"
)

func address(b byte) types.Address {
	var a types.Address
	a[0], a[31] = b, 1
	return a
}

func seedOf(b byte) []byte { return bytes.Repeat([]byte{b}, SeedSize) }

func mustList(t *testing.T, seed []byte, entries ...types.Address) *List {
	t.Helper()
	list, err := New(seed, entries)
	if err != nil {
		t.Fatal(err)
	}
	return list
}

// Reproduced by an independent encoder written from the algorithm in
// docs/ARCH_BOUNDED_DSA.md. A change here is a change to the list contract,
// and so to the address of every account with a list.
const (
	goldenRoot      = "4d250f6cd7cf1576f88827ac394e3e93f4e178230f90ea4c1beefa734eaba78c"
	goldenProofHash = "2b6dec15d0822cffecacf19aca00b29954546e3000e97da23f37ccab23e499f1"
)

func TestGoldenVector(t *testing.T) {
	list := mustList(t, seedOf(0x5a), address(3), address(1), address(2))
	root := list.Root()
	if got := hex.EncodeToString(root[:]); got != goldenRoot {
		t.Errorf("root = %s, want %s", got, goldenRoot)
	}
	proof, ok := list.Proof(address(2))
	if !ok {
		t.Fatal("no proof for a listed address")
	}
	sum := sha256.Sum256(proof)
	if got := hex.EncodeToString(sum[:]); got != goldenProofHash {
		t.Errorf("proof hash = %s, want %s (proof %x)", got, goldenProofHash, proof)
	}
}

func TestProofsVerifyOnlyForTheirEntry(t *testing.T) {
	entries := []types.Address{address(1), address(2), address(3)}
	list := mustList(t, seedOf(7), entries...)
	root := list.Root()
	for _, entry := range entries {
		proof, ok := list.Proof(entry)
		if !ok || len(proof) != ProofSize {
			t.Fatalf("proof for %s: %d bytes, %v", entry, len(proof), ok)
		}
		if !Verify(entry, proof, root) {
			t.Fatalf("the proof for %s does not verify", entry)
		}
		for _, other := range append(entries, address(9)) {
			if other != entry && Verify(other, proof, root) {
				t.Fatalf("the proof for %s verifies %s", entry, other)
			}
		}
		for i := range proof {
			tampered := bytes.Clone(proof)
			tampered[i] ^= 1
			if Verify(entry, tampered, root) {
				t.Fatalf("a proof with byte %d flipped verifies", i)
			}
		}
		if Verify(entry, proof[:ProofSize-1], root) || Verify(entry, append(bytes.Clone(proof), 0), root) {
			t.Fatal("a proof of the wrong length verifies")
		}
	}
	if _, ok := list.Proof(address(9)); ok || list.Contains(address(9)) {
		t.Fatal("an unlisted address has a proof")
	}
}

// O16: the root alone reveals nothing, even for one entry.
func TestRootHidesItsEntries(t *testing.T) {
	one := mustList(t, seedOf(1), address(1))
	unsalted, err := merkleallowlist.RootFromRecipientsParam(address(1).String())
	if err != nil {
		t.Fatal(err)
	}
	if one.Root() == unsalted {
		t.Fatal("a one-entry root equals the unsalted recipient root")
	}
	if mustList(t, seedOf(2), address(1)).Root() == one.Root() {
		t.Fatal("the same entry under a fresh seed gives the same root")
	}
	if mustList(t, seedOf(1), address(2), address(1)).Root() != mustList(t, seedOf(1), address(1), address(2)).Root() {
		t.Fatal("the root depends on the order the entries were given in")
	}
}

// O16: a proof doesn't show the list's size. Padding is pseudorandom, so no
// revealed sibling is a constant, and no two leaves are equal.
func TestProofsDoNotRevealTheListSize(t *testing.T) {
	list := mustList(t, seedOf(3), address(1))
	proof, _ := list.Proof(address(1))
	emptyRecipientLeaf := sha256.Sum256([]byte{0x00})
	seen := map[[sha256.Size]byte]bool{}
	for _, leaf := range list.levels[0] {
		if leaf == emptyRecipientLeaf || seen[leaf] {
			t.Fatal("a leaf is a constant or repeats")
		}
		seen[leaf] = true
	}
	for offset := sha256.Size; offset < ProofSize; offset += sha256.Size {
		var sibling [sha256.Size]byte
		copy(sibling[:], proof[offset:])
		if sibling == emptyRecipientLeaf || sibling == ([sha256.Size]byte{}) {
			t.Fatal("a revealed sibling is a constant")
		}
	}
	full := make([]types.Address, MaxEntries)
	for i := range full {
		full[i] = address(byte(i + 1))
	}
	fullList := mustList(t, seedOf(3), full...)
	for _, entry := range full {
		if proof, ok := fullList.Proof(entry); !ok || !Verify(entry, proof, fullList.Root()) {
			t.Fatalf("a full list's proof for %s does not verify", entry)
		}
	}
}

func TestNewRefusesBadInput(t *testing.T) {
	tooMany := make([]types.Address, MaxEntries+1)
	for i := range tooMany {
		tooMany[i] = address(byte(i + 1))
	}
	for name, test := range map[string]struct {
		seed    []byte
		entries []types.Address
		want    string
	}{
		"short seed": {seedOf(1)[:31], []types.Address{address(1)}, "seed must be 32 bytes"},
		"no entries": {seedOf(1), nil, "at least one address"},
		"too many":   {seedOf(1), tooMany, "at most 16 addresses"},
		"zero":       {seedOf(1), []types.Address{{}}, "zero address"},
		"repeat":     {seedOf(1), []types.Address{address(1), address(1)}, "repeats"},
	} {
		if _, err := New(test.seed, test.entries); err == nil || !strings.Contains(err.Error(), test.want) {
			t.Errorf("%s: error = %v, want %q", name, err, test.want)
		}
	}
}

func TestZeroClearsTheSeed(t *testing.T) {
	list := mustList(t, seedOf(4), address(1))
	list.Zero()
	if list.seed != ([SeedSize]byte{}) || list.levels != nil {
		t.Fatal("Zero left the seed or the tree")
	}
}
