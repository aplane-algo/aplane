// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package rekeylist is the hiding Merkle tree behind a bounded account's
// rekey-to list (O16 in the account-overlays design). It differs from the
// recipient trees in internal/merkleallowlist, which make no privacy claim:
// each leaf carries a secret salt, and unused leaves are random, so the root
// reveals nothing about the list, even when it holds one address, and a proof
// reveals only the entry it proves.
//
// Salts and padding derive from one per-account secret seed, so the account
// stores the seed and the entries and nothing else. The seed and the entries
// stay with the signer: never in the program, never on the client wire.
package rekeylist

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

const (
	// Depth is the tree's fixed depth, a constant of the list contract.
	Depth = 4
	// MaxEntries is the most addresses one list holds.
	MaxEntries = 1 << Depth
	// SeedSize is the per-account secret's size.
	SeedSize = 32
	// ProofSize is a proof's exact size: the entry's salt, then one sibling per level.
	ProofSize = sha256.Size * (1 + Depth)

	// LeafPrefix separates these leaves from the recipient tree's (0x00).
	LeafPrefix byte = 0x02
	// NodePrefix is the sorted-pair node prefix the recipient trees use.
	NodePrefix byte = 0x01

	saltLabel    = "APLANE_REKEY_LIST_SALT_V1"
	paddingLabel = "APLANE_REKEY_LIST_PAD_V1"
	seedLabel    = "APLANE_REKEY_LIST_SEED_V1"
)

// List is one account's rekey-to list: its entries in canonical order and the
// seed their salts and the padding derive from. Zero it when done.
type List struct {
	seed    [SeedSize]byte
	entries []types.Address
	levels  [][][sha256.Size]byte
}

// SeedFromSpendingKey derives an account's list seed from its spending private
// key, so the seed is in every backup the key is in and is never stored or sent
// on its own. The list's privacy then rests on the spending key staying secret.
// The key's bytes, as the key file stores them, are part of the list contract: a
// payload format that re-encodes the private key must keep handing over the same
// bytes, or every existing account's root stops matching.
func SeedFromSpendingKey(privateKey []byte) ([SeedSize]byte, error) {
	var seed [SeedSize]byte
	if len(privateKey) == 0 {
		return seed, fmt.Errorf("rekey list seed needs the spending private key")
	}
	mac := hmac.New(sha256.New, privateKey)
	mac.Write([]byte(seedLabel))
	mac.Sum(seed[:0])
	return seed, nil
}

// ParseEntries reads a comma-separated list of addresses, as an account's
// creation parameters store it, and returns it in canonical order.
func ParseEntries(value string) ([]types.Address, error) {
	if strings.TrimSpace(value) == "" {
		return nil, fmt.Errorf("a rekey-to list needs at least one address")
	}
	var entries []types.Address
	for _, item := range strings.Split(value, ",") {
		address, err := types.DecodeAddress(strings.TrimSpace(item))
		if err != nil {
			return nil, fmt.Errorf("invalid address %q: %w", item, err)
		}
		entries = append(entries, address)
	}
	return Canonical(entries)
}

// FromSpendingKey rebuilds an account's list from its spending private key and
// its entries. The caller zeroes the result.
func FromSpendingKey(privateKey []byte, entries []types.Address) (*List, error) {
	seed, err := SeedFromSpendingKey(privateKey)
	if err != nil {
		return nil, err
	}
	defer func() {
		for i := range seed {
			seed[i] = 0
		}
	}()
	return New(seed[:], entries)
}

// New builds the tree for entries under seed. Entries must be distinct,
// nonzero, and at most MaxEntries; their order doesn't matter.
func New(seed []byte, entries []types.Address) (*List, error) {
	if len(seed) != SeedSize {
		return nil, fmt.Errorf("rekey list seed must be %d bytes, got %d", SeedSize, len(seed))
	}
	canonical, err := Canonical(entries)
	if err != nil {
		return nil, err
	}
	list := &List{entries: canonical}
	copy(list.seed[:], seed)

	leaves := make([][sha256.Size]byte, MaxEntries)
	for i := range leaves {
		if i < len(canonical) {
			leaves[i] = leaf(list.salt(i), canonical[i])
		} else {
			leaves[i] = list.derive(paddingLabel, i)
		}
	}
	list.levels = [][][sha256.Size]byte{leaves}
	for level := leaves; len(level) > 1; {
		next := make([][sha256.Size]byte, len(level)/2)
		for i := range next {
			next[i] = node(level[2*i], level[2*i+1])
		}
		list.levels = append(list.levels, next)
		level = next
	}
	return list, nil
}

// Canonical checks entries and returns them sorted by address bytes.
func Canonical(entries []types.Address) ([]types.Address, error) {
	if len(entries) == 0 {
		return nil, fmt.Errorf("a rekey-to list needs at least one address")
	}
	if len(entries) > MaxEntries {
		return nil, fmt.Errorf("a rekey-to list holds at most %d addresses, got %d", MaxEntries, len(entries))
	}
	canonical := append([]types.Address(nil), entries...)
	sort.Slice(canonical, func(i, j int) bool { return bytes.Compare(canonical[i][:], canonical[j][:]) < 0 })
	for i, address := range canonical {
		if address.IsZero() {
			return nil, fmt.Errorf("a rekey-to list must not contain the zero address")
		}
		if i > 0 && address == canonical[i-1] {
			return nil, fmt.Errorf("the rekey-to list repeats %s", address)
		}
	}
	return canonical, nil
}

// Root is the commitment compiled into the account's program.
func (l *List) Root() [sha256.Size]byte {
	return l.levels[Depth][0]
}

// Contains reports whether address is on the list.
func (l *List) Contains(address types.Address) bool {
	_, ok := l.index(address)
	return ok
}

// Proof returns the proof for address: its salt, then one sibling per level.
// The second result is false when address is not on the list.
func (l *List) Proof(address types.Address) ([]byte, bool) {
	i, ok := l.index(address)
	if !ok {
		return nil, false
	}
	salt := l.salt(i)
	proof := make([]byte, 0, ProofSize)
	proof = append(proof, salt[:]...)
	clear(salt[:])
	for level := 0; level < Depth; level++ {
		sibling := l.levels[level][i^1]
		proof = append(proof, sibling[:]...)
		i /= 2
	}
	return proof, true
}

// Zero clears the seed and the derived tree.
func (l *List) Zero() {
	if l == nil {
		return
	}
	for i := range l.seed {
		l.seed[i] = 0
	}
	for _, level := range l.levels {
		for i := range level {
			level[i] = [sha256.Size]byte{}
		}
	}
	l.levels = nil
}

// Verify checks a proof the way the program does: the salt and the address
// make the leaf, each sibling is folded in as a sorted pair, and the result
// must equal root.
func Verify(address types.Address, proof []byte, root [sha256.Size]byte) bool {
	if len(proof) != ProofSize {
		return false
	}
	var salt [sha256.Size]byte
	copy(salt[:], proof[:sha256.Size])
	hash := leaf(salt, address)
	for offset := sha256.Size; offset < ProofSize; offset += sha256.Size {
		var sibling [sha256.Size]byte
		copy(sibling[:], proof[offset:offset+sha256.Size])
		hash = node(hash, sibling)
	}
	return hmac.Equal(hash[:], root[:])
}

func (l *List) index(address types.Address) (int, bool) {
	i := sort.Search(len(l.entries), func(i int) bool { return bytes.Compare(l.entries[i][:], address[:]) >= 0 })
	return i, i < len(l.entries) && l.entries[i] == address
}

func (l *List) salt(i int) [sha256.Size]byte {
	return l.derive(saltLabel, i)
}

// derive is HMAC-SHA256 keyed by the seed over a label and a leaf index, so
// salts and padding are independent pseudorandom values one seed reproduces.
func (l *List) derive(label string, i int) [sha256.Size]byte {
	mac := hmac.New(sha256.New, l.seed[:])
	mac.Write([]byte(label))
	mac.Write(binary.BigEndian.AppendUint32(nil, uint32(i)))
	var out [sha256.Size]byte
	mac.Sum(out[:0])
	return out
}

func leaf(salt [sha256.Size]byte, address types.Address) [sha256.Size]byte {
	data := make([]byte, 0, 1+2*sha256.Size)
	data = append(data, LeafPrefix)
	data = append(data, salt[:]...)
	data = append(data, address[:]...)
	sum := sha256.Sum256(data)
	clear(data)
	return sum
}

func node(a, b [sha256.Size]byte) [sha256.Size]byte {
	lo, hi := a[:], b[:]
	if bytes.Compare(lo, hi) > 0 {
		lo, hi = hi, lo
	}
	data := make([]byte, 0, 1+2*sha256.Size)
	data = append(data, NodePrefix)
	data = append(data, lo...)
	data = append(data, hi...)
	return sha256.Sum256(data)
}
