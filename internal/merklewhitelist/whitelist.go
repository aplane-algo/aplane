// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package merklewhitelist

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

const (
	Depth     = 16
	ProofSize = Depth * sha256.Size
	MaxItems  = 1 << Depth
)

func RootHexFromRecipientsParam(recipients string) (string, error) {
	root, err := RootFromRecipientsParam(recipients)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(root[:]), nil
}

func RootFromRecipientsParam(recipients string) ([sha256.Size]byte, error) {
	entries, err := canonicalEntries(recipients)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	root, _, err := build(entries, "")
	return root, err
}

func ProofForAddressParam(recipients string, address types.Address) ([]byte, error) {
	entries, err := canonicalEntries(recipients)
	if err != nil {
		return nil, err
	}
	_, proof, err := build(entries, address.String())
	if err != nil {
		return nil, err
	}
	if proof == nil {
		return nil, fmt.Errorf("address %s is not in whitelist", address.String())
	}
	return proof, nil
}

func Verify(address types.Address, proof []byte, root [sha256.Size]byte) bool {
	if len(proof) != ProofSize {
		return false
	}
	hash := leaf(address)
	for offset := 0; offset < len(proof); offset += sha256.Size {
		var sibling [sha256.Size]byte
		copy(sibling[:], proof[offset:offset+sha256.Size])
		hash = node(hash, sibling)
	}
	return bytes.Equal(hash[:], root[:])
}

type entry struct {
	address string
	pubkey  types.Address
	leaf    [sha256.Size]byte
}

func canonicalEntries(recipients string) ([]entry, error) {
	parts := strings.Split(recipients, ",")
	entries := make([]entry, 0, len(parts))
	seen := make(map[types.Address]struct{}, len(parts))
	for _, part := range parts {
		item := strings.TrimSpace(part)
		if item == "" {
			return nil, fmt.Errorf("recipients contains an empty address")
		}
		addr, err := types.DecodeAddress(item)
		if err != nil {
			return nil, fmt.Errorf("invalid whitelist address %q: %w", item, err)
		}
		if _, ok := seen[addr]; ok {
			return nil, fmt.Errorf("duplicate whitelist address public key: %s", addr.String())
		}
		seen[addr] = struct{}{}
		entries = append(entries, entry{
			address: addr.String(),
			pubkey:  addr,
			leaf:    leaf(addr),
		})
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("recipients must contain at least one address")
	}
	if len(entries) > MaxItems {
		return nil, fmt.Errorf("recipients contains %d addresses, maximum is %d", len(entries), MaxItems)
	}
	sort.Slice(entries, func(i, j int) bool {
		return bytes.Compare(entries[i].pubkey[:], entries[j].pubkey[:]) < 0
	})
	return entries, nil
}

func build(entries []entry, proofAddress string) ([sha256.Size]byte, []byte, error) {
	leafCount := 1 << Depth
	empty := emptyLeaf()
	level := make([][sha256.Size]byte, leafCount)
	for i := range level {
		level[i] = empty
	}

	indices := make(map[string]int, len(entries))
	for i, e := range entries {
		level[i] = e.leaf
		indices[e.address] = i
	}

	wantProof := strings.TrimSpace(proofAddress)
	proofIndex, proofWanted := indices[wantProof]
	if wantProof != "" && !proofWanted {
		return [sha256.Size]byte{}, nil, nil
	}
	proof := make([]byte, 0, ProofSize)

	for depth := 0; depth < Depth; depth++ {
		if proofWanted {
			proof = append(proof, level[proofIndex^1][:]...)
			proofIndex /= 2
		}

		next := make([][sha256.Size]byte, len(level)/2)
		for i := range next {
			next[i] = node(level[i*2], level[i*2+1])
		}
		level = next
	}

	if proofWanted && len(proof) != ProofSize {
		return [sha256.Size]byte{}, nil, fmt.Errorf("internal proof length %d, want %d", len(proof), ProofSize)
	}
	return level[0], proof, nil
}

func leaf(addr types.Address) [sha256.Size]byte {
	data := make([]byte, 0, 1+len(addr))
	data = append(data, 0x00)
	data = append(data, addr[:]...)
	return sha256.Sum256(data)
}

func emptyLeaf() [sha256.Size]byte {
	return sha256.Sum256([]byte{0x00})
}

func node(left, right [sha256.Size]byte) [sha256.Size]byte {
	first, second := left[:], right[:]
	if bytes.Compare(first, second) > 0 {
		first, second = second, first
	}
	data := make([]byte, 0, 1+sha256.Size*2)
	data = append(data, 0x01)
	data = append(data, first...)
	data = append(data, second...)
	return sha256.Sum256(data)
}
