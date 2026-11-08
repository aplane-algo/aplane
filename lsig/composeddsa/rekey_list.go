// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package composeddsa

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/rekeylist"
)

// rekeyListProofSlot names the derived argument carrying a listed rekey's proof.
const rekeyListProofSlot = "rekey_list_proof"

func rekeyListEntriesParameterDef() lsigprovider.ParameterDef {
	return lsigprovider.ParameterDef{
		Name:        BoundedRekeyToParameter,
		Label:       "Rekey-To Addresses",
		Description: "Addresses the account may be rekeyed to with the spending key alone. Every other rekey is refused.",
		Type:        "address[]",
		Required:    true,
		MinItems:    1,
		MaxItems:    rekeylist.MaxEntries,
		NonZero:     true,
	}
}

func rekeyListProofArg() boundedmeta.DerivedArg {
	return boundedmeta.DerivedArg{
		Name:      rekeyListProofSlot,
		Kind:      boundedmeta.DerivedArgRekeyListProof,
		Parameter: BoundedRekeyToParameter,
		MaxSize:   boundedmeta.RekeyListProofSize,
	}
}

// RekeyListEntries parses a rekey-to list's entries from creation parameters.
func RekeyListEntries(params map[string]string) ([]types.Address, error) {
	if strings.TrimSpace(params[BoundedRekeyToParameter]) == "" {
		return nil, fmt.Errorf("%s is required", BoundedRekeyToParameter)
	}
	entries, err := rekeylist.ParseEntries(params[BoundedRekeyToParameter])
	if err != nil {
		return nil, fmt.Errorf("%s: %w", BoundedRekeyToParameter, err)
	}
	return entries, nil
}

// rekeyListRoot reads the root the generator added. A request can never carry
// it: it is not a creation parameter, so creation-parameter validation refuses
// it as unknown.
func rekeyListRoot(params map[string]string) ([]byte, error) {
	value, ok := params[boundedmeta.RekeyListRootParameter]
	if !ok {
		return nil, fmt.Errorf("the rekey-to list root is computed at key generation, and this program has none")
	}
	root, err := hex.DecodeString(value)
	if err != nil || len(root) != 32 {
		return nil, fmt.Errorf("%s must be 32 bytes of hex", boundedmeta.RekeyListRootParameter)
	}
	return root, nil
}

// splitRekeyListRoot separates the generator's root from the creation
// parameters, which are validated without it.
func splitRekeyListRoot(params map[string]string) (map[string]string, map[string]string) {
	value, ok := params[boundedmeta.RekeyListRootParameter]
	if !ok {
		return params, nil
	}
	rest := make(map[string]string, len(params))
	for name, v := range params {
		if name != boundedmeta.RekeyListRootParameter {
			rest[name] = v
		}
	}
	return rest, map[string]string{boundedmeta.RekeyListRootParameter: value}
}

// PrepareRekeyList returns params with the rekey-to list's root added. The
// root comes from the entries and a seed derived from the spending private
// key, so the generator calls this once the keypair exists and before it
// renders the program. A composer without a list returns params unchanged.
func (c *ComposedDSA) PrepareRekeyList(privateKey []byte, params map[string]string) (map[string]string, error) {
	if c.bounded == nil || c.bounded.RekeyList == nil {
		return params, nil
	}
	if _, present := params[boundedmeta.RekeyListRootParameter]; present {
		return nil, fmt.Errorf("%s is set by key generation, not by a request", boundedmeta.RekeyListRootParameter)
	}
	root, err := RekeyListRootFor(privateKey, params)
	if err != nil {
		return nil, err
	}
	prepared := make(map[string]string, len(params)+1)
	for name, value := range params {
		prepared[name] = value
	}
	prepared[boundedmeta.RekeyListRootParameter] = hex.EncodeToString(root[:])
	return prepared, nil
}

// RekeyListFor rebuilds an account's list from its spending private key and
// its stored entries. The caller zeroes the result.
func RekeyListFor(privateKey []byte, params map[string]string) (*rekeylist.List, error) {
	entries, err := RekeyListEntries(params)
	if err != nil {
		return nil, err
	}
	return rekeylist.FromSpendingKey(privateKey, entries)
}

// RekeyListRootFor computes the root an account's program commits to.
func RekeyListRootFor(privateKey []byte, params map[string]string) ([32]byte, error) {
	list, err := RekeyListFor(privateKey, params)
	if err != nil {
		return [32]byte{}, err
	}
	defer list.Zero()
	return list.Root(), nil
}

// renderListedRekey checks that a pure rekey's target is on the list: the
// proof's salt and the target make the leaf, each sibling is folded in as a
// sorted pair, and the result must equal the root compiled here.
func renderListedRekey(b *strings.Builder, proofIndex int, root []byte) {
	b.WriteString("// listed rekey: the target must be on the rekey-to list\n")
	b.WriteString(fmt.Sprintf("arg %d\nlen\npushint %d\n==\nassert\n", proofIndex, rekeylist.ProofSize))
	b.WriteString(fmt.Sprintf("pushbytes 0x%02x\narg %d\npushint 0\npushint 32\nextract3\nconcat\ntxn RekeyTo\nconcat\nsha256\n", rekeylist.LeafPrefix, proofIndex))
	for offset := 32; offset < rekeylist.ProofSize; offset += 32 {
		b.WriteString(fmt.Sprintf("arg %d\npushint %d\npushint 32\nextract3\ncallsub %s\n", proofIndex, offset, boundedRekeyListCombineLabel))
	}
	b.WriteString("pushbytes 0x" + hex.EncodeToString(root) + "\n==\nassert\n")
	b.WriteString("b " + boundedAcceptLabel + "\n\n")
	b.WriteString(boundedRekeyListCombineLabel + ":\ndup2\nb<\nbnz " + boundedRekeyListOrderedLabel + "\nswap\n" +
		boundedRekeyListOrderedLabel + ":\nconcat\npushbytes 0x01\nswap\nconcat\nsha256\nretsub\n\n")
}
