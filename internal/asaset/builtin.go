// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package asaset

import (
	"sort"

	asaregistry "github.com/aplane-algo/aplane/internal/asa/registry"
	apconfig "github.com/aplane-algo/aplane/internal/config"
)

// Origin says where an asset's metadata comes from.
type Origin string

const (
	// OriginBuiltin is the table shipped with the binary.
	OriginBuiltin Origin = "builtin"
	// OriginOperator is a confirmation the node's operator recorded.
	OriginOperator Origin = "operator"
)

// Asset is one asset of the effective table: what is known about it and
// where that comes from.
type Asset struct {
	Identity
	Name     string
	UnitName string
	Decimals uint64
	Origin   Origin
}

// Builtins projects the built-in table onto chain identity. The built-in
// network tokens are reserved and cannot be remapped, so each one names a
// fixed genesis hash.
func Builtins() []Asset {
	var out []Asset
	for hash, network := range apconfig.BuiltinGenesisHashNetworks() {
		genesis, err := ParseGenesisHash(hash)
		if err != nil {
			// The built-in hashes are constants in canonical form.
			panic("asaset: built-in genesis hash " + hash + ": " + err.Error())
		}
		for id, info := range asaregistry.AllBuiltinMetadata(network) {
			out = append(out, Asset{
				Identity: Identity{Genesis: genesis, AssetID: id},
				Name:     info.Name,
				UnitName: info.UnitName,
				Decimals: info.Decimals,
				Origin:   OriginBuiltin,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].less(out[j].Identity) })
	return out
}

func builtinIdentities() map[Identity]bool {
	out := map[Identity]bool{}
	for _, a := range Builtins() {
		out[a.Identity] = true
	}
	return out
}

// Table is the effective ASA set: the built-ins and the operator's
// confirmations, sorted by chain and ID. A Table is immutable.
type Table struct {
	assets []Asset
	byID   map[Identity]int
}

// Effective is the built-in table plus s.
func Effective(s *Set) *Table {
	assets := Builtins()
	for _, e := range s.entries {
		assets = append(assets, Asset{Identity: e.Identity, Name: e.Name, UnitName: e.UnitName, Decimals: e.Decimals, Origin: OriginOperator})
	}
	return newTable(assets)
}

func newTable(assets []Asset) *Table {
	sort.Slice(assets, func(i, j int) bool { return assets[i].less(assets[j].Identity) })
	t := &Table{assets: assets, byID: make(map[Identity]int, len(assets))}
	for i, a := range assets {
		t.byID[a.Identity] = i
	}
	return t
}

// Assets returns every asset of the table, sorted by chain and ID.
func (t *Table) Assets() []Asset { return append([]Asset(nil), t.assets...) }

// Lookup returns what the table knows about id.
func (t *Table) Lookup(id Identity) (Asset, bool) {
	i, ok := t.byID[id]
	if !ok {
		return Asset{}, false
	}
	return t.assets[i], true
}
