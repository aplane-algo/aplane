// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package asaset

import (
	"fmt"
	"sort"
	"unicode/utf8"

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

// NewTable is a table of exactly assets, such as one an export carries. It
// refuses a duplicate identity, an unknown origin, and values outside
// Algorand's limits.
func NewTable(assets []Asset) (*Table, error) {
	seen := make(map[Identity]bool, len(assets))
	for _, a := range assets {
		switch {
		case seen[a.Identity]:
			return nil, fmt.Errorf("%s appears twice", a.Identity)
		case a.Genesis == (GenesisHash{}) || a.AssetID == 0:
			return nil, fmt.Errorf("%s: an asset needs a chain and a positive ID", a.Identity)
		case a.Origin != OriginBuiltin && a.Origin != OriginOperator:
			return nil, fmt.Errorf("%s: unknown origin %q", a.Identity, a.Origin)
		case a.Decimals > MaxDecimals:
			return nil, fmt.Errorf("%s: decimals %d exceed %d", a.Identity, a.Decimals, MaxDecimals)
		case !utf8.ValidString(a.Name) || len(a.Name) > MaxNameBytes:
			return nil, fmt.Errorf("%s: name must be valid UTF-8 of at most %d bytes", a.Identity, MaxNameBytes)
		case !utf8.ValidString(a.UnitName) || len(a.UnitName) > MaxUnitNameBytes:
			return nil, fmt.Errorf("%s: unit name must be valid UTF-8 of at most %d bytes", a.Identity, MaxUnitNameBytes)
		}
		seen[a.Identity] = true
	}
	return newTable(append([]Asset(nil), assets...)), nil
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
