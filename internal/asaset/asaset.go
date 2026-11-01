// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package asaset is a node's ASA set: the built-in asset table plus the
// assets its operator confirmed. An asset is identified by the chain it lives
// on (its genesis hash) and its ID; a network token is only a local name that
// resolves to a genesis hash. The set supplies labels and decimal precision
// for display and decides which specific assets submitted policy documents
// may name. It never decides what a transaction may do.
//
// This package is pure: it parses, validates and encodes the set file, and
// projects the built-in table onto chain identity. Reading and writing the
// file in a generation belongs to the store adapters.
package asaset

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"
	"unicode/utf8"

	"github.com/algorand/go-algorand-sdk/v2/types"

	apconfig "github.com/aplane-algo/aplane/internal/config"
)

// Format is the set file's format.
const Format = "aplane.asa-set.v1"

// Algorand's limits on an asset's parameters.
const (
	MaxDecimals      = 19
	MaxUnitNameBytes = 8
	MaxNameBytes     = 32
)

// GenesisHash is a chain's 32-byte genesis hash.
type GenesisHash [32]byte

// String is the hash's canonical standard base64 form.
func (g GenesisHash) String() string { return base64.StdEncoding.EncodeToString(g[:]) }

// ParseGenesisHash parses the canonical standard base64 form of a genesis
// hash. Any other encoding is refused, so equal hashes have equal text.
func ParseGenesisHash(text string) (GenesisHash, error) {
	raw, err := base64.StdEncoding.DecodeString(text)
	if err != nil || len(raw) != len(GenesisHash{}) {
		return GenesisHash{}, fmt.Errorf("genesis hash %q is not the base64 of 32 bytes", text)
	}
	var g GenesisHash
	copy(g[:], raw)
	if g.String() != text {
		return GenesisHash{}, fmt.Errorf("genesis hash %q is not in canonical base64", text)
	}
	return g, nil
}

// Identity is an asset: its chain and its ID. The same ID on another chain
// is another asset, or none.
type Identity struct {
	Genesis GenesisHash
	AssetID uint64
}

func (i Identity) String() string { return fmt.Sprintf("asset %d on %s", i.AssetID, i.Genesis) }

func (i Identity) less(j Identity) bool {
	if c := bytes.Compare(i.Genesis[:], j.Genesis[:]); c != 0 {
		return c < 0
	}
	return i.AssetID < j.AssetID
}

// Entry is one operator confirmation. Only the asset's fixed parameters are
// kept: its name, unit name and decimals cannot change after creation, while
// its manager, reserve, freeze and clawback addresses can, so those are
// observations at confirmation time and are not stored.
type Entry struct {
	Identity
	Name        string
	UnitName    string
	Decimals    uint64
	Creator     string
	ConfirmedAt time.Time
	// NetworkAtConfirmation is the token the operator named. It is
	// diagnostic: a token may later name another chain.
	NetworkAtConfirmation string
}

func (e Entry) validate() error {
	switch {
	case e.Genesis == (GenesisHash{}):
		return errors.New("genesis hash is required")
	case e.AssetID == 0:
		return errors.New("asset ID must be positive")
	case e.Decimals > MaxDecimals:
		return fmt.Errorf("decimals %d exceed %d", e.Decimals, MaxDecimals)
	case !utf8.ValidString(e.Name) || len(e.Name) > MaxNameBytes:
		return fmt.Errorf("name must be valid UTF-8 of at most %d bytes", MaxNameBytes)
	case !utf8.ValidString(e.UnitName) || len(e.UnitName) > MaxUnitNameBytes:
		return fmt.Errorf("unit name must be valid UTF-8 of at most %d bytes", MaxUnitNameBytes)
	case e.ConfirmedAt.IsZero():
		return errors.New("confirmation time is required")
	}
	if _, err := types.DecodeAddress(e.Creator); err != nil {
		return fmt.Errorf("creator %q is not an Algorand address", e.Creator)
	}
	if err := apconfig.ValidateNetworkID(e.NetworkAtConfirmation); err != nil {
		return fmt.Errorf("network at confirmation: %w", err)
	}
	return nil
}

// Set is a node's operator confirmations, sorted by chain and ID. A Set is
// immutable; With and Without return new ones.
type Set struct {
	entries []Entry
}

// Empty is the set of a node with no confirmations: the built-ins only.
func Empty() *Set { return &Set{} }

// New validates entries and returns them as a set. Duplicate identities and
// entries for built-in assets are refused.
func New(entries []Entry) (*Set, error) {
	builtins := builtinIdentities()
	sorted := append([]Entry(nil), entries...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].less(sorted[j].Identity) })
	for i, e := range sorted {
		if err := e.validate(); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Identity, err)
		}
		if builtins[e.Identity] {
			return nil, fmt.Errorf("%s is built in and cannot be confirmed again", e.Identity)
		}
		if i > 0 && sorted[i-1].Identity == e.Identity {
			return nil, fmt.Errorf("%s is confirmed twice", e.Identity)
		}
		e.ConfirmedAt = e.ConfirmedAt.UTC().Truncate(time.Second)
		sorted[i] = e
	}
	return &Set{entries: sorted}, nil
}

// Entries returns the confirmations, sorted by chain and ID.
func (s *Set) Entries() []Entry { return append([]Entry(nil), s.entries...) }

// Lookup returns the confirmation for id.
func (s *Set) Lookup(id Identity) (Entry, bool) {
	i := sort.Search(len(s.entries), func(i int) bool { return !s.entries[i].less(id) })
	if i < len(s.entries) && s.entries[i].Identity == id {
		return s.entries[i], true
	}
	return Entry{}, false
}

// With returns the set with e added.
func (s *Set) With(e Entry) (*Set, error) { return New(append(s.Entries(), e)) }

// Without returns the set without id, and whether it held it.
func (s *Set) Without(id Identity) (*Set, bool) {
	out := make([]Entry, 0, len(s.entries))
	found := false
	for _, e := range s.entries {
		if e.Identity == id {
			found = true
			continue
		}
		out = append(out, e)
	}
	return &Set{entries: out}, found
}

// fileV1 is the set file. Its field order is the canonical member order.
type fileV1 struct {
	Format string        `json:"format"`
	Assets []fileEntryV1 `json:"assets"`
}

type fileEntryV1 struct {
	GenesisHash           string `json:"genesis_hash"`
	AssetID               uint64 `json:"asset_id"`
	Name                  string `json:"name"`
	UnitName              string `json:"unit_name"`
	Decimals              uint64 `json:"decimals"`
	Creator               string `json:"creator"`
	ConfirmedAt           string `json:"confirmed_at"`
	NetworkAtConfirmation string `json:"network_at_confirmation"`
}

// Marshal returns the set file's canonical bytes: two-space indented JSON,
// members in a fixed order, entries sorted by chain and ID, times in UTC to
// the second, and a trailing newline.
func (s *Set) Marshal() ([]byte, error) {
	f := fileV1{Format: Format, Assets: make([]fileEntryV1, 0, len(s.entries))}
	for _, e := range s.entries {
		f.Assets = append(f.Assets, fileEntryV1{
			GenesisHash:           e.Genesis.String(),
			AssetID:               e.AssetID,
			Name:                  e.Name,
			UnitName:              e.UnitName,
			Decimals:              e.Decimals,
			Creator:               e.Creator,
			ConfirmedAt:           e.ConfirmedAt.UTC().Format(time.RFC3339),
			NetworkAtConfirmation: e.NetworkAtConfirmation,
		})
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(f); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// Parse reads a set file. It refuses unknown members, content after the
// object, another format, and any invalid entry, and it requires the
// canonical form, so a stored file has one byte representation.
func Parse(data []byte) (*Set, error) {
	var f fileV1
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("asa set: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("asa set: unexpected content after the set")
	}
	if f.Format != Format {
		return nil, fmt.Errorf("asa set: format is %q, want %q", f.Format, Format)
	}
	if f.Assets == nil {
		return nil, errors.New(`asa set: "assets" is required`)
	}
	entries := make([]Entry, 0, len(f.Assets))
	for i, fe := range f.Assets {
		genesis, err := ParseGenesisHash(fe.GenesisHash)
		if err != nil {
			return nil, fmt.Errorf("asa set: asset %d: %w", i+1, err)
		}
		confirmed, err := time.Parse(time.RFC3339, fe.ConfirmedAt)
		if err != nil || confirmed.Location() != time.UTC {
			return nil, fmt.Errorf("asa set: asset %d: confirmed_at %q is not an RFC 3339 UTC time", i+1, fe.ConfirmedAt)
		}
		entries = append(entries, Entry{
			Identity:              Identity{Genesis: genesis, AssetID: fe.AssetID},
			Name:                  fe.Name,
			UnitName:              fe.UnitName,
			Decimals:              fe.Decimals,
			Creator:               fe.Creator,
			ConfirmedAt:           confirmed,
			NetworkAtConfirmation: fe.NetworkAtConfirmation,
		})
	}
	s, err := New(entries)
	if err != nil {
		return nil, fmt.Errorf("asa set: %w", err)
	}
	canonical, err := s.Marshal()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, data) {
		return nil, errors.New("asa set: the file is not in canonical form")
	}
	return s, nil
}
