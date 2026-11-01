// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package asaset

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/types"

	apconfig "github.com/aplane-algo/aplane/internal/config"
)

var (
	chainA = GenesisHash{0x0a}
	chainB = GenesisHash{0x0b}
	when   = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
)

func entry(chain GenesisHash, id uint64) Entry {
	return Entry{
		Identity:              Identity{Genesis: chain, AssetID: id},
		Name:                  "Example token",
		UnitName:              "XYZ",
		Decimals:              6,
		Creator:               types.Address{7}.String(),
		ConfirmedAt:           when,
		NetworkAtConfirmation: "private-dev",
	}
}

func mainnet(t *testing.T) GenesisHash {
	t.Helper()
	g, err := ParseGenesisHash(apconfig.AlgorandMainnetGenesisHash)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestSetRoundTripsInCanonicalForm(t *testing.T) {
	// Given out of order, with a non-UTC time carrying sub-second precision.
	late := entry(chainB, 5)
	late.ConfirmedAt = when.In(time.FixedZone("x", 3600)).Add(500 * time.Millisecond)
	s, err := New([]Entry{late, entry(chainA, 9), entry(chainA, 2)})
	if err != nil {
		t.Fatal(err)
	}
	data, err := s.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse(Marshal()) error = %v\n%s", err, data)
	}
	got := parsed.Entries()
	if len(got) != 3 || got[0].AssetID != 2 || got[1].AssetID != 9 || got[2].Genesis != chainB {
		t.Fatalf("entries not sorted by chain then ID: %+v", got)
	}
	if !got[2].ConfirmedAt.Equal(when) || got[2].ConfirmedAt.Location() != time.UTC {
		t.Fatalf("confirmed_at = %v, want %v in UTC to the second", got[2].ConfirmedAt, when)
	}
	again, err := parsed.Marshal()
	if err != nil || string(again) != string(data) {
		t.Fatalf("re-marshal differs:\n%s\n%s", data, again)
	}
}

func TestTheSameIDOnTwoChainsIsTwoAssets(t *testing.T) {
	s, err := New([]Entry{entry(chainA, 7), entry(chainB, 7)})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	a, okA := s.Lookup(Identity{Genesis: chainA, AssetID: 7})
	b, okB := s.Lookup(Identity{Genesis: chainB, AssetID: 7})
	if !okA || !okB || a.Genesis == b.Genesis {
		t.Fatalf("lookups = %+v %v, %+v %v", a, okA, b, okB)
	}
	if _, ok := s.Lookup(Identity{Genesis: GenesisHash{0x0c}, AssetID: 7}); ok {
		t.Fatal("an unconfirmed chain found the asset")
	}
}

func TestNewRefusesBadEntries(t *testing.T) {
	for name, mutate := range map[string]func(*Entry){
		"no chain":           func(e *Entry) { e.Genesis = GenesisHash{} },
		"zero asset":         func(e *Entry) { e.AssetID = 0 },
		"too many decimals":  func(e *Entry) { e.Decimals = MaxDecimals + 1 },
		"long name":          func(e *Entry) { e.Name = strings.Repeat("n", MaxNameBytes+1) },
		"long unit":          func(e *Entry) { e.UnitName = "TOOLONGUN" },
		"invalid UTF-8 name": func(e *Entry) { e.Name = "\xff" },
		"bad creator":        func(e *Entry) { e.Creator = "nope" },
		"no confirmation":    func(e *Entry) { e.ConfirmedAt = time.Time{} },
		"bad network token":  func(e *Entry) { e.NetworkAtConfirmation = "Not A Token" },
	} {
		e := entry(chainA, 1)
		mutate(&e)
		if _, err := New([]Entry{e}); err == nil {
			t.Errorf("%s: New() succeeded", name)
		}
	}
	if _, err := New([]Entry{entry(chainA, 1), entry(chainA, 1)}); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Errorf("duplicate: New() error = %v", err)
	}
	// The limits themselves are accepted.
	e := entry(chainA, 1)
	e.Decimals, e.Name, e.UnitName = MaxDecimals, strings.Repeat("n", MaxNameBytes), "EIGHTCHR"
	if _, err := New([]Entry{e}); err != nil {
		t.Errorf("at the limits: New() error = %v", err)
	}
}

func TestWithAndWithout(t *testing.T) {
	s := Empty()
	s1, err := s.With(entry(chainA, 1))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Entries()) != 0 {
		t.Fatal("With changed the original set")
	}
	if _, err := s1.With(entry(chainA, 1)); err == nil {
		t.Fatal("With accepted a second confirmation of the same asset")
	}
	s2, found := s1.Without(Identity{Genesis: chainA, AssetID: 1})
	if !found || len(s2.Entries()) != 0 || len(s1.Entries()) != 1 {
		t.Fatalf("Without: found %v, entries %d / %d", found, len(s2.Entries()), len(s1.Entries()))
	}
	if _, found := s2.Without(Identity{Genesis: chainA, AssetID: 1}); found {
		t.Fatal("Without found a removed asset")
	}
}

func TestEffectiveTableHoldsBuiltinsAndConfirmations(t *testing.T) {
	s, err := New([]Entry{entry(chainA, 5)})
	if err != nil {
		t.Fatal(err)
	}
	table := Effective(s)
	usdc, ok := table.Lookup(Identity{Genesis: mainnet(t), AssetID: 31566704})
	if !ok || usdc.Origin != OriginBuiltin || usdc.UnitName != "USDC" || usdc.Decimals != 6 {
		t.Fatalf("built-in USDC = %+v, %v", usdc, ok)
	}
	mine, ok := table.Lookup(Identity{Genesis: chainA, AssetID: 5})
	if !ok || mine.Origin != OriginOperator || mine.UnitName != "XYZ" {
		t.Fatalf("operator entry = %+v, %v", mine, ok)
	}
	// Mainnet's USDC ID on another chain is not USDC.
	if _, ok := table.Lookup(Identity{Genesis: chainA, AssetID: 31566704}); ok {
		t.Fatal("a built-in ID was found on another chain")
	}
	if got := len(table.Assets()); got != len(Builtins())+1 {
		t.Fatalf("table has %d assets, want %d", got, len(Builtins())+1)
	}
}

func TestParseGenesisHashIsCanonical(t *testing.T) {
	if _, err := ParseGenesisHash(apconfig.AlgorandTestnetGenesisHash); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "AAAA", strings.Repeat("A", 43) + "B", "48:63:b5:18"} {
		if _, err := ParseGenesisHash(bad); err == nil {
			t.Errorf("ParseGenesisHash(%q) succeeded", bad)
		}
	}
}

// The contract fixtures pin the file format: every valid one parses and is
// canonical; every invalid one is refused.
func TestSetFileFixtures(t *testing.T) {
	dir := filepath.Join("..", "..", "test", "contracts", "asaset", "v1")
	valid, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	invalid, _ := filepath.Glob(filepath.Join(dir, "invalid", "*.json"))
	if len(valid) == 0 || len(invalid) == 0 {
		t.Fatalf("fixtures missing: %d valid, %d invalid", len(valid), len(invalid))
	}
	for _, path := range valid {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Parse(data); err != nil {
			t.Errorf("%s: %v", filepath.Base(path), err)
		}
	}
	for _, path := range invalid {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Parse(data); err == nil {
			t.Errorf("invalid/%s: parsed", filepath.Base(path))
		}
	}
}

// A release can add an asset the operator already confirmed to the built-in
// table. The stored set must still load, the built-in entry must win, and
// only a new confirmation of a built-in is refused.
func TestAConfirmationLaterBuiltInStillLoads(t *testing.T) {
	stored := entry(mainnet(t), 31566704)
	stored.UnitName, stored.Decimals = "OLD", 2 // differs from the built-in USDC
	s, err := New([]Entry{stored})
	if err != nil {
		t.Fatalf("New() with a confirmation that is now built in: %v", err)
	}
	data, err := s.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(data); err != nil {
		t.Fatalf("Parse() of a stored set overlapping the built-ins: %v", err)
	}
	usdc, ok := Effective(s).Lookup(stored.Identity)
	if !ok || usdc.Origin != OriginBuiltin || usdc.UnitName != "USDC" || usdc.Decimals != 6 {
		t.Fatalf("effective entry = %+v, %v; want the built-in USDC", usdc, ok)
	}
	if got := len(Effective(s).Assets()); got != len(Builtins()) {
		t.Fatalf("effective table has %d assets, want %d: the overlap must not duplicate", got, len(Builtins()))
	}
	if _, err := Empty().With(stored); err == nil {
		t.Fatal("With() accepted a new confirmation of a built-in asset")
	}
	// The shadowed confirmation can still be removed.
	if without, found := s.Without(stored.Identity); !found || len(without.Entries()) != 0 {
		t.Fatalf("Without() = %+v, %v", without.Entries(), found)
	}
}
