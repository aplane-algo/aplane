// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policycontext

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/asaset"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
)

const cosignerExportKey = "MYJZE3UF7G4JXR5STMQK5TSL5FNE7PE224BSKLZ2H4AJWJIPBEBQ"

// cosignerFollowerKey is a key that follows the node default: it has no
// document of its own, and may still have tokens.
const cosignerFollowerKey = "AAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYPQ"

var cosignerExportFixture = filepath.Join("..", "..", "test", "contracts", "policycontext", "v1", "node-context-cosigner.json")

func cosignerContext(t *testing.T) *Context {
	t.Helper()
	return sampleContext(t, func(_ *map[string]asaset.GenesisHash, _ *[]asaset.Asset, r *noderole.Role, _ *int) {
		*r = noderole.RoleCosigner
	})
}

// sampleCosignerExport is a cosigner export, with names recorded when names
// is not nil.
func sampleCosignerExport(t *testing.T, names map[string][]string) *Export {
	t.Helper()
	e, err := NewExport(cosignerContext(t), []policy.DocumentDigest{
		{Key: cosignerExportKey, SHA256: strings.Repeat("b", 64)},
		{Key: policy.DefaultKey, SHA256: strings.Repeat("a", 64)},
	}, time.Date(2026, 11, 1, 12, 30, 45, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if names != nil {
		if err := e.RecordSourceTokens(names); err != nil {
			t.Fatal(err)
		}
	}
	return e
}

// sampleTokenNames: the key with a document has tokens for screening and
// treasury, the follower, which has none, for ops, and the default for none.
var sampleTokenNames = map[string][]string{cosignerExportKey: {"treasury", "screening"}, cosignerFollowerKey: {"ops"}}

// The fixture pins the source_tokens field of a cosigner export.
func TestExportCosignerFixture(t *testing.T) {
	data, err := sampleCosignerExport(t, sampleTokenNames).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if *updateDigests {
		if err := os.WriteFile(cosignerExportFixture, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(cosignerExportFixture)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, want) {
		t.Fatalf("Marshal() differs from the fixture:\n%s", data)
	}
	got, err := ParseExport(want)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(got.SourceTokens) != fmt.Sprint(map[string][]string{cosignerExportKey: {"screening", "treasury"}, cosignerFollowerKey: {"ops"}}) {
		t.Fatalf("SourceTokens = %v", got.SourceTokens)
	}
	for selector, want := range map[string]string{cosignerFollowerKey: "[ops]", policy.DefaultKey: "[]"} {
		if names, known := got.SourceTokenNames(selector); !known || fmt.Sprint(names) != want {
			t.Fatalf("SourceTokenNames(%s) = %v, %v; want %s, known", selector, names, known, want)
		}
	}
	if again, _ := got.Marshal(); !bytes.Equal(again, want) {
		t.Fatal("a parsed export encodes differently")
	}
}

// Recorded names are beside the digests: an export with other names, or
// none, has the same context and snapshot digests, so a token set after the
// export does not make it stale.
func TestSourceTokensAreNotDigested(t *testing.T) {
	none := sampleCosignerExport(t, nil)
	some := sampleCosignerExport(t, sampleTokenNames)
	other := sampleCosignerExport(t, map[string][]string{policy.DefaultKey: {"ops"}})
	for _, e := range []*Export{some, other} {
		if e.Context.SHA256() != none.Context.SHA256() || e.Baseline.PolicySetSHA256 != none.Baseline.PolicySetSHA256 ||
			e.Baseline.SnapshotSHA256 != none.Baseline.SnapshotSHA256 {
			t.Fatalf("digests %+v differ from %+v", e.Baseline, none.Baseline)
		}
	}
	data, _ := none.Marshal()
	if strings.Contains(string(data), "source_tokens") {
		t.Fatalf("an export that recorded no names writes source_tokens:\n%s", data)
	}
	parsed, err := ParseExport(data)
	if err != nil || parsed.SourceTokens != nil {
		t.Fatalf("ParseExport() = %+v, %v; want no names recorded", parsed, err)
	}
	if _, known := parsed.SourceTokenNames(policy.DefaultKey); known {
		t.Fatal("an export that recorded no names claims to know the default's")
	}
	// Recording none is still recording: an empty list says no selector
	// has a token.
	empty := sampleCosignerExport(t, map[string][]string{policy.DefaultKey: {}})
	data, _ = empty.Marshal()
	if !strings.Contains(string(data), `"source_tokens": []`) {
		t.Fatalf("an export with no tokens set does not say so:\n%s", data)
	}
	if parsed, err := ParseExport(data); err != nil || parsed.SourceTokens == nil || len(parsed.SourceTokens) != 0 {
		t.Fatalf("ParseExport() = %+v, %v", parsed, err)
	} else if names, known := parsed.SourceTokenNames(cosignerExportKey); !known || len(names) != 0 {
		t.Fatalf("SourceTokenNames() = %v, %v; want none, known", names, known)
	}
}

func TestRecordSourceTokensRefusesWhatNoNodeHolds(t *testing.T) {
	signer := sampleExport(t)
	if err := signer.RecordSourceTokens(map[string][]string{}); err == nil {
		t.Fatal("a signer export recorded source token names")
	}
	long := strings.Repeat("s", 65)
	nine := []string{"a", "b", "c", "d", "e", "f", "g", "h", "i"}
	for name, names := range map[string]map[string][]string{
		"not a selector": {"CEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEI7JH2AYM": {"ops"}},
		"a bad name":     {policy.DefaultKey: {"Ops"}},
		"a long name":    {policy.DefaultKey: {long}},
		"a name twice":   {policy.DefaultKey: {"ops", "ops"}},
		"too many names": {policy.DefaultKey: nine},
	} {
		if err := sampleCosignerExport(t, nil).RecordSourceTokens(names); err == nil {
			t.Errorf("%s: RecordSourceTokens accepted %v", name, names)
		}
	}
}

func TestParseExportRefusesMalformedSourceTokens(t *testing.T) {
	data, err := sampleCosignerExport(t, sampleTokenNames).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	edit := func(change func(entries []any, f map[string]any)) []byte {
		var f map[string]any
		if err := json.Unmarshal(data, &f); err != nil {
			t.Fatal(err)
		}
		change(f["source_tokens"].([]any), f)
		out, err := json.Marshal(f)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	entry := func(entries []any, i int) map[string]any { return entries[i].(map[string]any) }
	signerData, _ := sampleExport(t).Marshal()
	var signer map[string]any
	_ = json.Unmarshal(signerData, &signer)
	signer["source_tokens"] = []any{}
	signerWithTokens, _ := json.Marshal(signer)

	for name, tc := range map[string]struct {
		data []byte
		want string
	}{
		"a signer export":  {signerWithTokens, "only a cosigner export"},
		"out of order":     {edit(func(e []any, f map[string]any) { f["source_tokens"] = []any{e[1], e[0]} }), "sorted by key"},
		"a key twice":      {edit(func(e []any, f map[string]any) { f["source_tokens"] = []any{e[0], e[0]} }), "each key once"},
		"no names":         {edit(func(e []any, _ map[string]any) { entry(e, 0)["sources"] = []any{} }), "no names"},
		"not a selector":   {edit(func(e []any, _ map[string]any) { entry(e, 1)["key"] = "ops" }), "source tokens"},
		"unsorted":         {edit(func(e []any, _ map[string]any) { entry(e, 0)["sources"] = []any{"treasury", "screening"} }), "sorted"},
		"listed twice":     {edit(func(e []any, _ map[string]any) { entry(e, 0)["sources"] = []any{"ops", "ops"} }), "listed once"},
		"a bad name":       {edit(func(e []any, _ map[string]any) { entry(e, 0)["sources"] = []any{"Ops"} }), "not a source name"},
		"no list":          {edit(func(e []any, _ map[string]any) { delete(entry(e, 0), "sources") }), "no sources list"},
		"an unknown field": {edit(func(e []any, _ map[string]any) { entry(e, 0)["token"] = "x" }), "unknown field"},
		"nine names": {edit(func(e []any, _ map[string]any) {
			entry(e, 0)["sources"] = []any{"a", "b", "c", "d", "e", "f", "g", "h", "i"}
		}), "at most 8"},
	} {
		_, err := ParseExport(tc.data)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: ParseExport() error = %v, want one naming %q", name, err, tc.want)
		}
	}
}

// A cosigner at every limit exports a context file well inside
// MaxExportBytes: the asset table of TestExportAtTheLimitsFitsTheBound, a
// document for every key the cap allows, and for each the most source names
// a token file holds, every name at its longest.
func TestCosignerExportAtTheLimitsFitsTheBound(t *testing.T) {
	var assets []asaset.Asset
	for i := uint64(1); i <= 5000; i++ {
		assets = append(assets, asaset.Asset{
			Identity: asaset.Identity{Genesis: asaset.GenesisHash{0xff, byte(i >> 8), byte(i)}, AssetID: i<<40 | i},
			Name:     strings.Repeat("n", asaset.MaxNameBytes), UnitName: strings.Repeat("u", asaset.MaxUnitNameBytes),
			Decimals: asaset.MaxDecimals, Origin: asaset.OriginOperator,
		})
	}
	table, err := asaset.NewTable(assets)
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := FromParts(noderole.RoleCosigner, map[string]asaset.GenesisHash{"mainnet": {1}}, table, AdmissionRulesVersion)
	if err != nil {
		t.Fatal(err)
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	docs := []policy.DocumentDigest{{Key: policy.DefaultKey, SHA256: strings.Repeat("a", 64)}}
	for i := 0; i < 8192; i++ {
		key := string([]byte{alphabet[i/1024%32], alphabet[i/32%32], alphabet[i%32]}) + strings.Repeat("A", 49)
		docs = append(docs, policy.DocumentDigest{Key: key, SHA256: strings.Repeat("b", 64)})
	}
	e, err := NewExport(ctx, docs, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	names := make(map[string][]string, len(docs))
	for _, doc := range docs {
		for j := 0; j < MaxSourceTokenNames; j++ {
			names[doc.Key] = append(names[doc.Key], fmt.Sprintf("%d", j)+strings.Repeat("s", 63))
		}
	}
	if err := e.RecordSourceTokens(names); err != nil {
		t.Fatal(err)
	}
	data, err := e.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > MaxExportBytes*3/4 {
		t.Fatalf("a context file at the limits is %d bytes, too near the %d bound", len(data), MaxExportBytes)
	}
	if _, err := ParseExport(data); err != nil {
		t.Fatal(err)
	}
}
