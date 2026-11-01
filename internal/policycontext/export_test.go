// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policycontext

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/asaset"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
)

const exportKey = "CEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEI7JH2AYM"

var exportFixture = filepath.Join("..", "..", "test", "contracts", "policycontext", "v1", "node-context.json")

func sampleExport(t *testing.T) *Export {
	t.Helper()
	e, err := NewExport(sampleContext(t, nil), []policy.DocumentDigest{
		{Key: exportKey, SHA256: strings.Repeat("b", 64)},
		{Key: policy.DefaultKey, SHA256: strings.Repeat("a", 64)},
	}, time.Date(2026, 11, 1, 12, 30, 45, 999, time.FixedZone("x", 3600)))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// The fixture pins the file format: a later release must still read it, and
// must write the same bytes for the same export.
func TestExportFixture(t *testing.T) {
	data, err := sampleExport(t).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if *updateDigests {
		if err := os.WriteFile(exportFixture, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(exportFixture)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, want) {
		t.Fatalf("Marshal() differs from the fixture:\n%s", data)
	}
}

func TestExportRoundTrips(t *testing.T) {
	e := sampleExport(t)
	data, err := e.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseExport(data)
	if err != nil {
		t.Fatal(err)
	}
	if !got.ExportedAt.Equal(time.Date(2026, 11, 1, 11, 30, 45, 0, time.UTC)) {
		t.Fatalf("ExportedAt = %v, want the export's whole second in UTC", got.ExportedAt)
	}
	if got.Context.SHA256() != e.Context.SHA256() || got.Context.Role() != e.Context.Role() {
		t.Fatal("the context did not survive the round trip")
	}
	if got.Baseline.PolicySetSHA256 != e.Baseline.PolicySetSHA256 || got.Baseline.SnapshotSHA256 != e.Baseline.SnapshotSHA256 ||
		len(got.Baseline.Documents) != 2 || got.Baseline.Documents[0].Key != exportKey {
		t.Fatalf("baseline = %+v, want %+v", got.Baseline, e.Baseline)
	}
	if again, _ := got.Marshal(); !bytes.Equal(again, data) {
		t.Fatal("a parsed export encodes differently")
	}
}

func TestNewExportComputesTheBaselineDigests(t *testing.T) {
	e := sampleExport(t)
	stored := []policy.StoredDocument{{Key: policy.DefaultKey, Bytes: []byte("{}")}}
	digests := []policy.DocumentDigest{{Key: policy.DefaultKey, SHA256: stored[0].SHA256()}}
	if policy.PolicySetSHA256OfDigests(digests) != policy.PolicySetSHA256(stored) {
		t.Fatal("the manifest digest differs from the stored-document digest")
	}
	if e.Baseline.SnapshotSHA256 != SnapshotSHA256(e.Context.SHA256(), e.Baseline.PolicySetSHA256) {
		t.Fatal("the baseline snapshot is not the context's with the policy set")
	}
}

func TestNewExportRefusesAManifestNoNodeHolds(t *testing.T) {
	ctx := sampleContext(t, nil)
	good := strings.Repeat("a", 64)
	for name, docs := range map[string][]policy.DocumentDigest{
		"no default":     {{Key: exportKey, SHA256: good}},
		"a key twice":    {{Key: policy.DefaultKey, SHA256: good}, {Key: exportKey, SHA256: good}, {Key: exportKey, SHA256: good}},
		"a bad key":      {{Key: policy.DefaultKey, SHA256: good}, {Key: "not-an-address", SHA256: good}},
		"a bad digest":   {{Key: policy.DefaultKey, SHA256: strings.Repeat("A", 64)}},
		"a short digest": {{Key: policy.DefaultKey, SHA256: "abc"}},
	} {
		if _, err := NewExport(ctx, docs, time.Now()); err == nil {
			t.Errorf("%s: NewExport accepted the manifest", name)
		}
	}
}

// Every field that carries meaning is checked: a damaged or hand-edited file
// is refused rather than read as some other context.
func TestParseExportRefusesWhatItCannotTrust(t *testing.T) {
	data, err := sampleExport(t).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	edit := func(change func(f map[string]any)) []byte {
		var f map[string]any
		if err := json.Unmarshal(data, &f); err != nil {
			t.Fatal(err)
		}
		change(f)
		out, err := json.Marshal(f)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	networks := func(f map[string]any) []any { return f["networks"].([]any) }
	asset := func(f map[string]any, i int) map[string]any { return f["assets"].([]any)[i].(map[string]any) }
	baseline := func(f map[string]any) map[string]any { return f["baseline"].(map[string]any) }

	for name, tc := range map[string]struct {
		data []byte
		want string
	}{
		"another format":      {edit(func(f map[string]any) { f["format"] = "aplane.policy-node-context.v2" }), "format"},
		"newer rules":         {edit(func(f map[string]any) { f["rules_version"] = 2 }), "rules version 2"},
		"an unknown field":    {edit(func(f map[string]any) { f["extra"] = true }), "unknown field"},
		"data after it":       {append(append([]byte(nil), data...), []byte("{}")...), "data after"},
		"no time":             {edit(func(f map[string]any) { f["exported_at"] = "" }), "exported_at"},
		"an unknown role":     {edit(func(f map[string]any) { f["role"] = "observer" }), "role"},
		"decimals edited":     {edit(func(f map[string]any) { asset(f, 1)["decimals"] = 6 }), "context_sha256"},
		"a token renamed":     {edit(func(f map[string]any) { networks(f)[0].(map[string]any)["network"] = "mainnet2" }), "context_sha256"},
		"a token twice":       {edit(func(f map[string]any) { f["networks"] = append(networks(f), networks(f)[0]) }), "listed twice"},
		"a bad genesis hash":  {edit(func(f map[string]any) { networks(f)[0].(map[string]any)["genesis_hash"] = "AQ==" }), "network"},
		"an unknown origin":   {edit(func(f map[string]any) { asset(f, 0)["origin"] = "guess" }), "origin"},
		"too many decimals":   {edit(func(f map[string]any) { asset(f, 0)["decimals"] = 20 }), "decimals"},
		"a document removed":  {edit(func(f map[string]any) { baseline(f)["documents"] = baseline(f)["documents"].([]any)[1:] }), "policy_set_sha256"},
		"the default removed": {edit(func(f map[string]any) { baseline(f)["documents"] = baseline(f)["documents"].([]any)[:1] }), "no default"},
		"a document's digest": {edit(func(f map[string]any) {
			baseline(f)["documents"].([]any)[0].(map[string]any)["sha256"] = strings.Repeat("c", 64)
		}), "policy_set_sha256"},
		"the snapshot": {edit(func(f map[string]any) { baseline(f)["snapshot_sha256"] = strings.Repeat("0", 64) }), "snapshot_sha256"},
		"too large":    {append(append([]byte(nil), data...), bytes.Repeat([]byte(" "), MaxExportBytes)...), "more than"},
		"not JSON":     {[]byte("format: x"), "context file"},
	} {
		_, err := ParseExport(tc.data)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: ParseExport() error = %v, want one naming %q", name, err, tc.want)
		}
	}
}

// Two tokens naming one chain would make an asset reference ambiguous.
func TestParseExportRefusesTwoTokensForOneChain(t *testing.T) {
	data, err := sampleExport(t).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var f map[string]any
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	first := f["networks"].([]any)[0].(map[string]any)
	f["networks"] = append(f["networks"].([]any), map[string]any{"network": "zzz", "genesis_hash": first["genesis_hash"]})
	out, _ := json.Marshal(f)
	if _, err := ParseExport(out); err == nil || !strings.Contains(err.Error(), "same chain") {
		t.Fatalf("ParseExport() error = %v, want the shared chain refused", err)
	}
}

// A node at its limits exports a context file well inside MaxExportBytes:
// more assets than a 1 MiB set file holds, every name at its longest, and
// a document for every key the cap allows.
func TestExportAtTheLimitsFitsTheBound(t *testing.T) {
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
	ctx, err := FromParts(noderole.RoleSigner, map[string]asaset.GenesisHash{"mainnet": {1}}, table, AdmissionRulesVersion)
	if err != nil {
		t.Fatal(err)
	}
	docs := []policy.DocumentDigest{{Key: policy.DefaultKey, SHA256: strings.Repeat("a", 64)}}
	for i := 0; i < 8192; i++ {
		docs = append(docs, policy.DocumentDigest{Key: types.Address{byte(i >> 8), byte(i), 1}.String(), SHA256: strings.Repeat("b", 64)})
	}
	e, err := NewExport(ctx, docs, time.Now())
	if err != nil {
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
