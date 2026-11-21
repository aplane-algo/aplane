// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policycontext

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"regexp"
	"slices"
	"sort"
	"time"

	"github.com/aplane-algo/aplane/internal/asaset"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
)

// ExportFormat is the format of the context file an export writes beside the
// policy documents it exported.
const ExportFormat = "aplane.policy-node-context.v1"

// MaxExportBytes bounds a context file. Its asset table is bounded by the
// ASA set file (1 MiB of confirmations), its manifest by the node's document
// cap (8,192 keys and the default), and its source token names by
// MaxSourceTokenSelectors and MaxSourceTokenNames, so even at every limit a
// file is well under this.
const MaxExportBytes = 16 << 20

// MaxSourceTokenNames is the most source names an export records for one
// selector: a selector's token file holds at most 8 tokens.
const MaxSourceTokenNames = 8

// MaxSourceTokenSelectors is the most selectors an export records token
// names for: a cosigner holds at most 8,192 keys (keys.MaxCosignerCredentials),
// each a selector, and the node default is one more.
const MaxSourceTokenSelectors = 8192 + 1

// Export is a node's policy context as exported with its documents: when it
// was taken, the context, and the baseline, the documents the node held then.
// Editing the exported documents does not change the baseline; it is what an
// apply compares the edited documents against.
type Export struct {
	ExportedAt time.Time
	Context    *Context
	Baseline   Baseline
	// SourceTokens names, for every selector of a cosigner that had a token
	// at export, whether or not it had a document of its own, the sources
	// it had one for, sorted. A selector it does not list had none. It is
	// nil when the export recorded no names (a signer, or a cosigner whose
	// tokens the export could not read), and then nothing is known of
	// tokens; use SourceTokenNames. The names sit beside the context and the
	// baseline and are in neither digest: a token is not policy, so one set
	// after the export does not make the export stale.
	SourceTokens map[string][]string
}

// Baseline is the node's policy documents at export, by digest, with the
// policy set digest and the composite snapshot they had with the context.
type Baseline struct {
	// Documents is sorted by key.
	Documents       []policy.DocumentDigest
	PolicySetSHA256 string
	SnapshotSHA256  string
}

// NewExport is the export of ctx with a node's documents, taken at at. It
// computes the baseline's digests, and refuses a manifest the node could not
// hold: a key the role does not name, a key listed twice, or no default.
func NewExport(ctx *Context, docs []policy.DocumentDigest, at time.Time) (*Export, error) {
	if ctx == nil {
		return nil, errors.New("an export needs a context")
	}
	if at.IsZero() {
		return nil, errors.New("an export needs its time")
	}
	baseline, err := newBaseline(ctx, docs)
	if err != nil {
		return nil, err
	}
	// The file records whole seconds.
	return &Export{ExportedAt: at.UTC().Truncate(time.Second), Context: ctx, Baseline: baseline}, nil
}

// RecordSourceTokens records names, the source names every selector with a
// token has a token for, by selector: the whole of a cosigner's tokens, so a
// selector it does not list is recorded as having none. A selector listed
// with no names is left out. Only a cosigner export records them, and each
// selector must be one a cosigner document can be keyed by, with at most
// MaxSourceTokenNames valid source names.
func (e *Export) RecordSourceTokens(names map[string][]string) error {
	if e.Context.Role() != noderole.RoleCosigner {
		return fmt.Errorf("only a cosigner export records source token names, not a %s one", e.Context.Role())
	}
	recorded := make(map[string][]string, len(names))
	for selector, list := range names {
		if len(list) == 0 {
			continue
		}
		if err := policy.ValidateDocumentKey(e.Context.Role(), selector); err != nil {
			return fmt.Errorf("source tokens: %w", err)
		}
		sorted := append([]string(nil), list...)
		sort.Strings(sorted)
		if err := validateSourceTokenNames(selector, sorted); err != nil {
			return err
		}
		recorded[selector] = sorted
	}
	if len(recorded) > MaxSourceTokenSelectors {
		return fmt.Errorf("source tokens: %d selectors, at most %d", len(recorded), MaxSourceTokenSelectors)
	}
	e.SourceTokens = recorded
	return nil
}

// SourceTokenNames returns the source names selector had a token for at the
// export, and known: false when the export recorded no names, so nothing is
// known of the selector's tokens. A selector the recorded names do not list
// had none, known.
func (e *Export) SourceTokenNames(selector string) (names []string, known bool) {
	if e == nil || e.SourceTokens == nil {
		return nil, false
	}
	return e.SourceTokens[selector], true
}

// validateSourceTokenNames checks one selector's recorded names: 1 to
// MaxSourceTokenNames valid source names, sorted and distinct.
func validateSourceTokenNames(key string, names []string) error {
	if len(names) == 0 {
		return fmt.Errorf("source tokens of %s: no names; a selector without tokens is not listed", key)
	}
	if len(names) > MaxSourceTokenNames {
		return fmt.Errorf("source tokens of %s: %d names, at most %d", key, len(names), MaxSourceTokenNames)
	}
	for i, name := range names {
		if !policy.IsExternalSourceName(name) {
			return fmt.Errorf("source tokens of %s: %q is not a source name", key, name)
		}
		if i > 0 && names[i-1] >= name {
			return fmt.Errorf("source tokens of %s must be sorted and listed once", key)
		}
	}
	return nil
}

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

func newBaseline(ctx *Context, docs []policy.DocumentDigest) (Baseline, error) {
	sorted := append([]policy.DocumentDigest(nil), docs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Key < sorted[j].Key })
	hasDefault := false
	for i, doc := range sorted {
		if err := policy.ValidateDocumentKey(ctx.Role(), doc.Key); err != nil {
			return Baseline{}, fmt.Errorf("baseline document: %w", err)
		}
		if i > 0 && sorted[i-1].Key == doc.Key {
			return Baseline{}, fmt.Errorf("baseline lists %s twice", doc.Key)
		}
		if !sha256Hex.MatchString(doc.SHA256) {
			return Baseline{}, fmt.Errorf("baseline document %s: digest must be 64 lowercase hex digits", doc.Key)
		}
		hasDefault = hasDefault || doc.Key == policy.DefaultKey
	}
	if !hasDefault {
		return Baseline{}, fmt.Errorf("baseline has no %s document; every node has one", policy.DefaultKey)
	}
	set := policy.PolicySetSHA256OfDigests(sorted)
	return Baseline{Documents: sorted, PolicySetSHA256: set, SnapshotSHA256: SnapshotSHA256(ctx.SHA256(), set)}, nil
}

type exportFileV1 struct {
	Format        string          `json:"format"`
	ExportedAt    string          `json:"exported_at"`
	Role          string          `json:"role"`
	RulesVersion  int             `json:"rules_version"`
	Networks      []exportNetwork `json:"networks"`
	Assets        []exportAsset   `json:"assets"`
	ContextSHA256 string          `json:"context_sha256"`
	Baseline      exportBaseline  `json:"baseline"`
	// SourceTokens is absent when the export recorded no names, else it has
	// one entry per selector that had a token, sorted by key: possibly none,
	// written as an empty list.
	SourceTokens *[]exportSourceTokens `json:"source_tokens,omitempty"`
}

type exportSourceTokens struct {
	Key     string   `json:"key"`
	Sources []string `json:"sources"`
}

type exportNetwork struct {
	Network     string `json:"network"`
	GenesisHash string `json:"genesis_hash"`
}

type exportAsset struct {
	GenesisHash string `json:"genesis_hash"`
	AssetID     uint64 `json:"asset_id"`
	Name        string `json:"name"`
	UnitName    string `json:"unit_name"`
	Decimals    uint64 `json:"decimals"`
	Origin      string `json:"origin"`
}

type exportBaseline struct {
	Documents       []exportDocument `json:"documents"`
	PolicySetSHA256 string           `json:"policy_set_sha256"`
	SnapshotSHA256  string           `json:"snapshot_sha256"`
}

type exportDocument struct {
	Key    string `json:"key"`
	SHA256 string `json:"sha256"`
}

// Marshal encodes the export as indented JSON, networks sorted by token and
// assets by chain and ID, so equal exports encode alike.
func (e *Export) Marshal() ([]byte, error) {
	f := exportFileV1{
		Format:        ExportFormat,
		ExportedAt:    e.ExportedAt.UTC().Format(time.RFC3339),
		Role:          string(e.Context.Role()),
		RulesVersion:  e.Context.RulesVersion(),
		Networks:      []exportNetwork{},
		Assets:        []exportAsset{},
		ContextSHA256: e.Context.SHA256(),
		Baseline: exportBaseline{
			Documents:       []exportDocument{},
			PolicySetSHA256: e.Baseline.PolicySetSHA256,
			SnapshotSHA256:  e.Baseline.SnapshotSHA256,
		},
	}
	for token, genesis := range e.Context.Networks() {
		f.Networks = append(f.Networks, exportNetwork{Network: token, GenesisHash: genesis.String()})
	}
	sort.Slice(f.Networks, func(i, j int) bool { return f.Networks[i].Network < f.Networks[j].Network })
	for _, a := range e.Context.Assets().Assets() {
		f.Assets = append(f.Assets, exportAsset{
			GenesisHash: a.Genesis.String(), AssetID: a.AssetID,
			Name: a.Name, UnitName: a.UnitName, Decimals: a.Decimals, Origin: string(a.Origin),
		})
	}
	for _, doc := range e.Baseline.Documents {
		f.Baseline.Documents = append(f.Baseline.Documents, exportDocument{Key: doc.Key, SHA256: doc.SHA256})
	}
	if e.SourceTokens != nil {
		entries := make([]exportSourceTokens, 0, len(e.SourceTokens))
		for _, key := range slices.Sorted(maps.Keys(e.SourceTokens)) {
			entries = append(entries, exportSourceTokens{Key: key, Sources: append([]string{}, e.SourceTokens[key]...)})
		}
		f.SourceTokens = &entries
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// ParseExport decodes a context file. It accepts only a file it can trust as
// a whole: the known format and rules version, no unknown fields, valid
// networks and assets, and digests that match what it recomputes from the
// file's own contents. A context file is an offline copy, not an authority;
// the digests only catch a damaged or hand-edited file.
func ParseExport(data []byte) (*Export, error) {
	if len(data) > MaxExportBytes {
		return nil, fmt.Errorf("context file is %d bytes, more than %d", len(data), MaxExportBytes)
	}
	var f exportFileV1
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("context file: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("context file: data after the context")
	}
	if f.Format != ExportFormat {
		return nil, fmt.Errorf("context file format %q is not %s", f.Format, ExportFormat)
	}
	if f.RulesVersion != AdmissionRulesVersion {
		return nil, fmt.Errorf("context file uses admission rules version %d; this release supports %d", f.RulesVersion, AdmissionRulesVersion)
	}
	at, err := time.Parse(time.RFC3339, f.ExportedAt)
	if err != nil {
		return nil, fmt.Errorf("context file exported_at: %w", err)
	}

	networks := make(map[string]asaset.GenesisHash, len(f.Networks))
	chains := make(map[asaset.GenesisHash]string, len(f.Networks))
	for _, n := range f.Networks {
		genesis, err := asaset.ParseGenesisHash(n.GenesisHash)
		if err != nil {
			return nil, fmt.Errorf("network %q: %w", n.Network, err)
		}
		if _, dup := networks[n.Network]; dup {
			return nil, fmt.Errorf("network %q is listed twice", n.Network)
		}
		if other, dup := chains[genesis]; dup {
			return nil, fmt.Errorf("networks %q and %q name the same chain", other, n.Network)
		}
		networks[n.Network], chains[genesis] = genesis, n.Network
	}
	assets := make([]asaset.Asset, 0, len(f.Assets))
	for _, a := range f.Assets {
		genesis, err := asaset.ParseGenesisHash(a.GenesisHash)
		if err != nil {
			return nil, fmt.Errorf("asset %d: %w", a.AssetID, err)
		}
		assets = append(assets, asaset.Asset{
			Identity: asaset.Identity{Genesis: genesis, AssetID: a.AssetID},
			Name:     a.Name, UnitName: a.UnitName, Decimals: a.Decimals, Origin: asaset.Origin(a.Origin),
		})
	}
	table, err := asaset.NewTable(assets)
	if err != nil {
		return nil, fmt.Errorf("context file assets: %w", err)
	}
	ctx, err := FromParts(noderole.Role(f.Role), networks, table, f.RulesVersion)
	if err != nil {
		return nil, fmt.Errorf("context file: %w", err)
	}
	if got := ctx.SHA256(); got != f.ContextSHA256 {
		return nil, errors.New("context file's context_sha256 does not match its networks and assets")
	}

	docs := make([]policy.DocumentDigest, 0, len(f.Baseline.Documents))
	for _, d := range f.Baseline.Documents {
		docs = append(docs, policy.DocumentDigest{Key: d.Key, SHA256: d.SHA256})
	}
	e, err := NewExport(ctx, docs, at)
	if err != nil {
		return nil, fmt.Errorf("context file: %w", err)
	}
	if e.Baseline.PolicySetSHA256 != f.Baseline.PolicySetSHA256 {
		return nil, errors.New("context file's policy_set_sha256 does not match its baseline documents")
	}
	if e.Baseline.SnapshotSHA256 != f.Baseline.SnapshotSHA256 {
		return nil, errors.New("context file's snapshot_sha256 does not match its context and baseline")
	}
	if err := e.parseSourceTokens(f.SourceTokens); err != nil {
		return nil, fmt.Errorf("context file: %w", err)
	}
	return e, nil
}

// parseSourceTokens reads the file's source token names, when it has them:
// on a cosigner export only, one entry per selector that had a token, sorted
// by key, each listed once and with at least one name.
func (e *Export) parseSourceTokens(entries *[]exportSourceTokens) error {
	if entries == nil {
		return nil
	}
	if len(*entries) > MaxSourceTokenSelectors {
		return fmt.Errorf("source_tokens lists %d selectors, at most %d", len(*entries), MaxSourceTokenSelectors)
	}
	names := make(map[string][]string, len(*entries))
	for i, entry := range *entries {
		if i > 0 && (*entries)[i-1].Key >= entry.Key {
			return fmt.Errorf("source_tokens must be sorted by key and list each key once (%s)", entry.Key)
		}
		if entry.Sources == nil {
			return fmt.Errorf("source_tokens entry %s has no sources list", entry.Key)
		}
		if err := validateSourceTokenNames(entry.Key, entry.Sources); err != nil {
			return err
		}
		names[entry.Key] = entry.Sources
	}
	return e.RecordSourceTokens(names)
}
