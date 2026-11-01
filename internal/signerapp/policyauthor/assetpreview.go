// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyauthor

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/aplane-algo/aplane/internal/asaset"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
)

// Asset entry. An asset is typed by its ID, bare or as asa:<id>, and stored
// as canonical asa:<id>. Before the value is set, the editor shows what the
// ID means on the network the field applies to, from the loaded node export
// or, without one, from the built-in tables. Nothing is looked up live.

// normalizeTerm returns term as the field stores it: an asset ID, bare or
// asa:<id> with leading zeros, becomes canonical asa:<id>. Other terms are
// returned unchanged. The result is checked as kind.
func normalizeTerm(kind TermKind, term string) (string, error) {
	if kind == TermAsset || kind == TermAssetRef {
		digits, prefixed := strings.CutPrefix(term, "asa:")
		if prefixed || allDigits(term) {
			if !allDigits(digits) {
				return "", fmt.Errorf(`%q is not an asset: use "algo", an asset ID or asa:<id>`, term)
			}
			id, err := strconv.ParseUint(digits, 10, 64)
			switch {
			case err != nil:
				return "", fmt.Errorf("asset ID %s is too large: the largest is 18446744073709551615", digits)
			case id == 0:
				return "", fmt.Errorf("asset ID 0 is not an asset: IDs start at 1")
			}
			term = "asa:" + strconv.FormatUint(id, 10)
		}
	}
	return term, checkTerm(kind, term)
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// AssetStatus is what an asset term's identity is known to be.
type AssetStatus int

const (
	// AssetInNodeSet: the exported node's effective ASA set has it.
	AssetInNodeSet AssetStatus = iota
	// AssetNotInNodeSet: the exported node's set does not; the node would
	// refuse to admit the document.
	AssetNotInNodeSet
	// AssetBuiltin: no export is loaded, and the built-in table has it;
	// whether the node's set has it is unverified.
	AssetBuiltin
	// AssetUnknown: no export is loaded, and the built-in table does not
	// have it; its decimals are unknown, so amounts are in base units.
	AssetUnknown
	// AssetUnresolved: the network is unknown or the field's network is
	// ambiguous, so no identity can be established.
	AssetUnresolved
)

// Problem reports whether the status is one a document should not keep.
func (s AssetStatus) Problem() bool {
	return s == AssetNotInNodeSet || s == AssetUnknown || s == AssetUnresolved
}

// AssetPreview is what one asset term means where it is being entered.
type AssetPreview struct {
	// Term is the term as it will be stored.
	Term    string
	Network string
	// Genesis is the network's genesis hash, when the network is known.
	Genesis       string
	Name          string
	UnitName      string
	Decimals      uint64
	DecimalsKnown bool
	Status        AssetStatus
	// Source is where known metadata comes from: built-in, or confirmed on
	// the node.
	Source string
	// Reason says why the identity is unresolved.
	Reason string
}

// String is the preview as one line of text, safe for a terminal: names and
// the network, which may come from a document, are made printable.
func (p AssetPreview) String() string {
	p.Network = asaset.Printable(p.Network)
	switch p.Status {
	case AssetUnresolved:
		return fmt.Sprintf("%s: %s", p.Term, p.Reason)
	case AssetUnknown:
		return fmt.Sprintf("%s on %s: unknown asset, decimals unknown; amounts are in base units (no node export loaded)", p.Term, p.Network)
	case AssetNotInNodeSet:
		return fmt.Sprintf("%s on %s: not in the exported node's ASA set; the node would refuse this document (apadmin asa add %s %s)",
			p.Term, p.Network, p.Network, strings.TrimPrefix(p.Term, "asa:"))
	}
	label := asaset.Printable(p.UnitName)
	if name := asaset.Printable(p.Name); name != "" && name != label {
		if label == "" {
			label = name
		} else {
			label += " (" + name + ")"
		}
	}
	where := "in the exported node's ASA set, " + p.Source
	if p.Status == AssetBuiltin {
		where = "built-in; whether the node has it is unverified without its export"
	}
	return fmt.Sprintf("%s on %s: %s, %d decimals; %s", p.Term, p.Network, label, p.Decimals, where)
}

// PreviewAsset describes term on network as the node of node describes it,
// or the built-in tables without one. It reports false for a term that names
// no specific asset: "algo", "*", a set, or anything that is not an asset.
func PreviewAsset(node *NodeContext, network, term string) (AssetPreview, bool) {
	ref, ok := parseAssetRef(term)
	if !ok || ref.Algo {
		return AssetPreview{}, false
	}
	p := AssetPreview{Term: "asa:" + strconv.FormatUint(ref.ASAID, 10), Network: network}
	ctx := builtinContext(noderole.RoleSigner)
	if node != nil {
		ctx = node.Context
	}
	if ctx == nil {
		p.Status, p.Reason = AssetUnresolved, "no network mapping is available"
		return p, true
	}
	genesis, known := ctx.Networks()[network]
	if !known {
		p.Status = AssetUnresolved
		if node != nil {
			p.Reason = fmt.Sprintf("network %q is not one the exported node maps", network)
		} else {
			p.Reason = fmt.Sprintf("network %q is not a built-in network; open the node's export to check its own", network)
		}
		return p, true
	}
	p.Genesis = genesis.String()
	a, found := ctx.Asset(network, ref.ASAID)
	switch {
	case !found && node != nil:
		p.Status = AssetNotInNodeSet
	case !found:
		p.Status = AssetUnknown
	default:
		p.Name, p.UnitName, p.Decimals, p.DecimalsKnown = a.Name, a.UnitName, a.Decimals, true
		p.Status, p.Source = AssetBuiltin, "built-in"
		if node != nil {
			p.Status = AssetInNodeSet
			if a.Origin == asaset.OriginOperator {
				p.Source = "confirmed on the node"
			}
		}
	}
	return p, true
}

// AssetNetwork is the network an asset typed into the field applies to:
// a set member's network, or a route's one network. It reports false with
// the reason when the field gives no single network.
func (e EditSpec) AssetNetwork(d *policy.Draft) (string, string, bool) {
	tokens := pointerTokens(e.Pointer)
	switch {
	case len(tokens) == 3 && tokens[0] == "asset_sets":
		return tokens[2], "", true
	case len(tokens) == 4 && tokens[0] == "transfer_policy" && tokens[1] == "routes" && tokens[3] == "assets":
		networks := d.At("/transfer_policy/routes/" + escapeToken(tokens[2]) + "/networks").Items()
		switch {
		case len(networks) == 0:
			return "", "the route has no network yet; set its networks first", false
		case len(networks) == 1 && networks[0].Kind() == "string" && networks[0].Text() != "*":
			return networks[0].Text(), "", true
		}
		return "", "a direct asset needs a route with exactly one network; for several networks, name the asset per network in an asset set", false
	}
	return "", "this field gives no network", false
}

// AssetPreviews describes each specific asset in input, a value typed into
// the field, on the field's network. Other terms are left out.
func (e EditSpec) AssetPreviews(d *policy.Draft, node *NodeContext, input string) []AssetPreview {
	if e.Term != TermAsset && e.Term != TermAssetRef {
		return nil
	}
	network, reason, ok := e.AssetNetwork(d)
	var out []AssetPreview
	for _, part := range strings.Split(input, ",") {
		term, err := normalizeTerm(e.Term, strings.TrimSpace(part))
		if err != nil {
			continue
		}
		if !ok {
			if ref, isRef := parseAssetRef(term); isRef && !ref.Algo {
				out = append(out, AssetPreview{Term: term, Status: AssetUnresolved, Reason: reason})
			}
			continue
		}
		if p, isAsset := PreviewAsset(node, network, term); isAsset {
			out = append(out, p)
		}
	}
	return out
}

// AssetPreviews describes the asset in input, for an add action that takes
// one; nil for any other action.
func (a AddAction) AssetPreviews(node *NodeContext, input string) []AssetPreview {
	if a.previewAsset == nil {
		return nil
	}
	network, term, ok := a.previewAsset(strings.TrimSpace(input))
	if !ok {
		return nil
	}
	if p, isAsset := PreviewAsset(node, network, term); isAsset {
		return []AssetPreview{p}
	}
	return nil
}

// SummarizeAssets says how many of previews have a problem, for a list too
// long to show one per line; the first problem is named.
func SummarizeAssets(previews []AssetPreview) string {
	problems := 0
	first := ""
	for _, p := range previews {
		if p.Status.Problem() {
			if problems == 0 {
				first = p.String()
			}
			problems++
		}
	}
	if problems == 0 {
		return fmt.Sprintf("%d asset(s), no problems", len(previews))
	}
	return fmt.Sprintf("%d asset(s), %d with a problem; first: %s", len(previews), problems, first)
}

// pointerTokens splits a JSON Pointer into its unescaped tokens.
func pointerTokens(pointer string) []string {
	if !strings.HasPrefix(pointer, "/") {
		return nil
	}
	tokens := strings.Split(pointer[1:], "/")
	for i, t := range tokens {
		tokens[i] = strings.ReplaceAll(strings.ReplaceAll(t, "~1", "/"), "~0", "~")
	}
	return tokens
}
