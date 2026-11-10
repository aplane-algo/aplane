// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyauthor

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/asa"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/policy"
)

// EditKind is the input a field takes.
type EditKind string

const (
	// EditBool toggles between true and false.
	EditBool EditKind = "bool"
	// EditChoice picks one of Choices.
	EditChoice EditKind = "choice"
	// EditAmount takes an amount in display units when the asset's decimals
	// are known, and in base units otherwise; the document stores base units.
	EditAmount EditKind = "amount"
	// EditText takes any string.
	EditText EditKind = "text"
	// EditTerms takes a comma-separated list of terms (EditTerm one term),
	// each checked as TermKind.
	EditTerms EditKind = "terms"
	EditTerm  EditKind = "term"
)

// TermKind is what a list term may be.
type TermKind string

const (
	TermAddress     TermKind = "address"      // an address only
	TermSource      TermKind = "source"       // an address, "*" or "@set"
	TermDestination TermKind = "destination"  // an address, "*", "self" or "@set"
	TermAsset       TermKind = "asset"        // "algo", "asa:<id>", "*" or "@set"
	TermAssetRef    TermKind = "asset_ref"    // "algo" or "asa:<id>"
	TermNetwork     TermKind = "network"      // a network token, or "*"
	TermRekeySender TermKind = "rekey_sender" // an address, "*" or a flat "@set"
	TermRekeyTarget TermKind = "rekey_target" // an address, "*", "self" or a flat "@set"
)

// EditSpec says how a field is edited: what it takes and where the value is
// written.
type EditSpec struct {
	Kind    EditKind
	Pointer string
	Choices []string
	Term    TermKind
	// Network and Asset place an amount, for its decimals.
	Network string
	Asset   string
}

// Decimals returns the decimals an amount is entered with, their source, and
// whether they are known. An editor fixes them when editing starts, so a
// metadata change during the edit cannot rescale what was typed.
func (e EditSpec) Decimals(lookup AssetLookup) (uint64, string, bool) {
	if e.Asset == "algo" {
		return algoDecimals, asa.SourceBuiltin, true
	}
	ref, ok := parseAssetRef(e.Asset)
	if !ok || lookup == nil {
		return 0, "", false
	}
	meta, ok := lookup(e.Network, ref.ASAID)
	if !ok {
		return 0, "", false
	}
	return meta.Decimals, meta.Source, true
}

// Input is the text an editor starts from for the value n: amounts in display
// units (with the given decimals, when known), lists joined by commas.
func (e EditSpec) Input(n policy.DraftNode, decimals uint64, known bool) string {
	switch {
	case !n.Exists():
		return ""
	case e.Kind == EditAmount && n.Kind() == "string":
		raw, err := strconv.ParseUint(n.Text(), 10, 64)
		if err == nil && known {
			return asa.FormatDisplayAmount(raw, asa.Metadata{Decimals: decimals})
		}
		return n.Text()
	case e.Kind == EditTerms && n.Kind() == "array":
		var parts []string
		for _, item := range n.Items() {
			parts = append(parts, render(item))
		}
		return strings.Join(parts, ", ")
	case e.Kind == EditBool && n.Kind() == "boolean":
		return strconv.FormatBool(n.Bool())
	}
	if n.Kind() == "string" {
		return n.Text()
	}
	return compact(n)
}

// Value turns input into the JSON the field stores, or explains why it is
// not acceptable. decimals and known are those fixed when editing started.
func (e EditSpec) Value(input string, decimals uint64, known bool) ([]byte, error) {
	input = strings.TrimSpace(input)
	switch e.Kind {
	case EditBool:
		switch strings.ToLower(input) {
		case "true", "yes", "y":
			return []byte("true"), nil
		case "false", "no", "n":
			return []byte("false"), nil
		}
		return nil, fmt.Errorf("enter yes or no")
	case EditChoice:
		for _, c := range e.Choices {
			if input == c {
				return json.Marshal(c)
			}
		}
		return nil, fmt.Errorf("choose one of: %s", strings.Join(e.Choices, ", "))
	case EditAmount:
		raw, err := parseAmount(input, decimals, known)
		if err != nil {
			return nil, err
		}
		return json.Marshal(strconv.FormatUint(raw, 10))
	case EditText:
		return json.Marshal(input)
	case EditTerm:
		term, err := normalizeTerm(e.Term, input)
		if err != nil {
			return nil, err
		}
		return json.Marshal(term)
	case EditTerms:
		var terms []string
		for _, part := range strings.Split(input, ",") {
			if part = strings.TrimSpace(part); part == "" {
				continue
			}
			term, err := normalizeTerm(e.Term, part)
			if err != nil {
				return nil, err
			}
			terms = append(terms, term)
		}
		if terms == nil {
			terms = []string{}
		}
		return json.Marshal(terms)
	}
	return nil, fmt.Errorf("this field cannot be edited")
}

// parseAmount reads an amount: in display units when the decimals are known
// (so "1.5" of a 6-decimal asset is 1500000), in whole base units otherwise.
func parseAmount(input string, decimals uint64, known bool) (uint64, error) {
	input = strings.ReplaceAll(input, ",", "")
	if input == "" {
		return 0, fmt.Errorf("enter an amount")
	}
	if !known {
		raw, err := strconv.ParseUint(input, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("the asset's decimals are unknown: enter whole base units")
		}
		return raw, nil
	}
	raw, err := asa.ParseDisplayAmount(input, asa.Metadata{Decimals: decimals, Source: asa.SourceBuiltin})
	if err != nil {
		return 0, fmt.Errorf("not an amount with at most %d decimal places: %v", decimals, err)
	}
	return raw, nil
}

// checkTerm catches the mistakes worth catching while typing; the decoder
// still checks the whole document.
func checkTerm(kind TermKind, term string) error {
	address := func() error {
		if a, err := types.DecodeAddress(term); err != nil || a.String() != term {
			return fmt.Errorf("%q is not a valid address (check its checksum)", term)
		}
		return nil
	}
	set := strings.HasPrefix(term, "@") && len(term) > 1
	switch kind {
	case TermAddress:
		return address()
	case TermSource:
		if term == "*" || set {
			return nil
		}
		return address()
	case TermDestination:
		if term == "*" || term == "self" || set {
			return nil
		}
		return address()
	case TermRekeySender:
		// A sender is always itself, so "self" there would be "*" under
		// another name.
		if term == "self" {
			return fmt.Errorf(`self is meaningless as a rekey_policy sender; use "*"`)
		}
		if term == "*" || set {
			return nil
		}
		return address()
	case TermRekeyTarget:
		if term == "*" || term == "self" || set {
			return nil
		}
		return address()
	case TermAsset, TermAssetRef:
		if kind == TermAsset && (term == "*" || set) {
			return nil
		}
		if _, ok := parseAssetRef(term); ok {
			return nil
		}
		return fmt.Errorf(`%q is not an asset: use "algo", an asset ID or asa:<id>`, term)
	case TermNetwork:
		if term == "*" || validNetworkToken(term) {
			return nil
		}
		return fmt.Errorf("%q is not a network token (lowercase letters, digits, '_' or '-')", term)
	}
	return nil
}

func validNetworkToken(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case (r == '_' || r == '-') && i > 0:
		default:
			return false
		}
	}
	return true
}

// AddAction is something that can be added to a section: a transaction type,
// a limit, a set, a route, a list member. Prompt asks for the input Apply
// takes.
type AddAction struct {
	Label  string
	Prompt string
	apply  func(d *policy.Draft, input string) (*policy.Draft, error)
	// previewAsset, for an action that takes an asset, reads the network
	// and the stored asset term from input.
	previewAsset func(input string) (network, term string, err error)
}

// Apply adds to d from input.
func (a AddAction) Apply(d *policy.Draft, input string) (*policy.Draft, error) {
	return a.apply(d, strings.TrimSpace(input))
}

// Removal is what deleting a field removes: an optional member, a list item,
// a route, a set or a limit.
type Removal struct {
	Label   string
	Pointer string
}

// Apply removes it from d.
func (r Removal) Apply(d *policy.Draft) (*policy.Draft, error) { return d.Remove(r.Pointer) }

// replaceWith sets pointer to value, whatever it holds now, without input.
// It repairs a missing or wrong-typed container; label states the value.
func replaceWith(label, pointer, value string) AddAction {
	return AddAction{Label: label, apply: func(d *policy.Draft, _ string) (*policy.Draft, error) {
		return d.Set(pointer, []byte(value))
	}}
}

// duplicateItem inserts a copy of item, the index-th of the list at list,
// right after it, to be edited from there.
func duplicateItem(label, list string, index int, item policy.DraftNode) *AddAction {
	value := compact(item)
	return &AddAction{Label: label, apply: func(d *policy.Draft, _ string) (*policy.Draft, error) {
		return d.Insert(fmt.Sprintf("%s/%d", list, index+1), []byte(value))
	}}
}

// copyRoute inserts a copy of route i after it, under a new id.
func copyRoute(i int, route policy.DraftNode) *AddAction {
	value := compact(route)
	return &AddAction{Label: "Copy the route", Prompt: "id for the copy", apply: func(d *policy.Draft, input string) (*policy.Draft, error) {
		if !validNetworkToken(input) {
			return nil, fmt.Errorf("a route id is lowercase letters, digits, '_' or '-'")
		}
		at := fmt.Sprintf("/transfer_policy/routes/%d", i+1)
		next, err := d.Insert(at, []byte(value))
		if err != nil {
			return nil, err
		}
		id, _ := json.Marshal(input)
		return next.Set(at+"/id", id)
	}}
}

// copySet copies a named set under a new name.
func copySet(kind, base string) AddAction {
	return AddAction{Label: "Copy an " + kind + " set", Prompt: "the set to copy and the new name, e.g. ops ops-backup", apply: func(d *policy.Draft, input string) (*policy.Draft, error) {
		parts := strings.Fields(strings.ReplaceAll(input, "@", ""))
		if len(parts) != 2 || !validNetworkToken(parts[1]) {
			return nil, fmt.Errorf("enter the set to copy and a new name")
		}
		src := d.At(base + "/" + escapeToken(parts[0]))
		if !src.Exists() {
			return nil, fmt.Errorf("there is no %s set %q", kind, parts[0])
		}
		return ensure(d, base+"/"+escapeToken(parts[1]), compact(src))
	}}
}

// NeedsInput reports whether the action takes input, or applies as it is.
func (a AddAction) NeedsInput() bool { return a.Prompt != "" }

// ensure sets value at pointer, first creating any missing parent objects.
func ensure(d *policy.Draft, pointer string, value string) (*policy.Draft, error) {
	tokens := strings.Split(pointer[1:], "/")
	path := ""
	var err error
	for _, t := range tokens[:len(tokens)-1] {
		path += "/" + t
		if !d.At(path).Exists() {
			if d, err = d.Set(path, []byte("{}")); err != nil {
				return nil, err
			}
		}
	}
	if d.At(pointer).Exists() {
		return nil, fmt.Errorf("%s already exists", pointer)
	}
	return d.Set(pointer, []byte(value))
}

func addItem(label, prompt, list string, term TermKind) AddAction {
	return AddAction{Label: label, Prompt: prompt, apply: func(d *policy.Draft, input string) (*policy.Draft, error) {
		input, err := normalizeTerm(term, input)
		if err != nil {
			return nil, err
		}
		v, _ := json.Marshal(input)
		if !d.At(list).Exists() {
			return ensure(d, list, "["+string(v)+"]")
		}
		return d.Insert(list+"/-", v)
	}}
}

// limitAdd adds a threshold for "network asset" under limits at base.
func limitAdd(label, base string, cosigner bool) AddAction {
	return AddAction{Label: label, Prompt: "network and asset, e.g. mainnet algo or mainnet 31566704", apply: func(d *policy.Draft, input string) (*policy.Draft, error) {
		network, asset, err := limitTarget(input)
		if err != nil {
			return nil, err
		}
		value := `{"reject_above": "0"}`
		if !cosigner {
			value = `{"review_above": "0"}`
		}
		return ensure(d, base+"/"+escapeToken(network)+"/"+escapeToken(asset), value)
	}, previewAsset: limitTarget}
}

// limitTarget reads "network asset", the asset normalized to its stored form.
func limitTarget(input string) (network, asset string, err error) {
	parts := strings.Fields(input)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("enter a network and an asset")
	}
	if err := checkTerm(TermNetwork, parts[0]); err != nil || parts[0] == "*" {
		return "", "", fmt.Errorf("%q is not a network token", parts[0])
	}
	asset, err = normalizeTerm(TermAssetRef, parts[1])
	if err != nil {
		return "", "", err
	}
	return parts[0], asset, nil
}

// Suggestions lists terms that fit the field, for an editor to offer: the
// wildcards and keywords the field accepts, the names of the sets of the
// right kind the document defines, the well-known networks, and the
// addresses, assets and networks the document already uses. Only terms the
// field accepts are offered.
func (e EditSpec) Suggestions(d *policy.Draft) []string {
	var out []string
	seen := map[string]bool{}
	add := func(terms ...string) {
		for _, t := range terms {
			if t != "" && !seen[t] && checkTerm(e.Term, t) == nil {
				seen[t] = true
				out = append(out, t)
			}
		}
	}
	sets := func(pointer string, flatOnly bool) {
		node := d.At(pointer)
		for _, name := range node.Keys() {
			if !flatOnly || node.Member(name).Kind() == "array" {
				add("@" + name)
			}
		}
	}
	switch e.Term {
	case TermSource:
		add("*")
		sets("/address_sets", false)
	case TermDestination:
		add("*", "self")
		sets("/address_sets", false)
	case TermRekeySender:
		add("*")
		sets("/address_sets", true)
	case TermRekeyTarget:
		add("*", "self")
		sets("/address_sets", true)
	case TermAsset:
		add("algo", "*")
		sets("/asset_sets", false)
	case TermAssetRef:
		add("algo")
	case TermNetwork:
		add("*", apconfig.NetworkMainnet, apconfig.NetworkTestnet, apconfig.NetworkBetanet)
	}
	// Terms the document already uses, in document order. Set references
	// are left out: sets are offered above only when they are of the kind
	// the field takes.
	var walk func(n policy.DraftNode)
	walk = func(n policy.DraftNode) {
		switch n.Kind() {
		case "string":
			if !strings.HasPrefix(n.Text(), "@") {
				add(n.Text())
			}
		case "object":
			for _, k := range n.Keys() {
				if e.Term == TermAssetRef || e.Term == TermAsset {
					add(k) // limit keys name assets
				}
				walk(n.Member(k))
			}
		case "array":
			for _, item := range n.Items() {
				walk(item)
			}
		}
	}
	if e.Term != TermNetwork {
		walk(d.Root())
		return out
	}
	// Networks are keys of limits and of per-network sets, and route items.
	add(d.At("/limits").Keys()...)
	for _, base := range []string{"/address_sets", "/asset_sets"} {
		node := d.At(base)
		for _, name := range node.Keys() {
			add(node.Member(name).Keys()...)
		}
	}
	for _, r := range d.At("/transfer_policy/routes").Items() {
		for _, n := range r.Member("networks").Items() {
			add(n.Text())
		}
	}
	return out
}
