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
	TermRekeyTarget TermKind = "rekey_target" // an address or "@set"
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
		if err := checkTerm(e.Term, input); err != nil {
			return nil, err
		}
		return json.Marshal(input)
	case EditTerms:
		var terms []string
		for _, part := range strings.Split(input, ",") {
			if part = strings.TrimSpace(part); part == "" {
				continue
			}
			if err := checkTerm(e.Term, part); err != nil {
				return nil, err
			}
			terms = append(terms, part)
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
	case TermRekeyTarget:
		if set {
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
		return fmt.Errorf(`%q is not an asset: use "algo" or "asa:<id>"`, term)
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
		if err := checkTerm(term, input); err != nil {
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
	return AddAction{Label: label, Prompt: "network and asset, e.g. mainnet algo or mainnet asa:31566704", apply: func(d *policy.Draft, input string) (*policy.Draft, error) {
		parts := strings.Fields(input)
		if len(parts) != 2 {
			return nil, fmt.Errorf("enter a network and an asset")
		}
		if err := checkTerm(TermNetwork, parts[0]); err != nil || parts[0] == "*" {
			return nil, fmt.Errorf("%q is not a network token", parts[0])
		}
		if err := checkTerm(TermAssetRef, parts[1]); err != nil {
			return nil, err
		}
		value := `{"reject_above": "0"}`
		if !cosigner {
			value = `{"review_above": "0"}`
		}
		return ensure(d, base+"/"+escapeToken(parts[0])+"/"+escapeToken(parts[1]), value)
	}}
}
