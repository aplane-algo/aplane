// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyauthor

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
)

// Section is one entry of a document's outline: a part of the document, the
// fields shown for it, and what can be added to it. Sections are a flat list
// in display order; Depth nests them (a route under Routes).
type Section struct {
	ID      string
	Title   string
	Depth   int
	Pointer string
	Fields  []Field
	// Adds are the things that can be added here; Remove, when set, deletes
	// the whole section's object (a route).
	Adds   []AddAction
	Remove *Removal
	// Problems are those that belong to the section but to none of its
	// fields, such as a document error with no pointer.
	Problems []Problem
}

// Field is one row of a section's form. Missing marks a field the role
// requires that the document lacks; Absent an optional field that is not set;
// Unknown a member the format does not define. Edit, when set, says how the
// field is edited, and Remove what deleting it removes.
type Field struct {
	Label    string
	Pointer  string
	Value    string
	Note     string
	Missing  bool
	Absent   bool
	Unknown  bool
	Edit     *EditSpec
	Remove   *Removal
	Problems []Problem
}

// ProblemCount reports how many problems the section holds, its fields'
// included, and how many of them are errors.
func (s Section) ProblemCount() (all, errors int) {
	count := func(ps []Problem) {
		for _, p := range ps {
			all++
			if p.Severity == SeverityError {
				errors++
			}
		}
	}
	count(s.Problems)
	for _, f := range s.Fields {
		count(f.Problems)
	}
	return all, errors
}

// Outline lays out a file's document as sections of fields, with problems
// attached to the field their pointer names. It works on a document that does
// not decode: every member is shown, fields the role requires and the
// document lacks are marked missing, optional fields that are not set are
// shown so they can be set, and members the format does not define are
// listed under "Other fields". An unreadable or unparsable file is one
// section holding its problems. lookup supplies ASA metadata for display
// units and may be nil.
func Outline(f *File, problems []Problem, lookup AssetLookup) []Section {
	o := &outliner{lookup: lookup, problems: append([]Problem(nil), problems...)}
	if f.Draft == nil {
		o.add(Section{ID: "file", Title: "File (" + f.State.String() + ")"})
		return o.finish()
	}
	o.draft = f.Draft
	o.role = f.Role
	o.build()
	return o.finish()
}

type outliner struct {
	draft    *policy.Draft
	role     noderole.Role
	lookup   AssetLookup
	problems []Problem
	sections []Section
}

// add appends a section and returns its index. Callers keep the index, not a
// pointer: a later add can move the slice.
func (o *outliner) add(s Section) int {
	o.sections = append(o.sections, s)
	return len(o.sections) - 1
}

// finish attaches each problem to the most specific field whose pointer is
// the problem's or contains it, then to the most specific section, and puts
// anything left on the first section.
func (o *outliner) finish() []Section {
	for _, p := range o.problems {
		bestSec, bestField, bestLen := -1, -1, -1
		for si, s := range o.sections {
			for fi, f := range s.Fields {
				if within(p, f) && len(f.Pointer) > bestLen {
					bestSec, bestField, bestLen = si, fi, len(f.Pointer)
				}
			}
		}
		if bestField >= 0 {
			o.sections[bestSec].Fields[bestField].Problems = append(o.sections[bestSec].Fields[bestField].Problems, p)
			continue
		}
		bestSec, bestLen = 0, -1
		for si, s := range o.sections {
			if s.Pointer != "" && covers(s.Pointer, p.Pointer) && len(s.Pointer) > bestLen {
				bestSec, bestLen = si, len(s.Pointer)
			}
		}
		if len(o.sections) == 0 {
			o.add(Section{ID: "file", Title: "File"})
		}
		o.sections[bestSec].Problems = append(o.sections[bestSec].Problems, p)
	}
	return o.sections
}

// within reports whether problem p belongs to field f: its pointer is the
// field's or under it, or it is a "missing required field" reported on the
// parent object for a field that is missing.
func within(p Problem, f Field) bool {
	if f.Pointer == "" || f.Absent {
		return false
	}
	if covers(f.Pointer, p.Pointer) {
		return true
	}
	if !f.Missing {
		return false
	}
	parent := f.Pointer[:strings.LastIndex(f.Pointer, "/")]
	name := f.Pointer[strings.LastIndex(f.Pointer, "/")+1:]
	return p.Pointer == parent && strings.Contains(p.Message, strconv.Quote(name))
}

// covers reports whether pointer is base or names a value inside it.
func covers(base, pointer string) bool {
	return pointer == base || strings.HasPrefix(pointer, base+"/")
}

func escapeToken(token string) string {
	return strings.ReplaceAll(strings.ReplaceAll(token, "~", "~0"), "/", "~1")
}

// fieldSpec is one field the format defines on an object, and how it is
// edited.
type fieldSpec struct {
	name, label, note string
	required          bool
	kind              string // display: "bool", "fee", "miss", or "" for plain
	edit              EditKind
	choices           []string
	term              TermKind
	asset             string
}

var (
	verdictsSigner   = []string{"allow", "review", "reject"}
	verdictsCosigner = []string{"allow", "reject"}
	missActions      = []string{"reject", "review", "operator_default"}
)

func (o *outliner) build() {
	root := o.draft.Root()
	if root.Kind() != "object" {
		var adds []AddAction
		for _, role := range []noderole.Role{noderole.RoleSigner, noderole.RoleCosigner} {
			role := role
			adds = append(adds, AddAction{Label: "Replace the document with the shipped " + string(role) + " default", apply: func(*policy.Draft, string) (*policy.Draft, error) {
				data, err := policy.EmbeddedDefault(role)
				if err != nil {
					return nil, err
				}
				return policy.ParseDraft(data)
			}})
		}
		o.add(Section{ID: "document", Title: "Document", Adds: adds, Fields: []Field{{Label: "document", Pointer: "", Value: render(root), Note: "a policy document must be a JSON object"}}})
		return
	}
	cosigner := o.role == noderole.RoleCosigner
	known := map[string]bool{}
	use := func(specs []fieldSpec) []fieldSpec {
		for _, s := range specs {
			known[s.name] = true
		}
		return specs
	}

	o.add(Section{ID: "summary", Title: "Summary", Fields: o.fields(root, "", use([]fieldSpec{
		{name: "format", label: "Format", required: true, edit: EditChoice, choices: []string{"aplane.policy.v1"}},
		{name: "role", label: "Role", required: true, edit: EditChoice, choices: []string{"signer", "cosigner"}},
		{name: "key", label: "Key", note: `"default", or the key this document governs`, required: true, edit: EditText},
		{name: "description", label: "Description", edit: EditText},
	}))})

	guard := func(name, label, note string) fieldSpec {
		return fieldSpec{name: name, label: label, note: note, required: true, kind: "bool", edit: EditBool}
	}
	guards := []fieldSpec{
		guard("reject_close_remainder", "Reject ALGO close-outs", "always deny"),
		guard("reject_asset_close", "Reject ASA close-outs", "always deny"),
		guard("reject_clawback", "Reject clawbacks", "always deny"),
	}
	if cosigner {
		guards = append(guards, guard("reject_rekey", "Reject every rekey", "always deny; when no, rekey_policy decides"))
	} else {
		guards = append([]fieldSpec{guard("reject_foreign_rekey", "Reject rekeys to keys this node does not hold", "always deny")}, guards...)
		guards = append(guards,
			guard("always_review_warnings", "Send warnings to review", "always review"),
			guard("auto_approve_self_noop_transfer", "Self no-op auto-approval", "always approve, after deny and review rules"),
		)
	}
	o.add(Section{ID: "guards", Title: "Guards", Fields: o.fields(root, "", use(guards))})

	o.add(Section{ID: "fee", Title: "Fee cap", Fields: o.fields(root, "", use([]fieldSpec{
		{name: "max_fee_microalgos", label: "Maximum fee", note: `0 is no cap`, required: true, kind: "fee", edit: EditAmount, asset: "algo"},
	}))})

	known["transaction_types"] = true
	typeAdds := []AddAction{o.typeAdd(cosigner)}
	if types := root.Member("transaction_types"); types.Exists() && types.Kind() != "object" {
		typeAdds = nil
	}
	if types := root.Member("transaction_types"); types.Kind() != "object" {
		typeAdds = append(typeAdds, replaceWith("Set transaction types to reject every type (\"*\": \"reject\")", "/transaction_types", `{"*": "reject"}`))
	}
	o.add(Section{ID: "types", Title: "Transaction types", Pointer: "/transaction_types",
		Fields: o.transactionTypes(root.Member("transaction_types"), cosigner), Adds: typeAdds})

	known["limits"] = true
	o.add(Section{ID: "limits", Title: "Limits", Pointer: "/limits", Fields: o.limits(root.Member("limits"), "/limits", cosigner),
		Adds: []AddAction{limitAdd("Add a limit", "/limits", cosigner)}})

	known["address_sets"] = true
	sets := root.Member("address_sets")
	o.add(Section{ID: "address_sets", Title: fmt.Sprintf("Address sets (%d)", len(sets.Keys())), Pointer: "/address_sets",
		Fields: o.addressSets(sets), Adds: o.addressSetAdds(sets)})
	known["asset_sets"] = true
	assetSets := root.Member("asset_sets")
	o.add(Section{ID: "asset_sets", Title: fmt.Sprintf("Asset sets (%d)", len(assetSets.Keys())), Pointer: "/asset_sets",
		Fields: o.assetSets(assetSets), Adds: []AddAction{assetSetAdd()}})

	known["transfer_policy"] = true
	o.transfers(root.Member("transfer_policy"), cosigner)

	if cosigner {
		known["rekey_policy"] = true
		o.add(Section{ID: "rekey", Title: "Rekey edges", Pointer: "/rekey_policy", Fields: o.rekey(root.Member("rekey_policy")),
			Adds: []AddAction{rekeyEdgeAdd()}})
	}

	if other := unknownFields(root, known, "a "+roleName(o.role)+" document"); len(other) > 0 {
		o.add(Section{ID: "other", Title: "Other fields", Fields: other})
	}
}

func roleName(r noderole.Role) string {
	if r == "" {
		return "policy"
	}
	return string(r)
}

// unknownFields lists the members of node that known does not name; each can
// be removed.
func unknownFields(node policy.DraftNode, known map[string]bool, of string) []Field {
	var out []Field
	for _, k := range node.Keys() {
		if !known[k] {
			n := node.Member(k)
			out = append(out, Field{Label: k, Pointer: n.Pointer(), Value: render(n), Unknown: true,
				Note: "not a field of " + of, Remove: &Removal{Label: "remove " + k, Pointer: n.Pointer()}})
		}
	}
	return out
}

// fields lays out the named members of object node at pointer base.
func (o *outliner) fields(node policy.DraftNode, base string, specs []fieldSpec) []Field {
	var out []Field
	for _, s := range specs {
		m := node.Member(s.name)
		f := Field{Label: s.label, Pointer: base + "/" + escapeToken(s.name), Note: s.note}
		if s.edit != "" {
			f.Edit = &EditSpec{Kind: s.edit, Pointer: f.Pointer, Choices: s.choices, Term: s.term, Asset: s.asset}
		}
		switch {
		case !m.Exists() && s.required:
			f.Missing, f.Value = true, "(missing)"
		case !m.Exists():
			f.Absent, f.Value = true, "(not set)"
		default:
			f.Value = o.value(m, s.kind, "")
			if !s.required {
				f.Remove = &Removal{Label: "remove " + strings.ToLower(s.label), Pointer: f.Pointer}
			}
		}
		out = append(out, f)
	}
	return out
}

// value renders a field's value; kind selects a friendlier form when the
// value has the expected type, and network gives an amount's context.
func (o *outliner) value(n policy.DraftNode, kind, network string) string {
	switch {
	case kind == "bool" && n.Kind() == "boolean":
		if n.Bool() {
			return "yes"
		}
		return "no"
	case kind == "fee" && n.Kind() == "string":
		if n.Text() == "0" {
			return "no cap"
		}
		return o.amount(network, policy.TransferAssetRef{Algo: true}, n.Text())
	case kind == "miss" && n.Kind() == "string":
		return missAction(policy.TransferOnNoRoute(n.Text()))
	}
	return render(n)
}

// amount shows a base-unit amount string in display units too, when it is a
// number and the asset's decimals are known.
func (o *outliner) amount(network string, ref policy.TransferAssetRef, text string) string {
	raw, err := strconv.ParseUint(text, 10, 64)
	if err != nil {
		return strconv.Quote(text)
	}
	e := explainer{lookup: o.lookup}
	return e.amount(network, ref, raw)
}

func (o *outliner) transactionTypes(types policy.DraftNode, cosigner bool) []Field {
	if !types.Exists() {
		return []Field{{Label: "transaction_types", Pointer: "/transaction_types", Value: "(missing)", Missing: true}}
	}
	if types.Kind() != "object" {
		return []Field{{Label: "transaction_types", Pointer: types.Pointer(), Value: render(types)}}
	}
	choices := verdictsSigner
	if cosigner {
		choices = verdictsCosigner
	}
	var out []Field
	for _, k := range types.Keys() {
		label := k
		if k == policy.TransactionTypeWildcard {
			label = "* (any other type)"
		}
		n := types.Member(k)
		out = append(out, Field{Label: label, Pointer: n.Pointer(), Value: render(n),
			Edit:   &EditSpec{Kind: EditChoice, Pointer: n.Pointer(), Choices: choices},
			Remove: &Removal{Label: "remove the " + k + " entry", Pointer: n.Pointer()}})
	}
	if cosigner && !types.Member(policy.TransactionTypeWildcard).Exists() {
		out = append(out, Field{Label: "* (any other type)", Value: "reject", Note: "omitted; a cosigner rejects every type the map does not name"})
	}
	return out
}

func (o *outliner) typeAdd(cosigner bool) AddAction {
	choices := verdictsSigner
	if cosigner {
		choices = verdictsCosigner
	}
	names := append([]string{policy.TransactionTypeWildcard}, policy.TransactionTypeNames...)
	return AddAction{Label: "Add a transaction type", Prompt: "type and verdict, e.g. keyreg " + choices[len(choices)-1], apply: func(d *policy.Draft, input string) (*policy.Draft, error) {
		parts := strings.Fields(input)
		if len(parts) != 2 || !slices.Contains(names, parts[0]) || !slices.Contains(choices, parts[1]) {
			return nil, fmt.Errorf("enter a type (%s) and a verdict (%s)", strings.Join(names, ", "), strings.Join(choices, ", "))
		}
		v, _ := json.Marshal(parts[1])
		return ensure(d, "/transaction_types/"+escapeToken(parts[0]), string(v))
	}}
}

// limits lays out network -> asset -> thresholds, one field per threshold, at
// base ("/limits", or a route's limits).
func (o *outliner) limits(limits policy.DraftNode, base string, cosigner bool) []Field {
	if !limits.Exists() {
		return nil
	}
	if limits.Kind() != "object" {
		return []Field{{Label: "limits", Pointer: limits.Pointer(), Value: render(limits), Remove: &Removal{Label: "remove limits", Pointer: limits.Pointer()}}}
	}
	var out []Field
	for _, network := range limits.Keys() {
		assets := limits.Member(network)
		if assets.Kind() != "object" {
			out = append(out, Field{Label: network, Pointer: assets.Pointer(), Value: render(assets), Remove: &Removal{Label: "remove " + network, Pointer: assets.Pointer()}})
			continue
		}
		for _, asset := range assets.Keys() {
			out = append(out, o.thresholdFields(network, asset, assets.Member(asset), cosigner)...)
		}
	}
	return out
}

// thresholdFields gives each threshold of one asset its own amount field.
// Removing the only threshold set removes the asset's entry.
func (o *outliner) thresholdFields(network, asset string, t policy.DraftNode, cosigner bool) []Field {
	label := network + " " + o.assetLabel(network, asset)
	entry := &Removal{Label: "remove the " + label + " limit", Pointer: t.Pointer()}
	if t.Kind() != "object" {
		return []Field{{Label: label, Pointer: t.Pointer(), Value: render(t), Remove: entry}}
	}
	ref, refOK := parseAssetRef(asset)
	names := []string{"review_above", "reject_above"}
	if cosigner {
		names = []string{"reject_above"}
	}
	set := 0
	for _, k := range names {
		if t.Member(k).Exists() {
			set++
		}
	}
	var out []Field
	for _, k := range names {
		v := t.Member(k)
		f := Field{Label: label + " " + strings.ReplaceAll(k, "_", " "), Pointer: t.Pointer() + "/" + k,
			Edit: &EditSpec{Kind: EditAmount, Pointer: t.Pointer() + "/" + k, Network: network, Asset: asset}}
		switch {
		case !v.Exists():
			f.Absent, f.Value = true, "(not set)"
		case refOK && v.Kind() == "string":
			f.Value = o.amount(network, ref, v.Text())
		default:
			f.Value = render(v)
		}
		if v.Exists() {
			f.Remove = &Removal{Label: "remove this threshold", Pointer: f.Pointer}
			if set == 1 {
				f.Remove = entry
			}
		}
		out = append(out, f)
	}
	// On a cosigner node review_above is not a field, so it shows as unknown.
	known := map[string]bool{"reject_above": true, "review_above": !cosigner}
	out = append(out, unknownFields(t, known, "a threshold")...)
	return out
}

func parseAssetRef(asset string) (policy.TransferAssetRef, bool) {
	if asset == "algo" {
		return policy.TransferAssetRef{Algo: true}, true
	}
	if id, ok := strings.CutPrefix(asset, "asa:"); ok {
		if n, err := strconv.ParseUint(id, 10, 64); err == nil && n > 0 {
			return policy.TransferAssetRef{ASAID: n}, true
		}
	}
	return policy.TransferAssetRef{}, false
}

func (o *outliner) assetLabel(network, asset string) string {
	ref, ok := parseAssetRef(asset)
	if !ok {
		return asset
	}
	e := explainer{lookup: o.lookup}
	return e.assetName(network, ref)
}

// addressSets lists every member, one field per address, grouped by network.
func (o *outliner) addressSets(sets policy.DraftNode) []Field {
	if !sets.Exists() {
		return nil
	}
	if sets.Kind() != "object" {
		return []Field{{Label: "address_sets", Pointer: sets.Pointer(), Value: render(sets), Remove: &Removal{Label: "remove address_sets", Pointer: sets.Pointer()}}}
	}
	var out []Field
	for _, name := range sets.Keys() {
		set := sets.Member(name)
		switch set.Kind() {
		case "array":
			out = append(out, listFields("@"+name+" (every network)", set, TermAddress, &Removal{Label: "remove @" + name, Pointer: set.Pointer()})...)
		case "object":
			for _, network := range set.Keys() {
				list := set.Member(network)
				gone := &Removal{Label: "remove @" + name + " on " + network, Pointer: list.Pointer()}
				if len(set.Keys()) == 1 {
					gone = &Removal{Label: "remove @" + name, Pointer: set.Pointer()}
				}
				out = append(out, listFields("@"+name+" "+network, list, TermAddress, gone)...)
			}
		default:
			out = append(out, Field{Label: "@" + name, Pointer: set.Pointer(), Value: render(set), Remove: &Removal{Label: "remove @" + name, Pointer: set.Pointer()}})
		}
	}
	return out
}

// addressSetAdds adds a set, and an address to each existing list.
func (o *outliner) addressSetAdds(sets policy.DraftNode) []AddAction {
	adds := []AddAction{{Label: "Add an address set", Prompt: "name, or name and network for a set on one network", apply: func(d *policy.Draft, input string) (*policy.Draft, error) {
		parts := strings.Fields(input)
		if len(parts) == 0 || len(parts) > 2 || !validNetworkToken(parts[0]) {
			return nil, fmt.Errorf("a set name is lowercase letters, digits, '_' or '-'")
		}
		if len(parts) == 1 {
			return ensure(d, "/address_sets/"+escapeToken(parts[0]), "[]")
		}
		if !validNetworkToken(parts[1]) {
			return nil, fmt.Errorf("%q is not a network token", parts[1])
		}
		return ensure(d, "/address_sets/"+escapeToken(parts[0])+"/"+escapeToken(parts[1]), "[]")
	}}}
	for _, name := range sets.Keys() {
		set := sets.Member(name)
		switch set.Kind() {
		case "array":
			adds = append(adds, addItem("Add an address to @"+name, "address", set.Pointer(), TermAddress))
		case "object":
			for _, network := range set.Keys() {
				adds = append(adds, addItem("Add an address to @"+name+" on "+network, "address", set.Member(network).Pointer(), TermAddress))
			}
		}
	}
	return adds
}

func (o *outliner) assetSets(sets policy.DraftNode) []Field {
	if !sets.Exists() {
		return nil
	}
	if sets.Kind() != "object" {
		return []Field{{Label: "asset_sets", Pointer: sets.Pointer(), Value: render(sets), Remove: &Removal{Label: "remove asset_sets", Pointer: sets.Pointer()}}}
	}
	var out []Field
	for _, name := range sets.Keys() {
		set := sets.Member(name)
		if set.Kind() != "object" {
			out = append(out, Field{Label: "@" + name, Pointer: set.Pointer(), Value: render(set), Remove: &Removal{Label: "remove @" + name, Pointer: set.Pointer()}})
			continue
		}
		for _, network := range set.Keys() {
			list := set.Member(network)
			var refs []string
			for _, item := range list.Items() {
				if item.Kind() == "string" {
					refs = append(refs, o.assetLabel(network, item.Text()))
				} else {
					refs = append(refs, render(item))
				}
			}
			value := strings.Join(refs, ", ")
			if list.Kind() != "array" {
				value = render(list)
			} else if len(refs) == 0 {
				value = "(none)"
			}
			gone := &Removal{Label: "remove @" + name + " on " + network, Pointer: list.Pointer()}
			if len(set.Keys()) == 1 {
				gone = &Removal{Label: "remove @" + name, Pointer: set.Pointer()}
			}
			out = append(out, Field{Label: "@" + name + " " + network, Pointer: list.Pointer(), Value: value,
				Edit: &EditSpec{Kind: EditTerms, Pointer: list.Pointer(), Term: TermAssetRef}, Remove: gone})
		}
	}
	return out
}

func assetSetAdd() AddAction {
	return AddAction{Label: "Add an asset set", Prompt: "name and network, e.g. usd mainnet", apply: func(d *policy.Draft, input string) (*policy.Draft, error) {
		parts := strings.Fields(input)
		if len(parts) != 2 || !validNetworkToken(parts[0]) || !validNetworkToken(parts[1]) {
			return nil, fmt.Errorf("enter a set name and a network")
		}
		return ensure(d, "/asset_sets/"+escapeToken(parts[0])+"/"+escapeToken(parts[1]), "[]")
	}}
}

// listFields gives each item of an array its own field, so every member is on
// screen with its own pointer and can be edited or removed. empty is what
// removing the field of an empty list removes.
func listFields(label string, list policy.DraftNode, term TermKind, empty *Removal) []Field {
	if list.Kind() != "array" {
		return []Field{{Label: label, Pointer: list.Pointer(), Value: render(list), Remove: empty}}
	}
	items := list.Items()
	if len(items) == 0 {
		return []Field{{Label: label, Pointer: list.Pointer(), Value: "(none)", Remove: empty}}
	}
	out := make([]Field, 0, len(items))
	for _, item := range items {
		out = append(out, Field{Label: label, Pointer: item.Pointer(), Value: render(item),
			Edit:   &EditSpec{Kind: EditTerm, Pointer: item.Pointer(), Term: term},
			Remove: &Removal{Label: "remove this address", Pointer: item.Pointer()}})
	}
	return out
}

func (o *outliner) transfers(tp policy.DraftNode, cosigner bool) {
	head := o.add(Section{ID: "transfers", Title: "Transfers", Pointer: "/transfer_policy"})
	if tp.Kind() != "object" {
		// Missing or not an object: offer an explicit starting value, stated
		// in full, rather than leaving the draft stuck.
		empty := `{"routes": []}`
		label := "Set transfer_policy to an allowlist with no routes (every transfer rejected)"
		if !cosigner {
			empty = `{"on_no_route": "reject", "close_on_no_route": "reject", "clawback_on_no_route": "reject", "routes": []}`
			label = "Set transfer_policy to an allowlist with no routes (every transfer, close-out and clawback rejected)"
		}
		o.sections[head].Adds = []AddAction{replaceWith(label, "/transfer_policy", empty)}
		if !tp.Exists() {
			o.sections[head].Fields = []Field{{Label: "transfer_policy", Pointer: "/transfer_policy", Value: "(missing)", Missing: true}}
		} else {
			o.sections[head].Fields = []Field{{Label: "transfer_policy", Pointer: tp.Pointer(), Value: render(tp), Note: "transfer_policy must be an object"}}
		}
		return
	}
	known := map[string]bool{"blocked_destinations": true, "routes": true}
	if !cosigner {
		miss := func(name, label string) fieldSpec {
			return fieldSpec{name: name, label: label, required: true, kind: "miss", edit: EditChoice, choices: missActions}
		}
		specs := []fieldSpec{
			miss("on_no_route", "Transfer no route allows"),
			miss("close_on_no_route", "Close-out no route allows"),
			miss("clawback_on_no_route", "Clawback no route allows"),
		}
		for _, s := range specs {
			known[s.name] = true
		}
		o.sections[head].Fields = append(o.sections[head].Fields, Field{Label: "Summary", Value: missSummary(tp)})
		o.add(Section{ID: "miss", Title: "Miss actions", Depth: 1, Fields: o.fields(tp, "/transfer_policy", specs)})
	} else {
		o.sections[head].Fields = append(o.sections[head].Fields, Field{Label: "Summary", Value: "allowlist: a transfer no route allows is rejected"})
	}
	blocked := tp.Member("blocked_destinations")
	o.add(Section{ID: "blocked", Title: fmt.Sprintf("Blocked destinations (%d)", len(blocked.Items())), Depth: 1, Pointer: "/transfer_policy/blocked_destinations",
		Fields: blockedFields(blocked),
		Adds:   []AddAction{addItem("Add a blocked destination", "address", "/transfer_policy/blocked_destinations", TermAddress)}})
	routes := tp.Member("routes")
	switch {
	case !routes.Exists():
		o.add(Section{ID: "routes", Title: "Routes", Depth: 1, Fields: []Field{{Label: "routes", Pointer: "/transfer_policy/routes", Value: "(missing)", Missing: true}},
			Adds: []AddAction{routeAdd()}})
	case routes.Kind() != "array":
		o.add(Section{ID: "routes", Title: "Routes", Depth: 1, Pointer: routes.Pointer(), Fields: []Field{{Label: "routes", Pointer: routes.Pointer(), Value: render(routes), Note: "routes must be a list"}},
			Adds: []AddAction{replaceWith("Set routes to an empty list", "/transfer_policy/routes", "[]")}})
	default:
		s := Section{ID: "routes", Title: fmt.Sprintf("Routes (%d)", len(routes.Items())), Depth: 1, Pointer: routes.Pointer(), Adds: []AddAction{routeAdd()}}
		if len(routes.Items()) == 0 {
			s.Fields = []Field{{Label: "routes", Pointer: routes.Pointer(), Value: "(none)"}}
		}
		o.add(s)
		for i, r := range routes.Items() {
			o.route(i, r, cosigner)
		}
	}
	if other := unknownFields(tp, known, "a "+roleName(o.role)+" transfer_policy"); len(other) > 0 {
		o.add(Section{ID: "transfers_other", Title: "Other transfer fields", Depth: 1, Fields: other})
	}
}

func blockedFields(blocked policy.DraftNode) []Field {
	if !blocked.Exists() {
		return nil
	}
	return listFields("never to", blocked, TermAddress, &Removal{Label: "remove blocked_destinations", Pointer: blocked.Pointer()})
}

func routeAdd() AddAction {
	return AddAction{Label: "Add a route", Prompt: "route id (lowercase letters, digits, '_' or '-')", apply: func(d *policy.Draft, input string) (*policy.Draft, error) {
		if !validNetworkToken(input) {
			return nil, fmt.Errorf("a route id is lowercase letters, digits, '_' or '-'")
		}
		// A new route covers nothing until its fields are filled in: empty
		// lists, which check reports until they are.
		id, _ := json.Marshal(input)
		route := `{"id": ` + string(id) + `, "networks": [], "sources": [], "assets": [], "destinations": []}`
		if !d.At("/transfer_policy/routes").Exists() {
			return ensure(d, "/transfer_policy/routes", "["+route+"]")
		}
		return d.Insert("/transfer_policy/routes/-", []byte(route))
	}}
}

func missSummary(tp policy.DraftNode) string {
	if tp.Member("on_no_route").Text() == "reject" && tp.Member("close_on_no_route").Text() == "reject" && tp.Member("clawback_on_no_route").Text() == "reject" {
		return "allowlist: a transfer, close-out or clawback no route allows is rejected"
	}
	return "routes do not decide every transfer; see Miss actions"
}

var routeSpecs = []fieldSpec{
	{name: "id", label: "ID", required: true, edit: EditText},
	{name: "description", label: "Description", edit: EditText},
	{name: "networks", label: "Networks", note: `"*" for every network`, required: true, edit: EditTerms, term: TermNetwork},
	{name: "sources", label: "Sources", note: "senders the route covers", required: true, edit: EditTerms, term: TermSource},
	{name: "assets", label: "Assets", required: true, edit: EditTerms, term: TermAsset},
	{name: "destinations", label: "Destinations", required: true, edit: EditTerms, term: TermDestination},
	{name: "asset_sources", label: "Clawback from", edit: EditTerms, term: TermSource},
	{name: "allow_close", label: "Allow close-outs", kind: "bool", edit: EditBool},
	{name: "allow_clawback", label: "Allow clawbacks", kind: "bool", edit: EditBool},
}

func (o *outliner) route(i int, r policy.DraftNode, cosigner bool) {
	title := fmt.Sprintf("Route %d", i+1)
	if id := r.Member("id"); id.Kind() == "string" && id.Text() != "" {
		title = "Route " + id.Text()
	}
	s := Section{ID: fmt.Sprintf("route:%d", i), Title: title, Depth: 2, Pointer: r.Pointer(),
		Remove: &Removal{Label: "remove " + strings.ToLower(title), Pointer: r.Pointer()}}
	if r.Kind() != "object" {
		s.Fields = []Field{{Label: "route", Pointer: r.Pointer(), Value: render(r), Note: "a route must be an object"}}
		o.add(s)
		return
	}
	known := map[string]bool{"limits": true}
	for _, spec := range routeSpecs {
		known[spec.name] = true
	}
	s.Fields = o.fields(r, r.Pointer(), routeSpecs)
	for _, f := range o.limits(r.Member("limits"), r.Pointer()+"/limits", cosigner) {
		f.Label = "limit " + f.Label
		s.Fields = append(s.Fields, f)
	}
	s.Fields = append(s.Fields, unknownFields(r, known, "a route")...)
	s.Adds = []AddAction{limitAdd("Add a route limit", r.Pointer()+"/limits", cosigner)}
	o.add(s)
}

func (o *outliner) rekey(rp policy.DraftNode) []Field {
	if !rp.Exists() {
		return nil
	}
	allowed := rp.Member("allowed")
	if rp.Kind() != "object" || allowed.Kind() != "array" {
		return []Field{{Label: "rekey_policy", Pointer: rp.Pointer(), Value: render(rp), Remove: &Removal{Label: "remove rekey_policy", Pointer: rp.Pointer()}}}
	}
	var out []Field
	for i, edge := range allowed.Items() {
		label := fmt.Sprintf("Edge %d", i+1)
		gone := &Removal{Label: "remove " + strings.ToLower(label), Pointer: edge.Pointer()}
		if edge.Kind() != "object" {
			out = append(out, Field{Label: label, Pointer: edge.Pointer(), Value: render(edge), Remove: gone})
			continue
		}
		for _, part := range []struct {
			name string
			edit EditKind
		}{{"sender", EditTerm}, {"targets", EditTerms}} {
			n := edge.Member(part.name)
			out = append(out, Field{Label: label + " " + part.name, Pointer: edge.Pointer() + "/" + part.name, Value: render(n), Missing: !n.Exists(),
				Edit: &EditSpec{Kind: part.edit, Pointer: edge.Pointer() + "/" + part.name, Term: TermRekeyTarget}, Remove: gone})
		}
		out = append(out, unknownFields(edge, map[string]bool{"sender": true, "targets": true}, "a rekey edge")...)
	}
	if len(out) == 0 {
		out = []Field{{Label: "allowed", Pointer: allowed.Pointer(), Value: "(none: every rekey is rejected)"}}
	}
	out = append(out, unknownFields(rp, map[string]bool{"allowed": true}, "rekey_policy")...)
	return out
}

func rekeyEdgeAdd() AddAction {
	return AddAction{Label: "Add a rekey edge", Prompt: "sender: an address or @set", apply: func(d *policy.Draft, input string) (*policy.Draft, error) {
		if err := checkTerm(TermRekeyTarget, input); err != nil {
			return nil, err
		}
		v, _ := json.Marshal(input)
		edge := []byte(`{"sender": ` + string(v) + `, "targets": []}`)
		if !d.At("/rekey_policy/allowed").Exists() {
			return ensure(d, "/rekey_policy/allowed", "["+string(edge)+"]")
		}
		return d.Insert("/rekey_policy/allowed/-", edge)
	}}
}

// render shows a value the way the document holds it: strings and numbers as
// their text, booleans and null as written, arrays of scalars joined, and
// anything else as compact JSON.
func render(n policy.DraftNode) string {
	switch n.Kind() {
	case "":
		return "(missing)"
	case "string", "number":
		return n.Text()
	case "boolean":
		return strconv.FormatBool(n.Bool())
	case "null":
		return "null"
	case "array":
		items := n.Items()
		parts := make([]string, 0, len(items))
		for _, item := range items {
			if k := item.Kind(); k == "object" || k == "array" {
				return compact(n)
			}
			parts = append(parts, render(item))
		}
		if len(parts) == 0 {
			return "(none)"
		}
		return strings.Join(parts, ", ")
	}
	return compact(n)
}

// compact writes a value as one-line JSON.
func compact(n policy.DraftNode) string {
	var b strings.Builder
	var write func(n policy.DraftNode)
	write = func(n policy.DraftNode) {
		switch n.Kind() {
		case "string":
			b.WriteString(strconv.Quote(n.Text()))
		case "number":
			b.WriteString(n.Text())
		case "boolean":
			b.WriteString(strconv.FormatBool(n.Bool()))
		case "null":
			b.WriteString("null")
		case "array":
			b.WriteByte('[')
			for i, item := range n.Items() {
				if i > 0 {
					b.WriteString(", ")
				}
				write(item)
			}
			b.WriteByte(']')
		case "object":
			b.WriteByte('{')
			for i, k := range n.Keys() {
				if i > 0 {
					b.WriteString(", ")
				}
				b.WriteString(strconv.Quote(k) + ": ")
				write(n.Member(k))
			}
			b.WriteByte('}')
		}
	}
	write(n)
	return b.String()
}
