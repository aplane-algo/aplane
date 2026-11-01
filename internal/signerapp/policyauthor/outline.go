// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyauthor

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
)

// Section is one entry of a document's outline: a part of the document and
// the fields shown for it. Sections are a flat list in display order; Depth
// nests them (a route under Routes).
type Section struct {
	ID      string
	Title   string
	Depth   int
	Pointer string
	Fields  []Field
	// Problems are those that belong to the section but to none of its
	// fields, such as a document error with no pointer.
	Problems []Problem
}

// Field is one row of a section's form: a value as the document holds it,
// shown for reading. Missing marks a field the role requires that the
// document lacks; Unknown marks a member the format does not define.
type Field struct {
	Label    string
	Pointer  string
	Value    string
	Note     string
	Missing  bool
	Unknown  bool
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

// Outline lays out a file's document as sections of read-only fields, with
// problems attached to the field their pointer names. It works on a document
// that does not decode: every member is shown, fields the role requires and
// the document lacks are marked missing, and members the format does not
// define are listed under "Other fields". An unreadable or unparsable file is
// one section holding its problems. lookup supplies ASA metadata for display
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
	if f.Pointer == "" {
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

// fieldSpec is one field the format defines on an object.
type fieldSpec struct {
	name, label, note string
	required          bool
	kind              string // "bool", "amount", "miss", or "" for a plain value
}

func (o *outliner) build() {
	root := o.draft.Root()
	if root.Kind() != "object" {
		o.add(Section{ID: "document", Title: "Document", Fields: []Field{{Label: "document", Pointer: "", Value: render(root), Note: "a policy document must be a JSON object"}}})
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
		{name: "format", label: "Format", required: true},
		{name: "role", label: "Role", required: true},
		{name: "key", label: "Key", note: `"default", or the key this document governs`, required: true},
		{name: "description", label: "Description"},
	}))})

	guards := []fieldSpec{
		{name: "reject_close_remainder", label: "Reject ALGO close-outs", note: "always deny", required: true, kind: "bool"},
		{name: "reject_asset_close", label: "Reject ASA close-outs", note: "always deny", required: true, kind: "bool"},
		{name: "reject_clawback", label: "Reject clawbacks", note: "always deny", required: true, kind: "bool"},
	}
	if cosigner {
		guards = append(guards, fieldSpec{name: "reject_rekey", label: "Reject every rekey", note: "always deny; when no, rekey_policy decides", required: true, kind: "bool"})
	} else {
		guards = append([]fieldSpec{{name: "reject_foreign_rekey", label: "Reject rekeys to keys this node does not hold", note: "always deny", required: true, kind: "bool"}}, guards...)
		guards = append(guards,
			fieldSpec{name: "always_review_warnings", label: "Send warnings to review", note: "always review", required: true, kind: "bool"},
			fieldSpec{name: "auto_approve_self_noop_transfer", label: "Self no-op auto-approval", note: "always approve, after deny and review rules", required: true, kind: "bool"},
		)
	}
	o.add(Section{ID: "guards", Title: "Guards", Fields: o.fields(root, "", use(guards))})

	o.add(Section{ID: "fee", Title: "Fee cap", Fields: o.fields(root, "", use([]fieldSpec{
		{name: "max_fee_microalgos", label: "Maximum fee", note: `"0" is no cap`, required: true, kind: "fee"},
	}))})

	known["transaction_types"] = true
	o.add(Section{ID: "types", Title: "Transaction types", Pointer: "/transaction_types", Fields: o.transactionTypes(root.Member("transaction_types"), cosigner)})

	known["limits"] = true
	if limits := root.Member("limits"); limits.Exists() {
		o.add(Section{ID: "limits", Title: "Limits", Pointer: "/limits", Fields: o.limits(limits)})
	}
	known["address_sets"] = true
	if sets := root.Member("address_sets"); sets.Exists() {
		o.add(Section{ID: "address_sets", Title: fmt.Sprintf("Address sets (%d)", len(sets.Keys())), Pointer: "/address_sets", Fields: o.addressSets(sets)})
	}
	known["asset_sets"] = true
	if sets := root.Member("asset_sets"); sets.Exists() {
		o.add(Section{ID: "asset_sets", Title: fmt.Sprintf("Asset sets (%d)", len(sets.Keys())), Pointer: "/asset_sets", Fields: o.assetSets(sets)})
	}

	known["transfer_policy"] = true
	o.transfers(root.Member("transfer_policy"), cosigner)

	if cosigner {
		known["rekey_policy"] = true
		if rp := root.Member("rekey_policy"); rp.Exists() {
			o.add(Section{ID: "rekey", Title: "Rekey edges", Pointer: "/rekey_policy", Fields: o.rekey(rp)})
		}
	}

	var other []Field
	for _, k := range root.Keys() {
		if !known[k] {
			n := root.Member(k)
			other = append(other, Field{Label: k, Pointer: n.Pointer(), Value: render(n), Unknown: true, Note: "not a field of a " + roleName(o.role) + " document"})
		}
	}
	if len(other) > 0 {
		o.add(Section{ID: "other", Title: "Other fields", Fields: other})
	}
}

func roleName(r noderole.Role) string {
	if r == "" {
		return "policy"
	}
	return string(r)
}

// fields lays out the named members of object node at pointer base.
func (o *outliner) fields(node policy.DraftNode, base string, specs []fieldSpec) []Field {
	var out []Field
	for _, s := range specs {
		m := node.Member(s.name)
		f := Field{Label: s.label, Pointer: base + "/" + escapeToken(s.name), Note: s.note}
		switch {
		case !m.Exists() && s.required:
			f.Missing, f.Value = true, "(missing)"
		case !m.Exists():
			continue
		default:
			f.Value = o.value(m, s.kind, "")
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
	var out []Field
	for _, k := range types.Keys() {
		label := k
		if k == policy.TransactionTypeWildcard {
			label = "* (any other type)"
		}
		out = append(out, Field{Label: label, Pointer: types.Member(k).Pointer(), Value: render(types.Member(k))})
	}
	if cosigner && !types.Member(policy.TransactionTypeWildcard).Exists() {
		out = append(out, Field{Label: "* (any other type)", Value: "reject", Note: "omitted; a cosigner rejects every type the map does not name"})
	}
	return out
}

// limits lays out network -> asset -> thresholds, one field per asset.
func (o *outliner) limits(limits policy.DraftNode) []Field {
	if limits.Kind() != "object" {
		return []Field{{Label: "limits", Pointer: limits.Pointer(), Value: render(limits)}}
	}
	var out []Field
	for _, network := range limits.Keys() {
		assets := limits.Member(network)
		if assets.Kind() != "object" {
			out = append(out, Field{Label: network, Pointer: assets.Pointer(), Value: render(assets)})
			continue
		}
		for _, asset := range assets.Keys() {
			t := assets.Member(asset)
			out = append(out, Field{Label: network + " " + o.assetLabel(network, asset), Pointer: t.Pointer(), Value: o.thresholds(network, asset, t)})
		}
	}
	return out
}

func (o *outliner) thresholds(network, asset string, t policy.DraftNode) string {
	if t.Kind() != "object" {
		return render(t)
	}
	ref, ok := parseAssetRef(asset)
	var parts []string
	for _, k := range t.Keys() {
		v := t.Member(k)
		label := strings.ReplaceAll(k, "_", " ")
		if ok && v.Kind() == "string" && (k == "review_above" || k == "reject_above") {
			parts = append(parts, label+" "+o.amount(network, ref, v.Text()))
		} else {
			parts = append(parts, label+" "+render(v))
		}
	}
	return strings.Join(parts, ", ")
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
	if sets.Kind() != "object" {
		return []Field{{Label: "address_sets", Pointer: sets.Pointer(), Value: render(sets)}}
	}
	var out []Field
	for _, name := range sets.Keys() {
		set := sets.Member(name)
		switch set.Kind() {
		case "array":
			out = append(out, listFields("@"+name+" (every network)", set)...)
		case "object":
			for _, network := range set.Keys() {
				out = append(out, listFields("@"+name+" "+network, set.Member(network))...)
			}
		default:
			out = append(out, Field{Label: "@" + name, Pointer: set.Pointer(), Value: render(set)})
		}
	}
	return out
}

func (o *outliner) assetSets(sets policy.DraftNode) []Field {
	if sets.Kind() != "object" {
		return []Field{{Label: "asset_sets", Pointer: sets.Pointer(), Value: render(sets)}}
	}
	var out []Field
	for _, name := range sets.Keys() {
		set := sets.Member(name)
		if set.Kind() != "object" {
			out = append(out, Field{Label: "@" + name, Pointer: set.Pointer(), Value: render(set)})
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
			}
			out = append(out, Field{Label: "@" + name + " " + network, Pointer: list.Pointer(), Value: value})
		}
	}
	return out
}

// listFields gives each item of an array its own field, so every member is
// on screen with its own pointer.
func listFields(label string, list policy.DraftNode) []Field {
	if list.Kind() != "array" {
		return []Field{{Label: label, Pointer: list.Pointer(), Value: render(list)}}
	}
	items := list.Items()
	if len(items) == 0 {
		return []Field{{Label: label, Pointer: list.Pointer(), Value: "(none)"}}
	}
	out := make([]Field, 0, len(items))
	for _, item := range items {
		out = append(out, Field{Label: label, Pointer: item.Pointer(), Value: render(item)})
	}
	return out
}

func (o *outliner) transfers(tp policy.DraftNode, cosigner bool) {
	head := o.add(Section{ID: "transfers", Title: "Transfers", Pointer: "/transfer_policy"})
	if !tp.Exists() {
		o.sections[head].Fields = []Field{{Label: "transfer_policy", Pointer: "/transfer_policy", Value: "(missing)", Missing: true}}
		return
	}
	if tp.Kind() != "object" {
		o.sections[head].Fields = []Field{{Label: "transfer_policy", Pointer: tp.Pointer(), Value: render(tp)}}
		return
	}
	known := map[string]bool{"blocked_destinations": true, "routes": true}
	if !cosigner {
		specs := []fieldSpec{
			{name: "on_no_route", label: "Transfer no route allows", required: true, kind: "miss"},
			{name: "close_on_no_route", label: "Close-out no route allows", required: true, kind: "miss"},
			{name: "clawback_on_no_route", label: "Clawback no route allows", required: true, kind: "miss"},
		}
		for _, s := range specs {
			known[s.name] = true
		}
		o.sections[head].Fields = append(o.sections[head].Fields, Field{Label: "Summary", Value: missSummary(tp)})
		o.add(Section{ID: "miss", Title: "Miss actions", Depth: 1, Fields: o.fields(tp, "/transfer_policy", specs)})
	} else {
		o.sections[head].Fields = append(o.sections[head].Fields, Field{Label: "Summary", Value: "allowlist: a transfer no route allows is rejected"})
	}
	if blocked := tp.Member("blocked_destinations"); blocked.Exists() {
		o.add(Section{ID: "blocked", Title: fmt.Sprintf("Blocked destinations (%d)", len(blocked.Items())), Depth: 1, Pointer: blocked.Pointer(), Fields: listFields("never to", blocked)})
	}
	routes := tp.Member("routes")
	switch {
	case !routes.Exists():
		o.add(Section{ID: "routes", Title: "Routes", Depth: 1, Fields: []Field{{Label: "routes", Pointer: "/transfer_policy/routes", Value: "(missing)", Missing: true}}})
	case routes.Kind() != "array":
		o.add(Section{ID: "routes", Title: "Routes", Depth: 1, Pointer: routes.Pointer(), Fields: []Field{{Label: "routes", Pointer: routes.Pointer(), Value: render(routes)}}})
	default:
		s := Section{ID: "routes", Title: fmt.Sprintf("Routes (%d)", len(routes.Items())), Depth: 1, Pointer: routes.Pointer()}
		if len(routes.Items()) == 0 {
			s.Fields = []Field{{Label: "routes", Pointer: routes.Pointer(), Value: "(none)"}}
		}
		o.add(s)
		for i, r := range routes.Items() {
			o.route(i, r)
		}
	}
	var other []Field
	for _, k := range tp.Keys() {
		if !known[k] {
			n := tp.Member(k)
			other = append(other, Field{Label: k, Pointer: n.Pointer(), Value: render(n), Unknown: true, Note: "not a field of a " + roleName(o.role) + " transfer_policy"})
		}
	}
	if len(other) > 0 {
		o.add(Section{ID: "transfers_other", Title: "Other transfer fields", Depth: 1, Fields: other})
	}
}

func missSummary(tp policy.DraftNode) string {
	if tp.Member("on_no_route").Text() == "reject" && tp.Member("close_on_no_route").Text() == "reject" && tp.Member("clawback_on_no_route").Text() == "reject" {
		return "allowlist: a transfer, close-out or clawback no route allows is rejected"
	}
	return "routes do not decide every transfer; see Miss actions"
}

var routeSpecs = []fieldSpec{
	{name: "id", label: "ID", required: true},
	{name: "description", label: "Description"},
	{name: "networks", label: "Networks", required: true},
	{name: "sources", label: "Sources", note: "senders the route covers", required: true},
	{name: "assets", label: "Assets", required: true},
	{name: "destinations", label: "Destinations", required: true},
	{name: "asset_sources", label: "Clawback from"},
	{name: "allow_close", label: "Allow close-outs", kind: "bool"},
	{name: "allow_clawback", label: "Allow clawbacks", kind: "bool"},
}

func (o *outliner) route(i int, r policy.DraftNode) {
	title := fmt.Sprintf("Route %d", i+1)
	if id := r.Member("id"); id.Kind() == "string" && id.Text() != "" {
		title = "Route " + id.Text()
	}
	s := Section{ID: fmt.Sprintf("route:%d", i), Title: title, Depth: 2, Pointer: r.Pointer()}
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
	if limits := r.Member("limits"); limits.Exists() {
		for _, f := range o.limits(limits) {
			f.Label = "limit " + f.Label
			s.Fields = append(s.Fields, f)
		}
	}
	for _, k := range r.Keys() {
		if !known[k] {
			n := r.Member(k)
			s.Fields = append(s.Fields, Field{Label: k, Pointer: n.Pointer(), Value: render(n), Unknown: true, Note: "not a field of a route"})
		}
	}
	o.add(s)
}

func (o *outliner) rekey(rp policy.DraftNode) []Field {
	allowed := rp.Member("allowed")
	if rp.Kind() != "object" || allowed.Kind() != "array" {
		return []Field{{Label: "rekey_policy", Pointer: rp.Pointer(), Value: render(rp)}}
	}
	var out []Field
	for i, edge := range allowed.Items() {
		label := fmt.Sprintf("Edge %d", i+1)
		if edge.Kind() != "object" {
			out = append(out, Field{Label: label, Pointer: edge.Pointer(), Value: render(edge)})
			continue
		}
		for _, part := range []string{"sender", "targets"} {
			n := edge.Member(part)
			out = append(out, Field{Label: label + " " + part, Pointer: edge.Pointer() + "/" + part, Value: render(n), Missing: !n.Exists()})
		}
		for _, k := range edge.Keys() {
			if k != "sender" && k != "targets" {
				n := edge.Member(k)
				out = append(out, Field{Label: k, Pointer: n.Pointer(), Value: render(n), Unknown: true, Note: "not a field of a rekey edge"})
			}
		}
	}
	if len(out) == 0 {
		out = []Field{{Label: "allowed", Pointer: allowed.Pointer(), Value: "(none: every rekey is rejected)"}}
	}
	return out
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
