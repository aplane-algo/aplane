// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyauthor

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/strictjson"
)

// A cosigner document's external sources and checks: a section for the
// sources and one per source, a section for the checks and one per check,
// so every field of each is in view. A rule is edited as one JSON value.

var (
	externalScopes = []string{
		string(policy.ExternalScopeRequest), string(policy.ExternalScopeTransaction), string(policy.ExternalScopeMovement),
	}
	externalSourceSpecs = []fieldSpec{
		{name: "base_url", label: "Base URL", note: "https, or http on loopback", required: true, edit: EditText},
		{name: "timeout_ms", label: "Timeout (ms)", note: "2000 when not set", edit: EditInteger},
		{name: "max_response_bytes", label: "Answer cap (bytes)", note: "65536 when not set", edit: EditInteger},
		{name: "tls_spki_sha256", label: "Pinned server keys", note: "system roots when not set", edit: EditTerms, term: TermTLSPin},
	}
	externalTokenSpecs = []fieldSpec{
		{name: "header", label: "Token header", required: true, edit: EditText},
		{name: "prefix", label: "Token prefix", note: `e.g. "Bearer "`, edit: EditVerbatim},
	}
)

func (o *outliner) externalSources(sources policy.DraftNode) {
	head := Section{ID: "external_sources", Title: fmt.Sprintf("External sources (%d)", len(sources.Keys())), Pointer: "/external_sources",
		Adds: []AddAction{externalSourceAdd()}}
	if sources.Exists() && sources.Kind() != "object" {
		head.Title, head.Adds = "External sources", nil
		head.Fields = []Field{{Label: "external_sources", Pointer: sources.Pointer(), Value: render(sources), Note: "external_sources must be an object",
			Remove: &Removal{Label: "remove external_sources", Pointer: sources.Pointer()}}}
	}
	o.add(head)
	if sources.Kind() != "object" {
		return
	}
	for _, name := range sources.Keys() {
		o.externalSource(name, sources.Member(name))
	}
}

func (o *outliner) externalSource(name string, src policy.DraftNode) {
	s := Section{ID: "external_source:" + name, Title: "Source " + name, Depth: 1, Pointer: src.Pointer(),
		Remove: &Removal{Label: "remove source " + name, Pointer: src.Pointer()}}
	if src.Kind() != "object" {
		s.Fields = []Field{{Label: "source", Pointer: src.Pointer(), Value: render(src), Note: "a source must be an object"}}
		o.add(s)
		return
	}
	known := map[string]bool{"token": true}
	for _, spec := range externalSourceSpecs {
		known[spec.name] = true
	}
	s.Fields = o.fields(src, src.Pointer(), externalSourceSpecs[:1])
	s.Fields = append(s.Fields, o.externalToken(src)...)
	s.Fields = append(s.Fields, o.fields(src, src.Pointer(), externalSourceSpecs[1:])...)
	s.Fields = append(s.Fields, unknownFields(src, known, "an external source")...)
	if !src.Member("token").Exists() {
		s.Adds = []AddAction{externalTokenAdd(src.Pointer() + "/token")}
	}
	o.add(s)
}

// externalToken lays out a source's token: how it is sent, never the token.
func (o *outliner) externalToken(src policy.DraftNode) []Field {
	token := src.Member("token")
	pointer := src.Pointer() + "/token"
	gone := &Removal{Label: "remove the token", Pointer: pointer}
	switch {
	case !token.Exists():
		return []Field{{Label: "Token", Pointer: pointer, Value: "(not set)", Note: "no token is sent", Absent: true}}
	case token.Kind() != "object":
		return []Field{{Label: "Token", Pointer: pointer, Value: render(token), Note: "token must be an object", Remove: gone}}
	}
	fields := o.fields(token, pointer, externalTokenSpecs)
	// A token needs its header, so removing the header removes the token.
	fields[0].Remove = gone
	// The prefix is shown quoted, so a trailing space is seen.
	if prefix := token.Member("prefix"); prefix.Kind() == "string" {
		fields[1].Value = compactJSON(prefix)
	}
	return append(fields, unknownFields(token, map[string]bool{"header": true, "prefix": true}, "a token")...)
}

func (o *outliner) externalChecks(checks, sources policy.DraftNode) {
	head := Section{ID: "external_checks", Title: fmt.Sprintf("External checks (%d)", len(checks.Items())), Pointer: "/external_checks",
		Adds: []AddAction{externalCheckAdd()}}
	if checks.Exists() && checks.Kind() != "array" {
		head.Title, head.Adds = "External checks", nil
		head.Fields = []Field{{Label: "external_checks", Pointer: checks.Pointer(), Value: render(checks), Note: "external_checks must be a list",
			Remove: &Removal{Label: "remove external_checks", Pointer: checks.Pointer()}}}
	}
	o.add(head)
	for i, c := range checks.Items() {
		o.externalCheck(i, c, sources.Keys())
	}
}

func (o *outliner) externalCheck(i int, c policy.DraftNode, sourceNames []string) {
	title := fmt.Sprintf("Check %d", i+1)
	if id := c.Member("id"); id.Kind() == "string" && id.Text() != "" {
		title = "Check " + id.Text()
	}
	s := Section{ID: fmt.Sprintf("external_check:%d", i), Title: title, Depth: 1, Pointer: c.Pointer(),
		Remove: &Removal{Label: "remove " + strings.ToLower(title), Pointer: c.Pointer()}}
	if c.Kind() != "object" {
		s.Fields = []Field{{Label: "check", Pointer: c.Pointer(), Value: render(c), Note: "a check must be an object"}}
		o.add(s)
		return
	}
	source := fieldSpec{name: "source", label: "Source", required: true, edit: EditText}
	if len(sourceNames) > 0 {
		source.edit, source.choices = EditChoice, sourceNames
	}
	head := []fieldSpec{
		{name: "id", label: "ID", required: true, edit: EditText},
		{name: "description", label: "Description", edit: EditText},
		source,
		{name: "scope", label: "Scope", note: "one lookup per request, transaction or movement", required: true, edit: EditChoice, choices: externalScopes},
		{name: "networks", label: "Networks", note: `"*" for every network`, required: true, edit: EditTerms, term: TermNetwork},
	}
	// Movement kinds belong to a movement check; another scope shows them
	// only when the document has them, as an error to remove.
	if c.Member("scope").Text() == string(policy.ExternalScopeMovement) || c.Member("movement_kinds").Exists() {
		head = append(head, fieldSpec{name: "movement_kinds", label: "Movement kinds", note: "every kind when not set", edit: EditTerms, term: TermMovement})
	}
	head = append(head, fieldSpec{name: "path", label: "Path", note: "after the base URL's path", required: true, edit: EditText})
	echo := []fieldSpec{{name: "echo_pointer", label: "Echo pointer", note: "holds the request ID", edit: EditText}}

	known := map[string]bool{"query": true, "require": true}
	for _, spec := range append(append([]fieldSpec(nil), head...), echo...) {
		known[spec.name] = true
	}
	s.Fields = o.fields(c, c.Pointer(), head)
	s.Fields = append(s.Fields, externalQueryFields(c.Member("query"))...)
	s.Fields = append(s.Fields, o.fields(c, c.Pointer(), echo)...)
	s.Fields = append(s.Fields, externalRuleFields(c.Pointer()+"/require", c.Member("require"))...)
	s.Fields = append(s.Fields, unknownFields(c, known, "an external check")...)
	s.Adds = []AddAction{externalRuleAdd(c.Pointer() + "/require"), externalQueryAdd(c.Pointer() + "/query")}
	o.add(s)
}

// externalQueryFields gives each query parameter its own field. Removing the
// only one removes the query.
func externalQueryFields(query policy.DraftNode) []Field {
	switch {
	case !query.Exists():
		return nil
	case query.Kind() != "object":
		return []Field{{Label: "Query", Pointer: query.Pointer(), Value: render(query), Note: "query must be an object",
			Remove: &Removal{Label: "remove the query", Pointer: query.Pointer()}}}
	}
	names := query.Keys()
	if len(names) == 0 {
		return []Field{{Label: "Query", Pointer: query.Pointer(), Value: "(none)", Remove: &Removal{Label: "remove the query", Pointer: query.Pointer()}}}
	}
	var out []Field
	for _, name := range names {
		v := query.Member(name)
		gone := &Removal{Label: "remove query parameter " + name, Pointer: v.Pointer()}
		if len(names) == 1 {
			gone = &Removal{Label: "remove the query", Pointer: query.Pointer()}
		}
		out = append(out, Field{Label: "Query " + name, Pointer: v.Pointer(), Value: render(v),
			Edit: &EditSpec{Kind: EditText, Pointer: v.Pointer()}, Remove: gone})
	}
	return out
}

// externalRuleFields gives each rule its own field, edited as one JSON value
// and read out in words below it.
func externalRuleFields(pointer string, rules policy.DraftNode) []Field {
	switch {
	case !rules.Exists():
		return []Field{{Label: "Rules", Pointer: pointer, Value: "(missing)", Missing: true}}
	case rules.Kind() != "array":
		return []Field{{Label: "Rules", Pointer: pointer, Value: render(rules), Note: "require must be a list of rules",
			Edit: &EditSpec{Kind: EditJSON, Pointer: pointer}}}
	}
	items := rules.Items()
	if len(items) == 0 {
		return []Field{{Label: "Rules", Pointer: pointer, Value: "(none)"}}
	}
	out := make([]Field, 0, len(items))
	for j, rule := range items {
		label := fmt.Sprintf("Rule %d", j+1)
		out = append(out, Field{Label: label, Pointer: rule.Pointer(), Value: compactJSON(rule), Note: draftRuleWords(rule),
			Edit:   &EditSpec{Kind: EditJSON, Pointer: rule.Pointer()},
			Remove: &Removal{Label: "remove " + strings.ToLower(label), Pointer: rule.Pointer()},
			Copy:   duplicateItem("Copy "+strings.ToLower(label), pointer, j, rule)})
	}
	return out
}

// draftRuleWords reads a rule of a draft in words, or "" when it is not
// shaped like a rule.
func draftRuleWords(rule policy.DraftNode) string {
	pointer, op := rule.Member("pointer"), rule.Member("op")
	if pointer.Kind() != "string" || op.Kind() != "string" {
		return ""
	}
	r := policy.ExternalRuleV1{Pointer: pointer.Text(), Op: policy.ExternalOp(op.Text())}
	if r.Op == policy.ExternalOpPresent || r.Op == policy.ExternalOpAbsent {
		return externalRuleWords(r)
	}
	if _, ok := externalOpWords[r.Op]; !ok {
		return ""
	}
	operands := 0
	strs := func(n policy.DraftNode) ([]string, bool) {
		var out []string
		for _, item := range n.Items() {
			if item.Kind() != "string" {
				return nil, false
			}
			out = append(out, item.Text())
		}
		return out, n.Kind() == "array"
	}
	for _, name := range []string{"number", "string", "bool", "numbers", "strings", "fact"} {
		n := rule.Member(name)
		if !n.Exists() {
			continue
		}
		operands++
		ok := true
		switch name {
		case "number":
			text := n.Text()
			r.Number, ok = &text, n.Kind() == "string"
		case "string":
			text := n.Text()
			r.String, ok = &text, n.Kind() == "string"
		case "bool":
			b := n.Bool()
			r.Bool, ok = &b, n.Kind() == "boolean"
		case "numbers":
			r.Numbers, ok = strs(n)
		case "strings":
			r.Strings, ok = strs(n)
		case "fact":
			r.Fact, ok = n.Text(), n.Kind() == "string" && n.Text() != ""
		}
		if !ok {
			return ""
		}
	}
	if operands != 1 {
		return ""
	}
	return externalRuleWords(r)
}

func externalSourceAdd() AddAction {
	return AddAction{Label: "Add a source", Prompt: "name and base URL, e.g. ops http://127.0.0.1:8650", apply: func(d *policy.Draft, input string) (*policy.Draft, error) {
		parts := strings.Fields(input)
		if len(parts) != 2 || !validNetworkToken(parts[0]) {
			return nil, fmt.Errorf("enter a source name (lowercase letters, digits, '_' or '-') and its base URL")
		}
		u, _ := json.Marshal(parts[1])
		return ensure(d, "/external_sources/"+escapeToken(parts[0]), `{"base_url": `+string(u)+`}`)
	}}
}

func externalTokenAdd(pointer string) AddAction {
	return AddAction{Label: "Add a token", Prompt: "header that carries it, e.g. Authorization", apply: func(d *policy.Draft, input string) (*policy.Draft, error) {
		if input == "" || strings.ContainsAny(input, " \t:") {
			return nil, fmt.Errorf("enter a header name, e.g. Authorization or X-Api-Key")
		}
		h, _ := json.Marshal(input)
		return ensure(d, pointer, `{"header": `+string(h)+`}`)
	}}
}

func externalCheckAdd() AddAction {
	return AddAction{Label: "Add a check", Prompt: "check id and the source it asks, e.g. ops-switch ops", apply: func(d *policy.Draft, input string) (*policy.Draft, error) {
		parts := strings.Fields(input)
		if len(parts) != 2 || !validNetworkToken(parts[0]) || !validNetworkToken(parts[1]) {
			return nil, fmt.Errorf("enter a check id and a source name (lowercase letters, digits, '_' or '-')")
		}
		// A new check covers no network and requires nothing until its
		// fields are filled in, which check reports until they are.
		id, _ := json.Marshal(parts[0])
		source, _ := json.Marshal(parts[1])
		check := `{"id": ` + string(id) + `, "source": ` + string(source) + `, "scope": "request", "networks": [], "path": "/", "require": []}`
		if !d.At("/external_checks").Exists() {
			return ensure(d, "/external_checks", "["+check+"]")
		}
		return d.Insert("/external_checks/-", []byte(check))
	}}
}

func externalRuleAdd(pointer string) AddAction {
	return AddAction{Label: "Add a rule", Prompt: `JSON Pointer into the answer, e.g. /enabled; edit the rule from there`, apply: func(d *policy.Draft, input string) (*policy.Draft, error) {
		if err := strictjson.ValidatePointer(input); err != nil {
			return nil, err
		}
		p, _ := json.Marshal(input)
		rule := `{"pointer": ` + string(p) + `, "op": "present"}`
		if !d.At(pointer).Exists() {
			return ensure(d, pointer, "["+rule+"]")
		}
		return d.Insert(pointer+"/-", []byte(rule))
	}}
}

func externalQueryAdd(pointer string) AddAction {
	return AddAction{Label: "Add a query parameter", Prompt: "name=value, e.g. chain=algorand", apply: func(d *policy.Draft, input string) (*policy.Draft, error) {
		name, value, ok := strings.Cut(input, "=")
		if name = strings.TrimSpace(name); !ok || name == "" {
			return nil, fmt.Errorf("enter name=value")
		}
		v, _ := json.Marshal(strings.TrimSpace(value))
		return ensure(d, pointer+"/"+escapeToken(name), string(v))
	}}
}
