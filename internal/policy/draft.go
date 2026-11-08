// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// Draft is a policy document as parsed JSON, whether or not it is valid
// policy. It is what an editor holds: a document with a missing field, a
// wrong-typed value, an invalid address or an unknown field is still a
// Draft, and nothing in it is dropped. Input that is not strict JSON (a
// syntax error, a duplicate key, trailing data, or a size or depth over the
// decoder's limits) is not a Draft: ParseDraft rejects it, as the decoder
// would.
type Draft struct {
	root *jsonNode
}

// ParseDraft parses data with the decoder's own parser, so the editor and the
// decoder agree on every limit and on JSON Pointer locations.
func ParseDraft(data []byte) (*Draft, error) {
	root, err := parseJSONTree(data)
	if err != nil {
		return nil, err
	}
	return &Draft{root: root}, nil
}

// TopLevelString returns the document's top-level member name when it is
// present and a string. It reads a draft that may not decode, such as one
// whose "key" or "role" is the only thing an editor can identify it by.
func (d *Draft) TopLevelString(name string) (string, bool) {
	if d.root.kind != nodeObject {
		return "", false
	}
	member := d.root.members[name]
	if member == nil || member.kind != nodeString {
		return "", false
	}
	return member.text, true
}

// Canonical returns the draft in canonical form: two-space indentation, one
// value per line, and the fields of each policy object in the order the
// decoder reads them, with any unknown fields kept after them in their
// original order. Members of map-like objects (transaction types, limits,
// sets) keep their original order. Number literals are written as parsed,
// never through float64. Formatting canonical output again returns the same
// bytes, and decoding it gives the same document and the same errors as the
// input. Output larger than the decoder accepts is an error.
func (d *Draft) Canonical() ([]byte, error) {
	var b bytes.Buffer
	if err := writeCanonical(&b, d.root, ctxRoot, ""); err != nil {
		return nil, err
	}
	b.WriteByte('\n')
	if b.Len() > maxPolicyDocumentBytes {
		return nil, docErrorf("", "canonical form is %d bytes, larger than the %d-byte limit", b.Len(), maxPolicyDocumentBytes)
	}
	return b.Bytes(), nil
}

// canonicalContext says what a value is in a policy document, which decides
// the order of an object's members and the context of its children.
type canonicalContext int

const (
	ctxGeneric canonicalContext = iota
	ctxRoot
	ctxLimits
	ctxNetworkLimits
	ctxThresholds
	ctxTransferPolicy
	ctxRoutes
	ctxRoute
	ctxRekeyPolicy
	ctxRekeyRules
	ctxRekeyRule
)

// canonicalFieldOrder lists, for each policy object, its fields in the order
// the decoder reads them (doc_v1.go). Fields of both roles are listed; a
// document carries only its own role's. TestCanonicalFieldOrderMatchesSchema
// keeps these lists equal to the schema's.
var canonicalFieldOrder = map[canonicalContext][]string{
	ctxRoot: {
		"format", "role", "key", "description",
		"rekeys", "reject_close_remainder", "reject_asset_close",
		"reject_clawback", "reject_rekey", "always_review_warnings",
		"auto_approve_self_noop_transfer", "max_fee_microalgos",
		"transaction_types", "limits", "address_sets", "asset_sets",
		"transfer_policy", "rekey_policy",
	},
	ctxTransferPolicy: {
		"on_no_route", "close_on_no_route", "clawback_on_no_route",
		"blocked_destinations", "routes",
	},
	ctxRoute: {
		"id", "description", "networks", "sources", "assets", "destinations",
		"asset_sources", "limits", "allow_close", "allow_clawback",
	},
	ctxThresholds:  {"review_above", "reject_above"},
	ctxRekeyPolicy: {"allowed"},
	ctxRekeyRule:   {"sender", "targets"},
}

// childContext is the context of a member or item of a value in ctx.
func childContext(ctx canonicalContext, key string) canonicalContext {
	switch ctx {
	case ctxRoot:
		switch key {
		case "limits":
			return ctxLimits
		case "transfer_policy":
			return ctxTransferPolicy
		case "rekey_policy":
			return ctxRekeyPolicy
		}
	case ctxLimits:
		return ctxNetworkLimits
	case ctxNetworkLimits:
		return ctxThresholds
	case ctxTransferPolicy:
		if key == "routes" {
			return ctxRoutes
		}
	case ctxRoutes:
		return ctxRoute
	case ctxRoute:
		if key == "limits" {
			return ctxLimits
		}
	case ctxRekeyPolicy:
		if key == "allowed" {
			return ctxRekeyRules
		}
	case ctxRekeyRules:
		return ctxRekeyRule
	}
	return ctxGeneric
}

// canonicalKeys returns an object's member names in canonical order.
func canonicalKeys(node *jsonNode, ctx canonicalContext) []string {
	order, ok := canonicalFieldOrder[ctx]
	if !ok {
		return node.keys
	}
	keys := make([]string, 0, len(node.keys))
	known := make(map[string]bool, len(order))
	for _, key := range order {
		known[key] = true
		if _, present := node.members[key]; present {
			keys = append(keys, key)
		}
	}
	for _, key := range node.keys {
		if !known[key] {
			keys = append(keys, key)
		}
	}
	return keys
}

func writeCanonical(b *bytes.Buffer, node *jsonNode, ctx canonicalContext, indent string) error {
	switch node.kind {
	case nodeNull:
		b.WriteString("null")
	case nodeBool:
		if node.boolean {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case nodeNumber:
		b.WriteString(node.text)
	case nodeString:
		return writeJSONString(b, node.text)
	case nodeObject:
		if len(node.keys) == 0 {
			b.WriteString("{}")
			return nil
		}
		inner := indent + "  "
		b.WriteString("{\n")
		for i, key := range canonicalKeys(node, ctx) {
			b.WriteString(inner)
			if err := writeJSONString(b, key); err != nil {
				return err
			}
			b.WriteString(": ")
			if err := writeCanonical(b, node.members[key], childContext(ctx, key), inner); err != nil {
				return err
			}
			if i < len(node.keys)-1 {
				b.WriteByte(',')
			}
			b.WriteByte('\n')
		}
		b.WriteString(indent + "}")
	case nodeArray:
		if len(node.items) == 0 {
			b.WriteString("[]")
			return nil
		}
		inner := indent + "  "
		b.WriteString("[\n")
		for i, item := range node.items {
			b.WriteString(inner)
			if err := writeCanonical(b, item, childContext(ctx, ""), inner); err != nil {
				return err
			}
			if i < len(node.items)-1 {
				b.WriteByte(',')
			}
			b.WriteByte('\n')
		}
		b.WriteString(indent + "]")
	}
	return nil
}

// writeJSONString writes s as a JSON string without HTML escaping, so the
// output differs from the input only where the input used an optional escape.
func writeJSONString(b *bytes.Buffer, s string) error {
	var out strings.Builder
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return err
	}
	b.WriteString(strings.TrimSuffix(out.String(), "\n"))
	return nil
}

// DraftNode is one value in a Draft, for reading. The zero DraftNode stands
// for an absent value: Exists reports false and every accessor returns its
// zero value, so a caller can walk a broken document without checking each
// step.
type DraftNode struct {
	n *jsonNode
}

// Root returns the document's top-level value.
func (d *Draft) Root() DraftNode { return DraftNode{n: d.root} }

// At returns the value a JSON Pointer (RFC 6901) names, or an absent node.
func (d *Draft) At(pointer string) DraftNode {
	if pointer == "" {
		return d.Root()
	}
	if !strings.HasPrefix(pointer, "/") {
		return DraftNode{}
	}
	node := d.Root()
	for _, token := range strings.Split(pointer[1:], "/") {
		token = strings.ReplaceAll(strings.ReplaceAll(token, "~1", "/"), "~0", "~")
		switch node.Kind() {
		case "object":
			node = node.Member(token)
		case "array":
			i, err := strconv.Atoi(token)
			items := node.Items()
			if err != nil || i < 0 || i >= len(items) || strconv.Itoa(i) != token {
				return DraftNode{}
			}
			node = items[i]
		default:
			return DraftNode{}
		}
	}
	return node
}

// Exists reports whether the node stands for a value in the document.
func (n DraftNode) Exists() bool { return n.n != nil }

// Kind is "null", "boolean", "number", "string", "object" or "array", or ""
// for an absent node.
func (n DraftNode) Kind() string {
	if n.n == nil {
		return ""
	}
	return n.n.kind.String()
}

// Pointer is the node's JSON Pointer in the document.
func (n DraftNode) Pointer() string {
	if n.n == nil {
		return ""
	}
	return n.n.pointer
}

// Text is a string's value or a number's literal text.
func (n DraftNode) Text() string {
	if n.n == nil {
		return ""
	}
	return n.n.text
}

// Bool is a boolean's value.
func (n DraftNode) Bool() bool { return n.n != nil && n.n.boolean }

// Keys returns an object's member names in document order.
func (n DraftNode) Keys() []string {
	if n.n == nil {
		return nil
	}
	return append([]string(nil), n.n.keys...)
}

// Member returns an object's member, or an absent node.
func (n DraftNode) Member(key string) DraftNode {
	if n.n == nil || n.n.kind != nodeObject {
		return DraftNode{}
	}
	if m := n.n.members[key]; m != nil {
		return DraftNode{n: m}
	}
	return DraftNode{}
}

// Items returns an array's items.
func (n DraftNode) Items() []DraftNode {
	if n.n == nil || n.n.kind != nodeArray {
		return nil
	}
	out := make([]DraftNode, len(n.n.items))
	for i, item := range n.n.items {
		out[i] = DraftNode{n: item}
	}
	return out
}

// Edits. Each returns a new Draft and leaves the receiver unchanged, so an
// editor can keep earlier drafts for undo. A value is given as JSON text and
// parsed with the decoder's parser, so an edit can make a document invalid
// policy but never invalid JSON.

// Set replaces the value at pointer, or adds a member when pointer names a
// member its parent object lacks (appended after the existing members).
func (d *Draft) Set(pointer string, value []byte) (*Draft, error) {
	v, err := parseEditValue(value)
	if err != nil {
		return nil, err
	}
	if pointer == "" {
		return newEditedDraft(v)
	}
	return d.edit(pointer, func(parent *jsonNode, token string) error {
		switch parent.kind {
		case nodeObject:
			if _, ok := parent.members[token]; !ok {
				parent.keys = append(parent.keys, token)
			}
			parent.members[token] = v
		case nodeArray:
			i, err := arrayIndex(token, len(parent.items))
			if err != nil {
				return err
			}
			parent.items[i] = v
		default:
			return fmt.Errorf("cannot set a member of a %s", parent.kind)
		}
		return nil
	})
}

// Insert adds value to an array at the index pointer's last token names
// (0 through the length), or at the end for "-".
func (d *Draft) Insert(pointer string, value []byte) (*Draft, error) {
	v, err := parseEditValue(value)
	if err != nil {
		return nil, err
	}
	return d.edit(pointer, func(parent *jsonNode, token string) error {
		if parent.kind != nodeArray {
			return fmt.Errorf("cannot insert into a %s", parent.kind)
		}
		i := len(parent.items)
		if token != "-" {
			if i, err = arrayIndex(token, len(parent.items)+1); err != nil {
				return err
			}
		}
		parent.items = append(parent.items, nil)
		copy(parent.items[i+1:], parent.items[i:])
		parent.items[i] = v
		return nil
	})
}

// Remove deletes the object member or array item at pointer.
func (d *Draft) Remove(pointer string) (*Draft, error) {
	return d.edit(pointer, func(parent *jsonNode, token string) error {
		switch parent.kind {
		case nodeObject:
			if _, ok := parent.members[token]; !ok {
				return fmt.Errorf("no member %q to remove", token)
			}
			delete(parent.members, token)
			parent.keys = slices.DeleteFunc(parent.keys, func(k string) bool { return k == token })
		case nodeArray:
			i, err := arrayIndex(token, len(parent.items))
			if err != nil {
				return err
			}
			parent.items = slices.Delete(parent.items, i, i+1)
		default:
			return fmt.Errorf("cannot remove a member of a %s", parent.kind)
		}
		return nil
	})
}

// Rename gives the object member at pointer a new name, keeping its place in
// the member order. Renaming onto an existing member is an error.
func (d *Draft) Rename(pointer, name string) (*Draft, error) {
	return d.edit(pointer, func(parent *jsonNode, token string) error {
		if parent.kind != nodeObject {
			return fmt.Errorf("cannot rename a member of a %s", parent.kind)
		}
		v, ok := parent.members[token]
		if !ok {
			return fmt.Errorf("no member %q to rename", token)
		}
		if name == token {
			return nil
		}
		if _, taken := parent.members[name]; taken {
			return fmt.Errorf("a member named %q already exists", name)
		}
		delete(parent.members, token)
		parent.members[name] = v
		for i, k := range parent.keys {
			if k == token {
				parent.keys[i] = name
			}
		}
		return nil
	})
}

// edit applies change to a copy of the draft at the parent of pointer, then
// recomputes every node's pointer and checks the nesting limit.
func (d *Draft) edit(pointer string, change func(parent *jsonNode, token string) error) (*Draft, error) {
	if pointer == "" || !strings.HasPrefix(pointer, "/") {
		return nil, fmt.Errorf("pointer %q does not name a member or item", pointer)
	}
	root := cloneNode(d.root)
	tokens := strings.Split(pointer[1:], "/")
	for i, t := range tokens {
		tokens[i] = strings.ReplaceAll(strings.ReplaceAll(t, "~1", "/"), "~0", "~")
	}
	parent := root
	for _, t := range tokens[:len(tokens)-1] {
		switch parent.kind {
		case nodeObject:
			parent = parent.members[t]
		case nodeArray:
			i, err := arrayIndex(t, len(parent.items))
			if err != nil {
				return nil, fmt.Errorf("%s: %w", pointer, err)
			}
			parent = parent.items[i]
		default:
			parent = nil
		}
		if parent == nil {
			return nil, fmt.Errorf("%s: no such value", pointer)
		}
	}
	if err := change(parent, tokens[len(tokens)-1]); err != nil {
		return nil, fmt.Errorf("%s: %w", pointer, err)
	}
	return newEditedDraft(root)
}

func newEditedDraft(root *jsonNode) (*Draft, error) {
	if depth := setPointers(root, "", 0); depth > maxPolicyDocumentDepth {
		return nil, docErrorf("", "nesting deeper than %d levels", maxPolicyDocumentDepth)
	}
	return &Draft{root: root}, nil
}

// parseEditValue parses a value given as JSON text.
func parseEditValue(value []byte) (*jsonNode, error) {
	v, err := parseJSONTree(value)
	if err != nil {
		var docErr *DocumentError
		if errors.As(err, &docErr) {
			return nil, fmt.Errorf("value: %s", docErr.Msg)
		}
		return nil, err
	}
	return v, nil
}

func arrayIndex(token string, n int) (int, error) {
	i, err := strconv.Atoi(token)
	if err != nil || i < 0 || i >= n || strconv.Itoa(i) != token {
		return 0, fmt.Errorf("index %q is out of range", token)
	}
	return i, nil
}

func cloneNode(n *jsonNode) *jsonNode {
	c := *n
	if n.members != nil {
		c.keys = append([]string(nil), n.keys...)
		c.members = make(map[string]*jsonNode, len(n.members))
		for k, m := range n.members {
			c.members[k] = cloneNode(m)
		}
	}
	if n.items != nil {
		c.items = make([]*jsonNode, len(n.items))
		for i, item := range n.items {
			c.items[i] = cloneNode(item)
		}
	}
	return &c
}

// setPointers gives every node its pointer and returns the nesting depth.
func setPointers(n *jsonNode, pointer string, depth int) int {
	n.pointer = pointer
	deepest := depth
	for _, k := range n.keys {
		deepest = max(deepest, setPointers(n.members[k], pointer+"/"+escapeJSONPointer(k), depth+1))
	}
	for i, item := range n.items {
		deepest = max(deepest, setPointers(item, pointer+"/"+strconv.Itoa(i), depth+1))
	}
	return deepest
}
