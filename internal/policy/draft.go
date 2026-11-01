// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"bytes"
	"encoding/json"
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
		"reject_foreign_rekey", "reject_close_remainder", "reject_asset_close",
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
