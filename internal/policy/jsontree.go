// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"errors"
	"fmt"

	"github.com/aplane-algo/aplane/internal/strictjson"
)

const (
	maxPolicyDocumentBytes = 1 << 20
	maxPolicyDocumentDepth = 32
)

// DocumentError is a policy document rejection located by JSON Pointer
// (RFC 6901). Pointer is "" for the document as a whole.
type DocumentError struct {
	Pointer string
	Msg     string
}

func (e *DocumentError) Error() string {
	if e.Pointer == "" {
		return "policy document: " + e.Msg
	}
	return e.Pointer + ": " + e.Msg
}

func docErrorf(pointer, format string, args ...any) error {
	return &DocumentError{Pointer: pointer, Msg: fmt.Sprintf(format, args...)}
}

type jsonKind int

// The kinds are strictjson's, in its order.
const (
	nodeNull   = jsonKind(strictjson.Null)
	nodeBool   = jsonKind(strictjson.Bool)
	nodeNumber = jsonKind(strictjson.Number)
	nodeString = jsonKind(strictjson.String)
	nodeObject = jsonKind(strictjson.Object)
	nodeArray  = jsonKind(strictjson.Array)
)

func (k jsonKind) String() string { return strictjson.Kind(k).String() }

// jsonNode is a parsed JSON value that keeps object member order and its JSON
// Pointer, so decoding errors can name the exact failing value.
type jsonNode struct {
	pointer string
	kind    jsonKind
	text    string // string value, or a number's literal text
	boolean bool
	keys    []string // object member names in document order
	members map[string]*jsonNode
	items   []*jsonNode
}

// policyDocumentLimits are the bounds of a policy document. Its numbers and
// strings are bounded field by field as they are decoded.
var policyDocumentLimits = strictjson.Limits{MaxBytes: maxPolicyDocumentBytes, MaxDepth: maxPolicyDocumentDepth}

// parseJSONTree parses one strict JSON document: valid UTF-8, bounded size and
// depth, no duplicate object keys, and nothing after the document. The reading
// is strictjson's; the tree is copied into this package's own node type.
func parseJSONTree(data []byte) (*jsonNode, error) {
	root, err := strictjson.Parse(data, policyDocumentLimits)
	if err != nil {
		var parseErr *strictjson.Error
		if errors.As(err, &parseErr) {
			return nil, &DocumentError{Pointer: parseErr.Pointer, Msg: parseErr.Msg}
		}
		return nil, err
	}
	return fromStrictNode(root), nil
}

func fromStrictNode(n *strictjson.Node) *jsonNode {
	node := &jsonNode{pointer: n.Pointer, kind: jsonKind(n.Kind), text: n.Text, boolean: n.Bool, keys: n.Keys}
	if n.Kind == strictjson.Object {
		node.members = make(map[string]*jsonNode, len(n.Members))
		for key, child := range n.Members {
			node.members[key] = fromStrictNode(child)
		}
	}
	for _, item := range n.Items {
		node.items = append(node.items, fromStrictNode(item))
	}
	return node
}

func escapeJSONPointer(token string) string { return strictjson.EscapePointerToken(token) }

// jsonObjectReader decodes one object's members and reports any member the
// decoder never asked for as an unknown field.
type jsonObjectReader struct {
	node *jsonNode
	used map[string]bool
}

func readJSONObject(node *jsonNode, what string) (*jsonObjectReader, error) {
	if node.kind != nodeObject {
		return nil, docErrorf(node.pointer, "%s must be an object, not %s", what, node.kind)
	}
	return &jsonObjectReader{node: node, used: make(map[string]bool, len(node.keys))}, nil
}

// field returns the named member, or nil when it is absent.
func (r *jsonObjectReader) field(key string) *jsonNode {
	r.used[key] = true
	return r.node.members[key]
}

func (r *jsonObjectReader) required(key string) (*jsonNode, error) {
	if n := r.field(key); n != nil {
		return n, nil
	}
	return nil, docErrorf(r.node.pointer, "missing required field %q", key)
}

// finish rejects the first member, in document order, that was not read.
func (r *jsonObjectReader) finish() error {
	for _, key := range r.node.keys {
		if !r.used[key] {
			return docErrorf(r.node.members[key].pointer, "unknown field")
		}
	}
	return nil
}

func jsonString(node *jsonNode) (string, error) {
	if node.kind != nodeString {
		return "", docErrorf(node.pointer, "must be a string, not %s", node.kind)
	}
	return node.text, nil
}

func jsonBool(node *jsonNode) (bool, error) {
	if node.kind != nodeBool {
		return false, docErrorf(node.pointer, "must be true or false, not %s", node.kind)
	}
	return node.boolean, nil
}

func jsonArrayItems(node *jsonNode, minItems int) ([]*jsonNode, error) {
	if node.kind != nodeArray {
		return nil, docErrorf(node.pointer, "must be an array, not %s", node.kind)
	}
	if len(node.items) < minItems {
		return nil, docErrorf(node.pointer, "must have at least %d item(s)", minItems)
	}
	return node.items, nil
}
