// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
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

const (
	nodeNull jsonKind = iota
	nodeBool
	nodeNumber
	nodeString
	nodeObject
	nodeArray
)

func (k jsonKind) String() string {
	return [...]string{"null", "boolean", "number", "string", "object", "array"}[k]
}

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

// parseJSONTree parses one strict JSON document: valid UTF-8, bounded size and
// depth, no duplicate object keys, and nothing after the document.
func parseJSONTree(data []byte) (*jsonNode, error) {
	if len(data) > maxPolicyDocumentBytes {
		return nil, docErrorf("", "document is %d bytes, larger than the %d-byte limit", len(data), maxPolicyDocumentBytes)
	}
	if !utf8.Valid(data) {
		return nil, docErrorf("", "document is not valid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	root, err := readJSONValue(dec, "", 0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, docErrorf("", "unexpected data after the document")
	}
	return root, nil
}

func readJSONValue(dec *json.Decoder, pointer string, depth int) (*jsonNode, error) {
	if depth > maxPolicyDocumentDepth {
		return nil, docErrorf(pointer, "nesting deeper than %d levels", maxPolicyDocumentDepth)
	}
	tok, err := dec.Token()
	if err != nil {
		return nil, docErrorf(pointer, "invalid JSON: %v", err)
	}
	node := &jsonNode{pointer: pointer}
	switch v := tok.(type) {
	case nil:
		node.kind = nodeNull
	case bool:
		node.kind, node.boolean = nodeBool, v
	case json.Number:
		node.kind, node.text = nodeNumber, v.String()
	case string:
		node.kind, node.text = nodeString, v
	case json.Delim:
		switch v {
		case '{':
			node.kind, node.members = nodeObject, make(map[string]*jsonNode)
			for dec.More() {
				keyTok, err := dec.Token()
				if err != nil {
					return nil, docErrorf(pointer, "invalid JSON: %v", err)
				}
				key := keyTok.(string)
				childPointer := pointer + "/" + escapeJSONPointer(key)
				if _, dup := node.members[key]; dup {
					return nil, docErrorf(childPointer, "duplicate key")
				}
				child, err := readJSONValue(dec, childPointer, depth+1)
				if err != nil {
					return nil, err
				}
				node.keys = append(node.keys, key)
				node.members[key] = child
			}
		case '[':
			node.kind = nodeArray
			for i := 0; dec.More(); i++ {
				child, err := readJSONValue(dec, fmt.Sprintf("%s/%d", pointer, i), depth+1)
				if err != nil {
					return nil, err
				}
				node.items = append(node.items, child)
			}
		}
		if _, err := dec.Token(); err != nil { // closing delimiter
			return nil, docErrorf(pointer, "invalid JSON: %v", err)
		}
	}
	return node, nil
}

func escapeJSONPointer(token string) string {
	return strings.ReplaceAll(strings.ReplaceAll(token, "~", "~0"), "/", "~1")
}

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
