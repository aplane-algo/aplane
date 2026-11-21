// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package strictjson reads one JSON document strictly and keeps it as a tree.
// Strict means: valid UTF-8, bounded size and nesting, no duplicate object
// keys, and nothing after the document, so two readers cannot take one text
// two ways. Numbers keep their literal text and are never read as floats.
// Policy documents and the answers of a cosigner's external checks are both
// read here, each with its own limits.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Kind is the type of a JSON value.
type Kind int

const (
	Null Kind = iota
	Bool
	Number
	String
	Object
	Array
)

func (k Kind) String() string {
	return [...]string{"null", "boolean", "number", "string", "object", "array"}[k]
}

// Node is a parsed JSON value. It keeps object member order and its own JSON
// Pointer (RFC 6901), so an error can name the exact value.
type Node struct {
	Pointer string
	Kind    Kind
	Text    string // a string's value, or a number's literal text
	Bool    bool
	Keys    []string // object member names in document order
	Members map[string]*Node
	Items   []*Node
}

// Limits bounds a document. A zero MaxNumberLiteral, MaxExponent or
// MaxStringBytes leaves that bound off.
type Limits struct {
	// MaxBytes is the largest document accepted.
	MaxBytes int
	// MaxDepth is the deepest nesting accepted; the document's own value is
	// at depth 0.
	MaxDepth int
	// MaxNumberLiteral is the longest number literal accepted, in characters.
	MaxNumberLiteral int
	// MaxExponent is the largest exponent magnitude a number may carry.
	MaxExponent int
	// MaxStringBytes is the longest string value or member name accepted.
	MaxStringBytes int
}

// Error is a rejection located by JSON Pointer. Pointer is "" for the document
// as a whole.
type Error struct {
	Pointer string
	Msg     string
}

func (e *Error) Error() string {
	if e.Pointer == "" {
		return e.Msg
	}
	return e.Pointer + ": " + e.Msg
}

func errorf(pointer, format string, args ...any) error {
	return &Error{Pointer: pointer, Msg: fmt.Sprintf(format, args...)}
}

// Parse reads one strict JSON document within limits.
func Parse(data []byte, limits Limits) (*Node, error) {
	if len(data) > limits.MaxBytes {
		return nil, errorf("", "document is %d bytes, larger than the %d-byte limit", len(data), limits.MaxBytes)
	}
	if !utf8.Valid(data) {
		return nil, errorf("", "document is not valid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	p := parser{dec: dec, limits: limits}
	root, err := p.value("", 0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errorf("", "unexpected data after the document")
	}
	return root, nil
}

type parser struct {
	dec    *json.Decoder
	limits Limits
}

func (p *parser) value(pointer string, depth int) (*Node, error) {
	if depth > p.limits.MaxDepth {
		return nil, errorf(pointer, "nesting deeper than %d levels", p.limits.MaxDepth)
	}
	tok, err := p.dec.Token()
	if err != nil {
		return nil, errorf(pointer, "invalid JSON: %v", err)
	}
	node := &Node{Pointer: pointer}
	switch v := tok.(type) {
	case nil:
		node.Kind = Null
	case bool:
		node.Kind, node.Bool = Bool, v
	case json.Number:
		node.Kind, node.Text = Number, v.String()
		if err := p.checkNumber(pointer, node.Text); err != nil {
			return nil, err
		}
	case string:
		node.Kind, node.Text = String, v
		if err := p.checkString(pointer, v); err != nil {
			return nil, err
		}
	case json.Delim:
		if err := p.container(node, v, depth); err != nil {
			return nil, err
		}
	}
	return node, nil
}

func (p *parser) container(node *Node, open json.Delim, depth int) error {
	pointer := node.Pointer
	switch open {
	case '{':
		node.Kind, node.Members = Object, make(map[string]*Node)
		for p.dec.More() {
			keyTok, err := p.dec.Token()
			if err != nil {
				return errorf(pointer, "invalid JSON: %v", err)
			}
			key := keyTok.(string)
			childPointer := pointer + "/" + EscapePointerToken(key)
			if err := p.checkString(childPointer, key); err != nil {
				return err
			}
			if _, dup := node.Members[key]; dup {
				return errorf(childPointer, "duplicate key")
			}
			child, err := p.value(childPointer, depth+1)
			if err != nil {
				return err
			}
			node.Keys = append(node.Keys, key)
			node.Members[key] = child
		}
	case '[':
		node.Kind = Array
		for i := 0; p.dec.More(); i++ {
			child, err := p.value(pointer+"/"+strconv.Itoa(i), depth+1)
			if err != nil {
				return err
			}
			node.Items = append(node.Items, child)
		}
	}
	if _, err := p.dec.Token(); err != nil { // closing delimiter
		return errorf(pointer, "invalid JSON: %v", err)
	}
	return nil
}

func (p *parser) checkString(pointer, s string) error {
	if p.limits.MaxStringBytes > 0 && len(s) > p.limits.MaxStringBytes {
		return errorf(pointer, "string is longer than %d bytes", p.limits.MaxStringBytes)
	}
	return nil
}

// checkNumber bounds a number's literal: its length, and the magnitude of its
// exponent, so that no later exact reading of it can be made expensive.
func (p *parser) checkNumber(pointer, literal string) error {
	if p.limits.MaxNumberLiteral > 0 && len(literal) > p.limits.MaxNumberLiteral {
		return errorf(pointer, "number is longer than %d characters", p.limits.MaxNumberLiteral)
	}
	if p.limits.MaxExponent > 0 {
		if i := strings.IndexAny(literal, "eE"); i >= 0 {
			exp, err := strconv.Atoi(literal[i+1:])
			if err != nil || exp > p.limits.MaxExponent || exp < -p.limits.MaxExponent {
				return errorf(pointer, "number has an exponent beyond ±%d", p.limits.MaxExponent)
			}
		}
	}
	return nil
}

// EscapePointerToken writes an object member name as a JSON Pointer token.
func EscapePointerToken(token string) string {
	return strings.ReplaceAll(strings.ReplaceAll(token, "~", "~0"), "/", "~1")
}

// ValidatePointer checks that pointer is an RFC 6901 JSON Pointer: empty, or
// "/token" repeated, where "~" appears only as "~0" or "~1".
func ValidatePointer(pointer string) error {
	if pointer == "" {
		return nil
	}
	if !strings.HasPrefix(pointer, "/") {
		return fmt.Errorf("a JSON Pointer is empty or starts with \"/\"")
	}
	for i := 0; i < len(pointer); i++ {
		if pointer[i] != '~' {
			continue
		}
		if i+1 >= len(pointer) || (pointer[i+1] != '0' && pointer[i+1] != '1') {
			return fmt.Errorf("in a JSON Pointer \"~\" must be written \"~0\", and \"/\" inside a name \"~1\"")
		}
	}
	return nil
}

// Resolve returns the value pointer names under n, and false when there is
// none. An array is indexed only by "0" or a number without sign or leading
// zeros; any other token names nothing in an array. pointer must be valid
// (ValidatePointer); an invalid one names nothing.
func (n *Node) Resolve(pointer string) (*Node, bool) {
	if ValidatePointer(pointer) != nil {
		return nil, false
	}
	if pointer == "" {
		return n, true
	}
	cur := n
	for _, raw := range strings.Split(pointer[1:], "/") {
		token := strings.ReplaceAll(strings.ReplaceAll(raw, "~1", "/"), "~0", "~")
		switch cur.Kind {
		case Object:
			next, ok := cur.Members[token]
			if !ok {
				return nil, false
			}
			cur = next
		case Array:
			i, ok := arrayIndex(raw)
			if !ok || i >= len(cur.Items) {
				return nil, false
			}
			cur = cur.Items[i]
		default:
			return nil, false
		}
	}
	return cur, true
}

// arrayIndex reads a canonical array index: "0", or digits not starting
// with 0.
func arrayIndex(token string) (int, bool) {
	if token == "" || (len(token) > 1 && token[0] == '0') {
		return 0, false
	}
	for i := 0; i < len(token); i++ {
		if token[i] < '0' || token[i] > '9' {
			return 0, false
		}
	}
	i, err := strconv.Atoi(token)
	return i, err == nil
}
