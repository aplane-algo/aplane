// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package strictjson

import (
	"errors"
	"strings"
	"testing"
)

var testLimits = Limits{MaxBytes: 1024, MaxDepth: 4, MaxNumberLiteral: 16, MaxExponent: 8, MaxStringBytes: 32}

func TestParseKeepsOrderLiteralsAndPointers(t *testing.T) {
	root, err := Parse([]byte(`{"b": 1.50, "a": [true, null, "x"], "c~/d": {"e": 1e2}}`), testLimits)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(root.Keys, ",") != "b,a,c~/d" {
		t.Fatalf("keys = %v, want document order", root.Keys)
	}
	if n := root.Members["b"]; n.Kind != Number || n.Text != "1.50" || n.Pointer != "/b" {
		t.Fatalf("number = %+v, want its literal kept", n)
	}
	if n := root.Members["a"].Items[2]; n.Kind != String || n.Text != "x" || n.Pointer != "/a/2" {
		t.Fatalf("item = %+v", n)
	}
	if n := root.Members["c~/d"].Members["e"]; n.Pointer != "/c~0~1d/e" {
		t.Fatalf("pointer = %q, want the name escaped", n.Pointer)
	}
}

func TestParseRejects(t *testing.T) {
	for _, tt := range []struct {
		name, doc, pointer, msg string
	}{
		{"duplicate key", `{"a": 1, "a": 2}`, "/a", "duplicate key"},
		{"nested duplicate key", `{"a": {"b": 1, "b": 1}}`, "/a/b", "duplicate key"},
		{"trailing value", `{} {}`, "", "unexpected data"},
		{"trailing garbage", `{}x`, "", "unexpected data"},
		{"invalid UTF-8", "\"\xff\"", "", "not valid UTF-8"},
		{"too deep", `[[[[[1]]]]]`, "/0/0/0/0/0", "nesting deeper than 4"},
		{"too large", `"` + strings.Repeat("a", 1024) + `"`, "", "larger than the 1024-byte limit"},
		{"long number", `12345678901234567`, "", "longer than 16 characters"},
		{"large exponent", `1e9`, "", "exponent beyond"},
		{"large negative exponent", `1e-9`, "", "exponent beyond"},
		{"long string", `"` + strings.Repeat("a", 33) + `"`, "", "longer than 32 bytes"},
		{"long member name", `{"` + strings.Repeat("a", 33) + `": 1}`, "/" + strings.Repeat("a", 33), "longer than 32 bytes"},
		{"unterminated", `{"a": `, "/a", "invalid JSON"},
		{"empty", ``, "", "invalid JSON"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.doc), testLimits)
			var parseErr *Error
			if !errors.As(err, &parseErr) {
				t.Fatalf("error = %v, want an Error", err)
			}
			if parseErr.Pointer != tt.pointer || !strings.Contains(parseErr.Msg, tt.msg) {
				t.Fatalf("error = %q at %q, want %q at %q", parseErr.Msg, parseErr.Pointer, tt.msg, tt.pointer)
			}
		})
	}
	// The bounds that are off accept what they would refuse.
	if _, err := Parse([]byte(`1e400`), Limits{MaxBytes: 64, MaxDepth: 1}); err != nil {
		t.Fatalf("unbounded number: %v", err)
	}
	// A number at the exponent bound is accepted.
	if _, err := Parse([]byte(`1E-8`), testLimits); err != nil {
		t.Fatalf("exponent at the bound: %v", err)
	}
}

func TestResolve(t *testing.T) {
	root, err := Parse([]byte(`{"a": {"b/c": [10, {"~": null}], "": 7}, "0": "zero"}`), testLimits)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		pointer string
		kind    Kind
		text    string
	}{
		{"", Object, ""},
		{"/a/b~1c/0", Number, "10"},
		{"/a/b~1c/1/~0", Null, ""},
		{"/a/", Number, "7"},
		{"/0", String, "zero"},
	} {
		n, ok := root.Resolve(tt.pointer)
		if !ok || n.Kind != tt.kind || n.Text != tt.text {
			t.Errorf("Resolve(%q) = %+v, %v; want %s %q", tt.pointer, n, ok, tt.kind, tt.text)
		}
	}
	for _, pointer := range []string{
		"/missing", "/a/b~1c/2", "/a/b~1c/01", "/a/b~1c/+0", "/a/b~1c/-", "/a/b~1c/x",
		"/a/b~1c/", "/0/x", "a", "/a~", "/a~2",
	} {
		if n, ok := root.Resolve(pointer); ok {
			t.Errorf("Resolve(%q) = %+v, want nothing", pointer, n)
		}
	}
}

func TestValidatePointer(t *testing.T) {
	for _, ok := range []string{"", "/", "/a", "/a/b", "/a~0b", "/a~1b", "//"} {
		if err := ValidatePointer(ok); err != nil {
			t.Errorf("ValidatePointer(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"a", "a/b", "/a~", "/a~2", "/~"} {
		if err := ValidatePointer(bad); err == nil {
			t.Errorf("ValidatePointer(%q) = nil, want an error", bad)
		}
	}
}
