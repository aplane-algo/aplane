// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package protocol

import (
	"reflect"
	"testing"
)

func TestSignRequestTerminalSafeEscapesEveryShownString(t *testing.T) {
	in := SignRequestMessage{
		BaseMessage: BaseMessage{Type: MsgTypeSignRequest, ID: "sign-1"},
		Address:     "A\x1b[2J",
		TxnSender:   "S\r",
		Description: "line one\n\tline\x1b[1A two\u202e",
		FirstValid:  1,
		LastValid:   2,
		Violations:  []PolicyViolation{{Field: "F\n", Value: "V\x1b", Severity: "warning\x07", Message: "m\none\x1b"}},
	}
	want := SignRequestMessage{
		BaseMessage: in.BaseMessage,
		Address:     `A\x1b[2J`,
		TxnSender:   `S\r`,
		Description: "line one\n\tline\\x1b[1A two\\u202e",
		FirstValid:  1,
		LastValid:   2,
		Violations:  []PolicyViolation{{Field: `F\n`, Value: `V\x1b`, Severity: `warning\a`, Message: "m\none\\x1b"}},
	}
	got := in.TerminalSafe()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("TerminalSafe() =\n%#v\nwant\n%#v", got, want)
	}
	if again := got.TerminalSafe(); !reflect.DeepEqual(again, got) {
		t.Fatalf("TerminalSafe() is not idempotent:\n%#v", again)
	}
	if in.Violations[0].Field != "F\n" {
		t.Fatal("TerminalSafe() changed the caller's violations")
	}
}

// apadmin and apapprover show a request's validity window with one line, and
// none when the signer sent no window.
func TestValidityWindowLine(t *testing.T) {
	for _, tc := range []struct {
		first, last uint64
		want        string
	}{
		{0, 0, ""},
		{10, 0, ""},
		{0, 10, ""},
		{10, 10, "Valid Rounds: 10 - 10 (window: 0 blocks)"},
		{100, 1100, "Valid Rounds: 100 - 1100 (window: 1000 blocks)"},
		{20, 10, "Valid Rounds: 20 - 10 (empty: no round is valid)"},
	} {
		if got := ValidityWindowLine(tc.first, tc.last); got != tc.want {
			t.Errorf("ValidityWindowLine(%d, %d) = %q, want %q", tc.first, tc.last, got, tc.want)
		}
	}
}

// fillStrings sets every string reachable from v to raw, giving each slice
// one element.
func fillStrings(v reflect.Value, raw string) {
	switch v.Kind() {
	case reflect.String:
		v.SetString(raw)
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			fillStrings(v.Field(i), raw)
		}
	case reflect.Slice:
		v.Set(reflect.MakeSlice(v.Type(), 1, 1))
		fillStrings(v.Index(0), raw)
	case reflect.Pointer:
		v.Set(reflect.New(v.Type().Elem()))
		fillStrings(v.Elem(), raw)
	}
}

// eachString calls visit with every string reachable from v.
func eachString(v reflect.Value, path string, visit func(path, s string)) {
	switch v.Kind() {
	case reflect.String:
		visit(path, v.String())
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			eachString(v.Field(i), path+"."+v.Type().Field(i).Name, visit)
		}
	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			eachString(v.Index(i), path, visit)
		}
	case reflect.Pointer:
		if !v.IsNil() {
			eachString(v.Elem(), path, visit)
		}
	}
}

// Every string of a sign request is escaped, its review's included: a string
// field added to the review later is covered here without being named.
func TestSignRequestTerminalSafeEscapesEveryStringOfTheReview(t *testing.T) {
	var in SignRequestMessage
	fillStrings(reflect.ValueOf(&in.Review).Elem(), "raw\x1b[2J\u202e")
	if in.Review == nil || len(in.Review.Items) != 1 || len(in.Review.Items[0].Effects) != 1 {
		t.Fatalf("the review was not filled: %+v", in.Review)
	}
	got := in.TerminalSafe()
	count := 0
	eachString(reflect.ValueOf(got.Review), "Review", func(path, s string) {
		count++
		for _, r := range s {
			if r == 0x1b || r == 0x202e {
				t.Errorf("%s is not escaped: %q", path, s)
			}
		}
	})
	if count < 20 {
		t.Fatalf("only %d strings were checked", count)
	}
	if in.Review.Items[0].Title != "raw\x1b[2J\u202e" {
		t.Fatal("TerminalSafe() changed the caller's review")
	}
	if again := got.TerminalSafe(); !reflect.DeepEqual(again, got) {
		t.Fatal("TerminalSafe() is not idempotent on a review")
	}
}
