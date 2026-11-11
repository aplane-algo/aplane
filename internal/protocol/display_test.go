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
