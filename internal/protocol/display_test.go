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
