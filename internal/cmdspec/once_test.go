// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package cmdspec

import "testing"

func TestSeenOptionsRefusesASecondValue(t *testing.T) {
	seen := SeenOptions{}
	if err := seen.Once("pay"); err != nil {
		t.Fatalf("first pay refused: %v", err)
	}
	if err := seen.Once("note"); err != nil {
		t.Fatalf("another option refused: %v", err)
	}
	if err := seen.Once("pay"); err == nil || err.Error() != "pay given more than once" {
		t.Fatalf("second pay error = %v, want %q", err, "pay given more than once")
	}
}

func TestAddLsigArgRefusesARepeatedName(t *testing.T) {
	var args map[string][]byte
	for _, token := range []string{"arg:preimage=text:a", "arg:hashlock=text:b"} {
		if err := AddLsigArg(&args, token); err != nil {
			t.Fatalf("AddLsigArg(%q) error = %v", token, err)
		}
	}
	if string(args["preimage"]) != "a" || string(args["hashlock"]) != "b" {
		t.Fatalf("args = %q", args)
	}
	err := AddLsigArg(&args, "arg:preimage=text:c")
	if err == nil || err.Error() != "arg:preimage given more than once" {
		t.Fatalf("repeated name error = %v, want %q", err, "arg:preimage given more than once")
	}
	if string(args["preimage"]) != "a" {
		t.Fatalf("refused value replaced the first: %q", args["preimage"])
	}
}

func TestParseKeyValueArgsRefusesARepeatedKey(t *testing.T) {
	for _, tt := range []struct {
		args []string
		want string
	}{
		{[]string{"hashlock=aa", "hashlock=bb"}, "hashlock given more than once"},
		{[]string{"recipients=[a b]", "recipients=c"}, "recipients given more than once"},
	} {
		if _, _, err := ParseKeyValueArgs(tt.args); err == nil || err.Error() != tt.want {
			t.Errorf("%v: error = %v, want %q", tt.args, err, tt.want)
		}
	}
	_, kv, err := ParseKeyValueArgs([]string{"hashlock=aa", "recipients=[a", "b]", "timeout=5"})
	if err != nil {
		t.Fatalf("well-formed parameters refused: %v", err)
	}
	if kv["hashlock"] != "aa" || kv["recipients"] != "a,b" || kv["timeout"] != "5" {
		t.Fatalf("parameters parsed as %v", kv)
	}
}
