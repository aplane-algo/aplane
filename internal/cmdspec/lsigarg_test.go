// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package cmdspec

import (
	"bytes"
	"strings"
	"testing"
)

const lsigArgTestAddress = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"

func TestParseLsigArg(t *testing.T) {
	tests := []struct {
		name       string
		token      string
		wantTarget string
		wantName   string
		wantValue  []byte
		wantErr    []string // substrings of the error; nil for success
	}{
		// No target: every transaction.
		{name: "string value", token: "arg:preimage=hello", wantName: "preimage", wantValue: []byte("hello")},
		{name: "hex value", token: "arg:preimage=0x68656c6c6f", wantName: "preimage", wantValue: []byte("hello")},
		{name: "hex value that looks like a word", token: "arg:preimage=0xCAFE", wantName: "preimage", wantValue: []byte{0xca, 0xfe}},
		{name: "hex prefix value", token: "arg:preimage=hex:68656c6c6f", wantName: "preimage", wantValue: []byte("hello")},
		{name: "base64 prefix value", token: "arg:preimage=b64:aGVsbG8=", wantName: "preimage", wantValue: []byte("hello")},
		{name: "text prefix value", token: "arg:preimage=text:hello", wantName: "preimage", wantValue: []byte("hello")},
		{name: "value holding colons and equals", token: "arg:preimage=text:a:b=c", wantName: "preimage", wantValue: []byte("a:b=c")},
		{name: "string that looks like hex", token: "arg:preimage=cafe", wantName: "preimage", wantValue: []byte("cafe")},
		{name: "empty value", token: "arg:preimage=", wantName: "preimage", wantValue: []byte("")},
		{name: "empty hex value", token: "arg:preimage=0x", wantName: "preimage", wantValue: []byte("")},

		// A target: the transactions that account sends.
		{name: "alias target", token: "arg:alice:preimage=text:open", wantTarget: "alice", wantName: "preimage", wantValue: []byte("open")},
		{name: "address target", token: "arg:" + lsigArgTestAddress + ":secret=0x6869", wantTarget: lsigArgTestAddress, wantName: "secret", wantValue: []byte("hi")},
		{name: "target, value holding a colon", token: "arg:alice:preimage=hex:68656c6c6f", wantTarget: "alice", wantName: "preimage", wantValue: []byte("hello")},
		{name: "target, value holding colons and equals", token: "arg:alice:preimage=text:a:b=c", wantTarget: "alice", wantName: "preimage", wantValue: []byte("a:b=c")},
		{name: "target, base64 value ending in equals", token: "arg:alice:preimage=b64:aGVsbG8=", wantTarget: "alice", wantName: "preimage", wantValue: []byte("hello")},
		// The parser does not judge target text; resolving it does.
		{name: "asterisk is target text", token: "arg:*:preimage=x", wantTarget: "*", wantName: "preimage", wantValue: []byte("x")},

		{name: "missing equals", token: "arg:preimage", wantErr: []string{"expected arg:<name>=<value> or arg:<account>:<name>=<value>"}},
		{name: "missing equals with a target", token: "arg:alice:preimage", wantErr: []string{"expected arg:<name>=<value>"}},
		{name: "empty name", token: "arg:=x", wantErr: []string{"arg:=...: the argument name is empty"}},
		{name: "empty target", token: "arg::preimage=x", wantErr: []string{"arg::preimage=...: the account before the name is empty"}},
		{name: "empty name after a target", token: "arg:alice:=x", wantErr: []string{"arg:alice:=...: the argument name is empty"}},
		{name: "empty target and name", token: "arg::=x", wantErr: []string{"the account before the name is empty"}},
		{name: "two colons", token: "arg:alice:pre:image=x", wantErr: []string{"arg:alice:pre:image=...: too many ':' (an argument name may not contain ':')"}},
		{name: "two colons, empty parts", token: "arg:::=x", wantErr: []string{"too many ':'"}},
		{name: "set target", token: "arg:@team:preimage=x", wantErr: []string{"a set cannot be the account an argument is for"}},
		{name: "invalid hex", token: "arg:preimage=0xxyz", wantErr: []string{"invalid arg:preimage"}},
		{name: "invalid prefixed hex with a target", token: "arg:alice:preimage=hex:xyz", wantErr: []string{"invalid arg:alice:preimage"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			arg, err := ParseLsigArg(tt.token)
			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("ParseLsigArg(%q) = %+v, want an error", tt.token, arg)
				}
				for _, want := range tt.wantErr {
					if !strings.Contains(err.Error(), want) {
						t.Fatalf("ParseLsigArg(%q) error = %q, want it to contain %q", tt.token, err, want)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseLsigArg(%q) error = %v", tt.token, err)
			}
			if arg.Target != tt.wantTarget || arg.Name != tt.wantName || !bytes.Equal(arg.Value, tt.wantValue) {
				t.Fatalf("ParseLsigArg(%q) = %q %q %q, want %q %q %q",
					tt.token, arg.Target, arg.Name, arg.Value, tt.wantTarget, tt.wantName, tt.wantValue)
			}
			if arg.Untargeted() != (tt.wantTarget == "") {
				t.Fatalf("ParseLsigArg(%q).Untargeted() = %v", tt.token, arg.Untargeted())
			}
		})
	}
}

// A refusal of the word's form names the word but never repeats the value,
// which may be a secret.
func TestParseLsigArgRefusalsLeaveTheValueOut(t *testing.T) {
	for _, token := range []string{"arg:=s3cret", "arg::preimage=s3cret", "arg:a:pre:image=s3cret", "arg:@team:x=s3cret"} {
		if _, err := ParseLsigArg(token); err == nil || strings.Contains(err.Error(), "s3cret") {
			t.Fatalf("ParseLsigArg(%q) error = %v, want a refusal without the value", token, err)
		}
	}
}

func TestAddLsigArgRefusesANameRepeatedForOneTarget(t *testing.T) {
	var args LsigArgs
	for _, token := range []string{"arg:preimage=text:a", "arg:hashlock=text:b", "arg:alice:preimage=text:c", "arg:bob:preimage=text:d"} {
		if err := AddLsigArg(&args, token); err != nil {
			t.Fatalf("AddLsigArg(%q) error = %v", token, err)
		}
	}
	want := LsigArgs{
		{Name: "preimage", Value: []byte("a")},
		{Name: "hashlock", Value: []byte("b")},
		{Target: "alice", Name: "preimage", Value: []byte("c")},
		{Target: "bob", Name: "preimage", Value: []byte("d")},
	}
	if len(args) != len(want) {
		t.Fatalf("args = %+v, want %+v", args, want)
	}
	for i := range want {
		if args[i].Target != want[i].Target || args[i].Name != want[i].Name || !bytes.Equal(args[i].Value, want[i].Value) {
			t.Fatalf("args[%d] = %+v, want %+v", i, args[i], want[i])
		}
	}

	for token, wantErr := range map[string]string{
		"arg:preimage=text:e":       "arg:preimage given more than once",
		"arg:alice:preimage=text:f": "arg:alice:preimage given more than once",
	} {
		if err := AddLsigArg(&args, token); err == nil || err.Error() != wantErr {
			t.Fatalf("AddLsigArg(%q) error = %v, want %q", token, err, wantErr)
		}
	}
	if len(args) != len(want) || string(args[0].Value) != "a" || string(args[2].Value) != "c" {
		t.Fatalf("a refused word changed the list: %+v", args)
	}
}
