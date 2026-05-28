// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package cmdspec

import (
	"reflect"
	"testing"
)

func TestExtractBracketList(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		startIdx   int
		want       []string
		wantEndIdx int
		wantErr    bool
	}{
		{name: "attached single token", args: []string{"[alice]"}, want: []string{"alice"}, wantEndIdx: 0},
		{name: "separate single token", args: []string{"[", "alice", "]"}, want: []string{"alice"}, wantEndIdx: 2},
		{name: "attached multi token", args: []string{"[alice", "bob]"}, want: []string{"alice", "bob"}, wantEndIdx: 1},
		{name: "separate multi token", args: []string{"[", "alice", "bob", "]"}, want: []string{"alice", "bob"}, wantEndIdx: 3},
		{name: "mixed edge token", args: []string{"[", "alice", "bob]"}, want: []string{"alice", "bob"}, wantEndIdx: 2},
		{name: "empty list", args: []string{"[", "]"}, wantErr: true},
		{name: "missing opening bracket", args: []string{"alice"}, wantErr: true},
		{name: "missing closing bracket", args: []string{"[", "alice"}, wantErr: true},
		{name: "nested opening bracket", args: []string{"[", "[alice", "]"}, wantErr: true},
		{name: "invalid extra closing bracket", args: []string{"[", "alice]]"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, endIdx, err := ExtractBracketList(tt.args, tt.startIdx)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ExtractBracketList() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("ExtractBracketList() items = %v, want %v", got, tt.want)
			}
			if endIdx != tt.wantEndIdx {
				t.Fatalf("ExtractBracketList() endIdx = %d, want %d", endIdx, tt.wantEndIdx)
			}
		})
	}
}

func TestParseKeyValueArgs(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantPos []string
		wantKV  map[string]string
		wantErr bool
	}{
		{
			name:    "plain key value",
			args:    []string{"expiry=123"},
			wantKV:  map[string]string{"expiry": "123"},
			wantPos: []string{},
		},
		{
			name:    "mixed positional and kv",
			args:    []string{"abc", "expiry=123"},
			wantKV:  map[string]string{"expiry": "123"},
			wantPos: []string{"abc"},
		},
		{
			name:    "bracket list value",
			args:    []string{"recipients=[", "alice", "bob]"},
			wantKV:  map[string]string{"recipients": "alice,bob"},
			wantPos: []string{},
		},
		{
			name:    "single token bracket list value",
			args:    []string{"recipients=[alice]"},
			wantKV:  map[string]string{"recipients": "alice"},
			wantPos: []string{},
		},
		{
			name:    "set value passes through",
			args:    []string{"recipients=@targets"},
			wantKV:  map[string]string{"recipients": "@targets"},
			wantPos: []string{},
		},
		{
			name:    "missing closing bracket",
			args:    []string{"recipients=[", "alice"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pos, kv, err := ParseKeyValueArgs(tt.args)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseKeyValueArgs() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if !reflect.DeepEqual(pos, tt.wantPos) {
				t.Fatalf("ParseKeyValueArgs() positional = %v, want %v", pos, tt.wantPos)
			}
			if !reflect.DeepEqual(kv, tt.wantKV) {
				t.Fatalf("ParseKeyValueArgs() kv = %v, want %v", kv, tt.wantKV)
			}
		})
	}
}
