// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import "testing"

func TestValidateSetNameInput(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{name: "team", wantErr: false},
		{name: "team-1", wantErr: false},
		{name: "team_1", wantErr: false},
		{name: "@team", wantErr: false},
		{name: "@team-1", wantErr: false},
		{name: "team=", wantErr: true},
		{name: "team.alpha", wantErr: true},
		{name: "team/alpha", wantErr: true},
		{name: "team alpha", wantErr: true},
		{name: "list", wantErr: true},
		{name: "add", wantErr: true},
		{name: "@team=[", wantErr: true},
		{name: "", wantErr: true},
	}

	for _, tt := range tests {
		err := validateSetNameInput(tt.name)
		if tt.wantErr && err == nil {
			t.Fatalf("validateSetNameInput(%q) returned nil, want error", tt.name)
		}
		if !tt.wantErr && err != nil {
			t.Fatalf("validateSetNameInput(%q) returned error %v, want nil", tt.name, err)
		}
	}
}

func TestValidateAliasNameInput(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{name: "alice", wantErr: false},
		{name: "alice-1", wantErr: false},
		{name: "alice_1", wantErr: false},
		{name: "Alice1", wantErr: false},
		{name: "alice.team", wantErr: true},
		{name: "alice/team", wantErr: true},
		{name: "alice team", wantErr: true},
		{name: "list", wantErr: true},
		{name: "delete", wantErr: true},
		{name: "remove", wantErr: true},
		{name: "", wantErr: true},
	}

	for _, tt := range tests {
		err := validateAliasNameInput(tt.name)
		if tt.wantErr && err == nil {
			t.Fatalf("validateAliasNameInput(%q) returned nil, want error", tt.name)
		}
		if !tt.wantErr && err != nil {
			t.Fatalf("validateAliasNameInput(%q) returned error %v, want nil", tt.name, err)
		}
	}
}

func TestNormalizeSetNameInput(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{input: "team", want: "team"},
		{input: "Team", want: "team"},
		{input: "@Team", want: "@team"},
	}

	for _, tt := range tests {
		if got := normalizeSetNameInput(tt.input); got != tt.want {
			t.Fatalf("normalizeSetNameInput(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
