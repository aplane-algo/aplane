// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package refname

import "testing"

func TestValidateAlias(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{name: "alice", wantErr: false},
		{name: "alice-1", wantErr: false},
		{name: "alice_1", wantErr: false},
		{name: "Alice1", wantErr: false},
		{name: "", wantErr: true},
		{name: "alice.team", wantErr: true},
		{name: "alice/team", wantErr: true},
		{name: "alice team", wantErr: true},
		{name: "list", wantErr: true},
		{name: "LIST", wantErr: true},
		{name: "delete", wantErr: true},
		{name: "remove", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAlias(tt.name)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateAlias(%q) error = %v, wantErr %v", tt.name, err, tt.wantErr)
			}
		})
	}
}

func TestValidateSet(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{name: "team", wantErr: false},
		{name: "team-1", wantErr: false},
		{name: "team_1", wantErr: false},
		{name: "", wantErr: true},
		{name: "@team", wantErr: true},
		{name: "team=1", wantErr: true},
		{name: "list", wantErr: true},
		{name: "LIST", wantErr: true},
		{name: "add", wantErr: true},
		{name: "remove", wantErr: true},
		{name: "delete", wantErr: true},
		{name: "all", wantErr: true},
		{name: "signers", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSet(tt.name)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateSet(%q) error = %v, wantErr %v", tt.name, err, tt.wantErr)
			}
		})
	}
}

func TestNormalize(t *testing.T) {
	if got := NormalizeAlias("HELLO_1"); got != "hello_1" {
		t.Fatalf("NormalizeAlias() = %q, want hello_1", got)
	}
	if got := NormalizeSet("TEAM-1"); got != "team-1" {
		t.Fatalf("NormalizeSet() = %q, want team-1", got)
	}
}

func TestIsDynamicSetName(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{name: "all", want: true},
		{name: "@all", want: true},
		{name: "SIGNERS", want: true},
		{name: "list", want: false},
		{name: "team", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsDynamicSetName(tt.name); got != tt.want {
				t.Fatalf("IsDynamicSetName(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}
