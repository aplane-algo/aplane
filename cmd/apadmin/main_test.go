// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import "testing"

func TestValidateFlagSpelling(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name: "long flags use double dash",
			args: []string{"--remote", "--client-data", "/tmp/apclient", "--version", "--print-manifest"},
		},
		{
			name: "short data dir flag remains single dash",
			args: []string{"-d", "/tmp/apsigner"},
		},
		{
			name: "short data dir flag accepts equals form",
			args: []string{"-d=/tmp/apsigner"},
		},
		{
			name:    "single dash long remote is rejected",
			args:    []string{"-remote"},
			wantErr: true,
		},
		{
			name:    "single dash long client data is rejected",
			args:    []string{"-client-data", "/tmp/apclient"},
			wantErr: true,
		},
		{
			name: "double dash stops spelling validation",
			args: []string{"--", "-remote"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateFlagSpelling(tt.args)
			if tt.wantErr && err == nil {
				t.Fatal("validateFlagSpelling() error = nil, want error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("validateFlagSpelling() error = %v, want nil", err)
			}
		})
	}
}
