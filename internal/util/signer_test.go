// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package util

import (
	"testing"
)

func TestValidateLsigArgs_UnknownArgsRejected(t *testing.T) {
	cache := &SignerCache{
		Keys:        make(map[string]string),
		RuntimeArgs: make(map[string][]RuntimeArgInfo),
	}

	// Set up schema with known args
	addr := "TESTADDR123"
	cache.SetRuntimeArgs(addr, []RuntimeArgInfo{
		{Name: "preimage", Type: "bytes", Required: true},
		{Name: "timeout", Type: "uint64", Required: false},
	})

	tests := []struct {
		name        string
		args        map[string][]byte
		wantErr     bool
		errContains string
	}{
		{
			name: "valid args accepted",
			args: map[string][]byte{
				"preimage": []byte("secret"),
				"timeout":  []byte("12345"),
			},
			wantErr: false,
		},
		{
			name: "unknown arg rejected",
			args: map[string][]byte{
				"preimage": []byte("secret"),
				"unknown":  []byte("bad"),
			},
			wantErr:     true,
			errContains: "unknown argument 'unknown'",
		},
		{
			name: "typo in arg name rejected",
			args: map[string][]byte{
				"preiamge": []byte("secret"), // typo
			},
			wantErr:     true,
			errContains: "unknown argument 'preiamge'",
		},
		{
			name: "multiple unknown args - first one reported",
			args: map[string][]byte{
				"preimage": []byte("secret"),
				"bad1":     []byte("x"),
				"bad2":     []byte("y"),
			},
			wantErr:     true,
			errContains: "unknown argument",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cache.ValidateLsigArgs(addr, tt.args)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errContains)
				} else if tt.errContains != "" && !contains(err.Error(), tt.errContains) {
					t.Errorf("expected error containing %q, got %q", tt.errContains, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
			}
		})
	}
}

func TestValidateLsigArgs_RequiredArgsEnforced(t *testing.T) {
	cache := &SignerCache{
		Keys:        make(map[string]string),
		RuntimeArgs: make(map[string][]RuntimeArgInfo),
	}

	addr := "TESTADDR456"
	cache.SetRuntimeArgs(addr, []RuntimeArgInfo{
		{Name: "preimage", Type: "bytes", Required: true},
		{Name: "signature", Type: "bytes", Required: true},
		{Name: "optional_hint", Type: "string", Required: false},
	})

	tests := []struct {
		name        string
		args        map[string][]byte
		wantErr     bool
		errContains string
	}{
		{
			name: "all required args provided",
			args: map[string][]byte{
				"preimage":  []byte("secret"),
				"signature": []byte("sig"),
			},
			wantErr: false,
		},
		{
			name: "all args including optional provided",
			args: map[string][]byte{
				"preimage":      []byte("secret"),
				"signature":     []byte("sig"),
				"optional_hint": []byte("hint"),
			},
			wantErr: false,
		},
		{
			name: "missing one required arg",
			args: map[string][]byte{
				"preimage": []byte("secret"),
				// signature missing
			},
			wantErr:     true,
			errContains: "missing required argument: signature",
		},
		{
			name: "missing multiple required args",
			args: map[string][]byte{
				"optional_hint": []byte("hint"),
				// both required args missing
			},
			wantErr:     true,
			errContains: "missing required arguments:",
		},
		{
			name:        "no args provided when required",
			args:        map[string][]byte{},
			wantErr:     true,
			errContains: "missing required arguments:",
		},
		{
			name:        "nil args when required",
			args:        nil,
			wantErr:     true,
			errContains: "missing required arguments:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cache.ValidateLsigArgs(addr, tt.args)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errContains)
				} else if tt.errContains != "" && !contains(err.Error(), tt.errContains) {
					t.Errorf("expected error containing %q, got %q", tt.errContains, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
			}
		})
	}
}

func TestValidateLsigArgs_NoSchemaAllowsNoArgs(t *testing.T) {
	cache := &SignerCache{
		Keys:        make(map[string]string),
		RuntimeArgs: make(map[string][]RuntimeArgInfo),
	}

	addr := "TESTADDR789"
	// No schema set for this address

	tests := []struct {
		name    string
		args    map[string][]byte
		wantErr bool
	}{
		{
			name:    "no args when no schema",
			args:    nil,
			wantErr: false,
		},
		{
			name:    "empty args when no schema",
			args:    map[string][]byte{},
			wantErr: false,
		},
		{
			name: "args provided when no schema - allowed (server handles)",
			args: map[string][]byte{
				"something": []byte("value"),
			},
			wantErr: false, // Let server validate - might be DSA lsig
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cache.ValidateLsigArgs(addr, tt.args)
			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}

func TestValidateLsigArgs_OnlyOptionalArgs(t *testing.T) {
	cache := &SignerCache{
		Keys:        make(map[string]string),
		RuntimeArgs: make(map[string][]RuntimeArgInfo),
	}

	addr := "TESTADDR_OPT"
	cache.SetRuntimeArgs(addr, []RuntimeArgInfo{
		{Name: "hint1", Type: "string", Required: false},
		{Name: "hint2", Type: "string", Required: false},
	})

	tests := []struct {
		name    string
		args    map[string][]byte
		wantErr bool
	}{
		{
			name:    "no args when all optional",
			args:    nil,
			wantErr: false,
		},
		{
			name: "some optional args provided",
			args: map[string][]byte{
				"hint1": []byte("value"),
			},
			wantErr: false,
		},
		{
			name: "all optional args provided",
			args: map[string][]byte{
				"hint1": []byte("value1"),
				"hint2": []byte("value2"),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cache.ValidateLsigArgs(addr, tt.args)
			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}

// contains checks if s contains substr
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && searchString(s, substr)))
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
