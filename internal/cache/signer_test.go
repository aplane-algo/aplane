// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package cache

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

func TestValidateLsigArgs_UnknownArgsRejected(t *testing.T) {
	cache := &SignerCache{
		Keys:        make(map[string]string),
		SigningArgs: make(map[string][]SigningArgInfo),
	}

	// Set up schema with known args
	addr := "TESTADDR123"
	cache.SetSigningArgs(addr, []SigningArgInfo{
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
		SigningArgs: make(map[string][]SigningArgInfo),
	}

	addr := "TESTADDR456"
	cache.SetSigningArgs(addr, []SigningArgInfo{
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
		SigningArgs: make(map[string][]SigningArgInfo),
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
		SigningArgs: make(map[string][]SigningArgInfo),
	}

	addr := "TESTADDR_OPT"
	cache.SetSigningArgs(addr, []SigningArgInfo{
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

func TestSignerCache_BasicCRUD(t *testing.T) {
	cache := NewSignerCache()

	if cache.Count() != 0 {
		t.Errorf("Count() = %d, want 0 for new cache", cache.Count())
	}

	// Add
	cache.AddAddress("ADDR1", "ed25519")
	cache.AddAddress("ADDR2", "aplane.falcon1024.v1")

	if cache.Count() != 2 {
		t.Errorf("Count() = %d, want 2", cache.Count())
	}
	if !cache.HasAddress("ADDR1") {
		t.Error("HasAddress(ADDR1) = false, want true")
	}
	if cache.HasAddress("ADDR3") {
		t.Error("HasAddress(ADDR3) = true, want false")
	}
	if got := cache.GetKeyType("ADDR1"); got != "ed25519" {
		t.Errorf("GetKeyType(ADDR1) = %q, want %q", got, "ed25519")
	}
	if got := cache.GetKeyType("ADDR2"); got != "aplane.falcon1024.v1" {
		t.Errorf("GetKeyType(ADDR2) = %q, want %q", got, "aplane.falcon1024.v1")
	}
	if got := cache.GetKeyType("ADDR3"); got != "" {
		t.Errorf("GetKeyType(ADDR3) = %q, want empty", got)
	}

	// Remove
	cache.RemoveAddress("ADDR1")
	if cache.Count() != 1 {
		t.Errorf("Count() = %d, want 1 after remove", cache.Count())
	}
	if cache.HasAddress("ADDR1") {
		t.Error("HasAddress(ADDR1) should be false after remove")
	}
}

func TestSignerCache_GenericLsig(t *testing.T) {
	cache := NewSignerCache()

	// Unset address
	if cache.IsGenericLsig("ADDR1") {
		t.Error("should not be generic lsig before setting")
	}

	// Set
	cache.SetGenericLsig("ADDR1", true)
	if !cache.IsGenericLsig("ADDR1") {
		t.Error("should be generic lsig after setting true")
	}

	// Unset
	cache.SetGenericLsig("ADDR1", false)
	if cache.IsGenericLsig("ADDR1") {
		t.Error("should not be generic lsig after setting false")
	}
}

func TestSignerCache_LsigSize(t *testing.T) {
	cache := NewSignerCache()

	// Default
	if got := cache.GetLsigSize("ADDR1"); got != 0 {
		t.Errorf("GetLsigSize() = %d, want 0 for unknown address", got)
	}

	// Set and get
	cache.SetLsigSize("ADDR1", 1234)
	if got := cache.GetLsigSize("ADDR1"); got != 1234 {
		t.Errorf("GetLsigSize() = %d, want 1234", got)
	}
}

func TestSignerCache_SigningArgs_RoundTrip(t *testing.T) {
	cache := NewSignerCache()

	// No args initially
	if args := cache.GetSigningArgs("ADDR1"); args != nil {
		t.Error("GetSigningArgs should return nil for unknown address")
	}

	// Set and get
	schema := []SigningArgInfo{
		{Name: "preimage", Type: "bytes", Required: true},
		{Name: "hint", Type: "string", Required: false},
	}
	cache.SetSigningArgs("ADDR1", schema)

	got := cache.GetSigningArgs("ADDR1")
	if len(got) != 2 {
		t.Fatalf("GetSigningArgs() returned %d args, want 2", len(got))
	}
	if got[0].Name != "preimage" || got[0].Required != true {
		t.Errorf("arg 0 = %+v, want preimage/required", got[0])
	}

	// Clear with empty slice
	cache.SetSigningArgs("ADDR1", nil)
	if args := cache.GetSigningArgs("ADDR1"); args != nil {
		t.Error("GetSigningArgs should return nil after clearing")
	}
}

func TestSignerCache_SaveAndLoadRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

	// Create and populate cache
	original := NewSignerCache()
	original.BindStore(store)
	original.AddAddress("ADDR1", "ed25519")
	original.AddAddress("ADDR2", "aplane.falcon1024.v1")
	original.SetGenericLsig("ADDR3", true)
	original.SetLsigSize("ADDR2", 5000)
	original.SetSigningArgs("ADDR3", []SigningArgInfo{
		{Name: "preimage", Type: "bytes", Required: true},
	})
	original.Locked = true

	// Save
	if err := original.SaveCache(); err != nil {
		t.Fatalf("SaveCache() error = %v", err)
	}

	// Load into a new cache
	loaded := LoadSignerCacheFromStore(store)

	// Verify all data survived round-trip
	if loaded.Count() != 2 {
		t.Errorf("Count() = %d, want 2", loaded.Count())
	}
	if loaded.GetKeyType("ADDR1") != "ed25519" {
		t.Errorf("ADDR1 key type = %q, want %q", loaded.GetKeyType("ADDR1"), "ed25519")
	}
	if loaded.GetKeyType("ADDR2") != "aplane.falcon1024.v1" {
		t.Errorf("ADDR2 key type = %q, want %q", loaded.GetKeyType("ADDR2"), "aplane.falcon1024.v1")
	}
	if !loaded.IsGenericLsig("ADDR3") {
		t.Error("ADDR3 should be generic lsig after load")
	}
	if loaded.GetLsigSize("ADDR2") != 5000 {
		t.Errorf("ADDR2 lsig size = %d, want 5000", loaded.GetLsigSize("ADDR2"))
	}
	args := loaded.GetSigningArgs("ADDR3")
	if len(args) != 1 || args[0].Name != "preimage" {
		t.Errorf("ADDR3 signing args = %+v, want [{preimage bytes true}]", args)
	}
	if loaded.Locked {
		t.Error("Locked should not persist across save/load")
	}
}

func TestSignerCache_LoadFromEmptyStore(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

	// Loading from a store with no saved cache should return empty cache
	loaded := LoadSignerCacheFromStore(store)
	if loaded.Count() != 0 {
		t.Errorf("Count() = %d, want 0 for empty store", loaded.Count())
	}
}

func TestSignerCache_LoadTamperedCacheReturnsEmpty(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

	original := NewSignerCache()
	original.BindStore(store)
	original.AddAddress("ADDR1", "ed25519")
	if err := original.SaveCache(); err != nil {
		t.Fatalf("SaveCache() error = %v", err)
	}

	filename := storePath(store, "signer_cache.json")
	raw, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", filename, err)
	}

	var signed SignedCache
	if err := json.Unmarshal(raw, &signed); err != nil {
		t.Fatalf("json.Unmarshal(signed cache) error = %v", err)
	}

	dataBytes, err := base64.StdEncoding.DecodeString(signed.Data)
	if err != nil {
		t.Fatalf("DecodeString() error = %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(dataBytes, &payload); err != nil {
		t.Fatalf("json.Unmarshal(payload) error = %v", err)
	}

	keys, ok := payload["keys"].(map[string]any)
	if !ok {
		t.Fatalf("payload keys = %T, want map[string]any", payload["keys"])
	}
	keys["ADDR1"] = "tampered"

	tamperedData, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("json.Marshal(payload) error = %v", err)
	}
	signed.Data = base64.StdEncoding.EncodeToString(tamperedData)

	rewritten, err := json.Marshal(signed)
	if err != nil {
		t.Fatalf("json.Marshal(signed) error = %v", err)
	}
	if err := os.WriteFile(filename, rewritten, 0600); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", filename, err)
	}

	loaded := LoadSignerCacheFromStore(store)
	if loaded.Count() != 0 {
		t.Errorf("Count() = %d, want 0 after tamper detection", loaded.Count())
	}
	if loaded.GetKeyType("ADDR1") != "" {
		t.Errorf("ADDR1 key type = %q, want empty after tamper detection", loaded.GetKeyType("ADDR1"))
	}
	if loaded.Locked {
		t.Error("tampered cache load should return an unlocked empty cache")
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
