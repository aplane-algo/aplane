// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keyadmin

import (
	"errors"
	"testing"

	"github.com/aplane-algo/aplane/internal/keymgmt"
	"github.com/aplane-algo/aplane/internal/protocol"
)

func TestProjectGenerateIPC(t *testing.T) {
	result := ProjectGenerateIPC(&GenerateResult{
		Address:    "ADDR",
		KeyType:    "ed25519",
		Mnemonic:   "one two three",
		Parameters: map[string]string{"owner": "alice"},
	}, nil)
	if !result.Success {
		t.Fatal("Success = false, want true")
	}
	if result.Address != "ADDR" || result.KeyType != "ed25519" {
		t.Fatalf("result = %#v", result)
	}
	if got, want := result.Parameters["owner"], "alice"; got != want {
		t.Fatalf("Parameters[owner] = %q, want %q", got, want)
	}

	errCases := []struct {
		name string
		err  *Error
		want string
	}{
		{name: "invalid input", err: &Error{Kind: ErrorInvalidInput, Message: "bad request"}, want: protocol.ErrCodeInvalidRequest},
		{name: "invalid passphrase", err: &Error{Kind: ErrorInvalidPassphrase, Message: "bad passphrase"}, want: protocol.ErrCodeInvalidPassphrase},
		{name: "locked", err: &Error{Kind: ErrorLocked, Message: "signer is locked"}, want: protocol.ErrCodeSignerLocked},
		{name: "internal", err: &Error{Kind: ErrorInternal, Message: "boom"}, want: protocol.ErrCodeInternal},
	}
	for _, tc := range errCases {
		t.Run(tc.name, func(t *testing.T) {
			result := ProjectGenerateIPC(nil, tc.err)
			if result.Success {
				t.Fatal("Success = true, want false")
			}
			if result.Code != tc.want {
				t.Fatalf("Code = %q, want %q", result.Code, tc.want)
			}
			if result.Error != tc.err.Message {
				t.Fatalf("Error = %q, want %q", result.Error, tc.err.Message)
			}
		})
	}
}

func TestProjectDeleteIPC(t *testing.T) {
	ok := ProjectDeleteIPC(nil)
	if !ok.Success {
		t.Fatal("Success = false, want true")
	}

	notFound := ProjectDeleteIPC(&Error{Kind: ErrorNotFound, Message: "key not found: ADDR"})
	if notFound.Success {
		t.Fatal("Success = true, want false")
	}
	if notFound.Code != protocol.ErrCodeKeyNotFound {
		t.Fatalf("Code = %q, want %q", notFound.Code, protocol.ErrCodeKeyNotFound)
	}
	if notFound.Error != "Key not found: ADDR" {
		t.Fatalf("Error = %q, want %q", notFound.Error, "Key not found: ADDR")
	}
}

func TestProjectListKeys(t *testing.T) {
	keys, err := ProjectListKeys([]ListKeyInfo{
		{Address: "A", KeyType: "ed25519"},
		{Address: "B", KeyType: "aplane.timed-whitelist.v1", TemplateProvenanceStatus: "conflict", TemplateProvenanceNote: "changed"},
	}, nil)
	if err != nil {
		t.Fatalf("ProjectListKeys() error = %v", err)
	}
	if len(keys) != 2 || keys[0].Address != "A" || keys[1].KeyType != "aplane.timed-whitelist.v1" {
		t.Fatalf("keys = %#v", keys)
	}
	if keys[1].TemplateProvenanceStatus != "conflict" || keys[1].TemplateProvenanceNote != "changed" {
		t.Fatalf("template provenance = (%q, %q), want conflict/changed", keys[1].TemplateProvenanceStatus, keys[1].TemplateProvenanceNote)
	}

	wantErr := &Error{Kind: ErrorInternal, Message: "boom"}
	keys, err = ProjectListKeys(nil, wantErr)
	if keys != nil || !errors.Is(err, wantErr) {
		t.Fatalf("ProjectListKeys(err) = (%#v, %v), want propagated error", keys, err)
	}
}

func TestProjectKeyDetailsIPC(t *testing.T) {
	ok := ProjectKeyDetailsIPC(&KeyDetailsResult{
		Address:     "ADDR",
		KeyType:     "aplane.timed-whitelist.v1",
		Parameters:  map[string]string{"owner": "alice"},
		DisplayTEAL: "#pragma version 8",
	}, nil)
	if !ok.Success {
		t.Fatal("Success = false, want true")
	}
	if ok.Address != "ADDR" || ok.DisplayTEAL == "" {
		t.Fatalf("result = %#v", ok)
	}

	notFound := ProjectKeyDetailsIPC(nil, &Error{Kind: ErrorNotFound, Message: "key not found"})
	if notFound.Code != protocol.ErrCodeKeyNotFound {
		t.Fatalf("Code = %q, want %q", notFound.Code, protocol.ErrCodeKeyNotFound)
	}
	internal := ProjectKeyDetailsIPC(nil, &Error{Kind: ErrorInternal, Message: "signer is locked"})
	if internal.Code != protocol.ErrCodeSignerLocked {
		t.Fatalf("Code = %q, want %q", internal.Code, protocol.ErrCodeSignerLocked)
	}
}

func TestProjectImportIPC(t *testing.T) {
	ok := ProjectImportIPC(&keymgmt.ImportResult{Address: "ADDR"}, "ed25519", nil)
	if !ok.Success || ok.Address != "ADDR" || ok.KeyType != "ed25519" {
		t.Fatalf("result = %#v", ok)
	}

	bad := ProjectImportIPC(nil, "ed25519", &Error{Kind: ErrorInvalidInput, Message: "invalid import key message"})
	if bad.Success {
		t.Fatal("Success = true, want false")
	}
	if bad.Code != protocol.ErrCodeInvalidRequest {
		t.Fatalf("Code = %q, want %q", bad.Code, protocol.ErrCodeInvalidRequest)
	}
}

func TestTrimKeyNotFoundPrefix(t *testing.T) {
	if got := trimKeyNotFoundPrefix("key not found: ADDR"); got != "ADDR" {
		t.Fatalf("trimKeyNotFoundPrefix() = %q, want ADDR", got)
	}
	if got := trimKeyNotFoundPrefix("ADDR"); got != "ADDR" {
		t.Fatalf("trimKeyNotFoundPrefix() = %q, want ADDR", got)
	}
}
