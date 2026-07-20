// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apboundedadminapp

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	boundedprotocol "github.com/aplane-algo/aplane/internal/boundedadmin/protocol"
)

func TestResponseFileRoundTripIsExclusiveAndPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ceremony"+ResponseExtension)
	response := boundedprotocol.Response{
		Schema:             boundedprotocol.ResponseSchemaV1,
		RequestHashHex:     strings.Repeat("01", 32),
		ContractAdminKeyID: "KEY",
		SignatureHex:       strings.Repeat("02", 64),
	}
	if err := WriteResponse(path, response, io.Discard); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 600", info.Mode().Perm())
	}
	got, err := ReadResponse(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != response {
		t.Fatalf("response = %#v, want %#v", got, response)
	}
	if err := WriteResponse(path, response, io.Discard); err == nil || !strings.Contains(err.Error(), "overwrite") {
		t.Fatalf("second write error = %v, want overwrite refusal", err)
	}
}

func TestCeremonyFilesRejectWrongExtensionAndSymlink(t *testing.T) {
	directory := t.TempDir()
	response := boundedprotocol.Response{Schema: boundedprotocol.ResponseSchemaV1}
	if err := WriteResponse(filepath.Join(directory, "response.json"), response, io.Discard); err == nil {
		t.Fatal("WriteResponse() accepted wrong extension")
	}
	target := filepath.Join(directory, "target"+ResponseExtension)
	if err := os.WriteFile(target, []byte(`{"schema":"aplane.bounded-admin-signature.v1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link"+ResponseExtension)
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadResponse(link, nil); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("ReadResponse() symlink error = %v", err)
	}
}

func TestCeremonyStdioFormsAreBoundedAndStrict(t *testing.T) {
	response := boundedprotocol.Response{
		Schema: boundedprotocol.ResponseSchemaV1,
	}
	var output bytes.Buffer
	if err := WriteResponse("-", response, &output); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadResponse("-", bytes.NewReader(output.Bytes())); err != nil {
		t.Fatal(err)
	}
	oversized := bytes.NewReader(bytes.Repeat([]byte{'x'}, boundedprotocol.MaxResponseBytes+1))
	if _, err := ReadResponse("-", oversized); err == nil {
		t.Fatal("ReadResponse() accepted oversized input")
	}
	unknown := `{"schema":"aplane.bounded-admin-signature.v1","unknown":true}`
	if _, err := ReadResponse("-", strings.NewReader(unknown)); err == nil {
		t.Fatal("ReadResponse() accepted unknown field")
	}
}
