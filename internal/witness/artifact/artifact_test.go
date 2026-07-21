// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package artifact

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/witness"
)

var testCreatedAt = time.Date(2026, time.July, 17, 12, 34, 56, 0, time.UTC)

func TestGenerateOpenAndInspect(t *testing.T) {
	t.Parallel()

	t.Run("falcon1024", func(t *testing.T) {
		passphrase := []byte("correct horse battery staple")
		bundle, sidecar, generated, err := Generate(passphrase, testCreatedAt)
		if err != nil {
			t.Fatalf("Generate() error = %v", err)
		}

		inspected, err := Inspect(bundle)
		if err != nil {
			t.Fatalf("Inspect() error = %v", err)
		}
		if inspected != generated {
			t.Fatalf("Inspect() = %#v, want %#v", inspected, generated)
		}
		var sidecarReference PublicReference
		if err := json.Unmarshal(sidecar, &sidecarReference); err != nil {
			t.Fatalf("decode sidecar: %v", err)
		}
		if sidecarReference != generated {
			t.Fatalf("sidecar = %#v, want %#v", sidecarReference, generated)
		}

		credential, err := Open(bundle, passphrase)
		if err != nil {
			t.Fatalf("Open() error = %v", err)
		}
		if credential.PublicReference != generated {
			t.Fatalf("Open() reference = %#v, want %#v", credential.PublicReference, generated)
		}
		if !credential.CreatedAt.Equal(testCreatedAt) {
			t.Fatalf("Open() created_at = %v, want %v", credential.CreatedAt, testCreatedAt)
		}
		if len(credential.PrivateMaterial) == 0 {
			t.Fatal("Open() returned empty private material")
		}
		privateMaterial := credential.PrivateMaterial
		credential.Zero()
		if credential.PrivateMaterial != nil {
			t.Fatal("Zero() retained private material")
		}
		if !bytes.Equal(privateMaterial, make([]byte, len(privateMaterial))) {
			t.Fatal("Zero() did not clear private material")
		}
	})
}

func TestVerifyRejectsWrongPassphrase(t *testing.T) {
	t.Parallel()

	bundle, _, _, err := Generate([]byte("right passphrase"), testCreatedAt)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if _, err := Verify(bundle, []byte("wrong passphrase")); err == nil || !strings.Contains(err.Error(), "decrypt witness artifact") {
		t.Fatalf("Verify() error = %v, want decryption failure", err)
	}
}

func TestInspectRejectsUnknownSchemaBeforeEnvelopeValidation(t *testing.T) {
	t.Parallel()

	data := []byte(`{"schema":"aplane.external-governance-bundle.v2"}`)
	_, err := Inspect(data)
	if ErrorCode(err) != ErrorUnsupportedArtifactSchema {
		t.Fatalf("ErrorCode(Inspect()) = %q, want %q (error: %v)", ErrorCode(err), ErrorUnsupportedArtifactSchema, err)
	}
}

func TestInspectRejectsSignerKeyPayload(t *testing.T) {
	t.Parallel()

	data := []byte(`{"format_version":1,"category":"witness","key_type":"aplane.witness-falcon1024.v1","public_key":"00","private_key":"00","created_at":"2026-07-21T00:00:00Z"}`)
	if _, err := Inspect(data); err == nil {
		t.Fatal("Inspect(signer key payload) error = nil, want custody-format rejection")
	}
}

func TestInspectRejectsUnboundedKDFParameters(t *testing.T) {
	t.Parallel()

	bundleBytes, _, _, err := Generate([]byte("passphrase"), testCreatedAt)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	var bundle Bundle
	if err := json.Unmarshal(bundleBytes, &bundle); err != nil {
		t.Fatalf("decode bundle: %v", err)
	}
	bundle.Encryption.KDFMemory++
	mutated, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("encode bundle: %v", err)
	}
	if _, err := Inspect(mutated); err == nil || !strings.Contains(err.Error(), "KDF parameters") {
		t.Fatalf("Inspect() error = %v, want KDF rejection", err)
	}
}

func TestOpenRejectsCiphertextCorruption(t *testing.T) {
	t.Parallel()

	passphrase := []byte("passphrase")
	bundleBytes, _, _, err := Generate(passphrase, testCreatedAt)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	var bundle Bundle
	if err := json.Unmarshal(bundleBytes, &bundle); err != nil {
		t.Fatalf("decode bundle: %v", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(bundle.Encryption.Ciphertext)
	if err != nil {
		t.Fatalf("decode ciphertext: %v", err)
	}
	ciphertext[len(ciphertext)-1] ^= 0xff
	bundle.Encryption.Ciphertext = base64.StdEncoding.EncodeToString(ciphertext)
	corrupted, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("encode corrupted bundle: %v", err)
	}
	if _, err := Open(corrupted, passphrase); err == nil || !strings.Contains(err.Error(), "decrypt witness artifact") {
		t.Fatalf("Open() error = %v, want authenticated decryption failure", err)
	}
}

func TestInspectRejectsUnknownFields(t *testing.T) {
	t.Parallel()

	data := []byte(`{"schema":"aplane.witness-key-bundle.v1","unexpected":true}`)
	if _, err := Inspect(data); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("Inspect() error = %v, want unknown-field rejection", err)
	}
}

func TestParsePublicReferenceValidatesIdentity(t *testing.T) {
	t.Parallel()

	_, sidecar, generated, err := Generate([]byte("passphrase"), testCreatedAt)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	parsed, err := ParsePublicReference(sidecar)
	if err != nil {
		t.Fatalf("ParsePublicReference() error = %v", err)
	}
	if parsed != generated {
		t.Fatalf("ParsePublicReference() = %#v, want %#v", parsed, generated)
	}

	parsed.WitnessKeyID = strings.Repeat("A", 52)
	mutated, err := json.Marshal(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePublicReference(mutated); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("ParsePublicReference() error = %v, want identity mismatch", err)
	}
}

func TestParsePublicReferenceRejectsUnknownSchema(t *testing.T) {
	t.Parallel()

	_, err := ParsePublicReference([]byte(`{"schema":"aplane.external-governance-public.v2"}`))
	if ErrorCode(err) != ErrorUnsupportedArtifactSchema {
		t.Fatalf("ErrorCode() = %q, want %q (error: %v)", ErrorCode(err), ErrorUnsupportedArtifactSchema, err)
	}
}

func TestGenerateFilesAndLoad(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	files, err := GenerateFiles(directory, []byte("passphrase"), testCreatedAt)
	if err != nil {
		t.Fatalf("GenerateFiles() error = %v", err)
	}
	if filepath.Base(files.BundlePath) != files.Reference.WitnessKeyID+BundleExtension {
		t.Fatalf("bundle path = %q", files.BundlePath)
	}
	if filepath.Base(files.ReferencePath) != files.Reference.WitnessKeyID+ReferenceExtension {
		t.Fatalf("reference path = %q", files.ReferencePath)
	}
	for _, path := range []string{files.BundlePath, files.ReferencePath} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("Stat(%q): %v", path, err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("mode(%q) = %o, want 600", path, info.Mode().Perm())
		}
	}
	data, err := LoadFile(files.BundlePath)
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}
	inspected, err := Inspect(data)
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	if inspected != files.Reference {
		t.Fatalf("Inspect() = %#v, want %#v", inspected, files.Reference)
	}
}

func TestGeneratedPublicIdentityUsesWitnessKeyID(t *testing.T) {
	_, _, reference, err := Generate([]byte("passphrase"), testCreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := hex.DecodeString(reference.PublicKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	if len(publicKey) != witness.Falcon1024PublicKeySize {
		t.Fatalf("public key length = %d", len(publicKey))
	}
	want, err := witness.ID(witness.Falcon1024V1, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if reference.WitnessKeyID != want {
		t.Fatalf("WitnessKeyID = %q, want %q", reference.WitnessKeyID, want)
	}
}

func TestFileOperationsRejectOverwriteAndWrongFileKinds(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	existing := filepath.Join(directory, "existing.wit")
	if err := os.WriteFile(existing, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeExclusiveAtomic(existing, []byte("replacement")); err == nil {
		t.Fatal("writeExclusiveAtomic() overwrote an existing file")
	}
	content, err := os.ReadFile(existing)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "original" {
		t.Fatalf("existing content = %q, want original", content)
	}

	wrongExtension := filepath.Join(directory, "credential.apb")
	if err := os.WriteFile(wrongExtension, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(wrongExtension); err == nil || !strings.Contains(err.Error(), BundleExtension) {
		t.Fatalf("LoadFile(.apb) error = %v, want extension rejection", err)
	}

	symlink := filepath.Join(directory, "linked.wit")
	if err := os.Symlink(existing, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(symlink); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("LoadFile(symlink) error = %v, want regular-file rejection", err)
	}

	directoryLink := filepath.Join(t.TempDir(), "output")
	if err := os.Symlink(directory, directoryLink); err != nil {
		t.Fatal(err)
	}
	if err := ValidateOutputDirectory(directoryLink); err == nil {
		t.Fatal("ValidateOutputDirectory() accepted a symlink")
	}
}

func TestProtocolErrorUnwrap(t *testing.T) {
	inner := errors.New("inner")
	err := &ProtocolError{Code: ErrorUnsupportedArtifactSchema, Err: inner}
	if !errors.Is(err, inner) {
		t.Fatal("ProtocolError does not unwrap its cause")
	}
}
