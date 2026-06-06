// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/attestor/keytypes"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keygen"
	"github.com/aplane-algo/aplane/internal/keymgmt"
	apkeys "github.com/aplane-algo/aplane/internal/keys"
)

func TestCmdAttestorExportPublicWritesEnvelopeFile(t *testing.T) {
	withPolicyCommandStore(t, func(_ string, passphrase []byte) {
		result, publicKeyHex := generateTestAttestorComponentKey(t, passphrase)
		outputPath := filepath.Join(t.TempDir(), "attestor-public.json")

		if err := cmdAttestor([]string{"export-public", result.Address, outputPath}); err != nil {
			t.Fatalf("cmdAttestor(export-public) error = %v", err)
		}

		data, err := os.ReadFile(outputPath)
		if err != nil {
			t.Fatalf("ReadFile(export) error = %v", err)
		}
		var env keymgmt.AttestorPublicKeyExport
		if err := json.Unmarshal(data, &env); err != nil {
			t.Fatalf("Unmarshal(export) error = %v", err)
		}
		if env.Schema != keymgmt.AttestorPublicKeyExportSchema {
			t.Fatalf("Schema = %q, want %q", env.Schema, keymgmt.AttestorPublicKeyExportSchema)
		}
		if env.ComponentKey != result.Address {
			t.Fatalf("ComponentKey = %q, want %q", env.ComponentKey, result.Address)
		}
		if env.KeyType != keytypes.AttestorComponentEd25519V1 {
			t.Fatalf("KeyType = %q, want %q", env.KeyType, keytypes.AttestorComponentEd25519V1)
		}
		if env.PublicKeyHex != publicKeyHex {
			t.Fatalf("PublicKeyHex = %q, want %q", env.PublicKeyHex, publicKeyHex)
		}
	})
}

func TestCmdAttestorExportPublicStdoutIsJSONOnly(t *testing.T) {
	withPolicyCommandStore(t, func(_ string, passphrase []byte) {
		result, _ := generateTestAttestorComponentKey(t, passphrase)

		out, err := withCapturedStdout(func() error {
			return cmdAttestor([]string{"export-public", result.Address})
		})
		if err != nil {
			t.Fatalf("cmdAttestor(export-public stdout) error = %v", err)
		}
		if strings.Contains(out, "Enter store passphrase") {
			t.Fatalf("stdout contains passphrase prompt: %q", out)
		}
		var env keymgmt.AttestorPublicKeyExport
		if err := json.Unmarshal([]byte(out), &env); err != nil {
			t.Fatalf("stdout is not a JSON envelope: %v\n%s", err, out)
		}
		if env.ComponentKey != result.Address {
			t.Fatalf("ComponentKey = %q, want %q", env.ComponentKey, result.Address)
		}
	})
}

func TestCmdAttestorExportPublicRequiresPublicSidecar(t *testing.T) {
	withPolicyCommandStore(t, func(_ string, passphrase []byte) {
		result, _ := generateTestAttestorComponentKey(t, passphrase)
		path := apkeys.ComponentPublicMetadataPath(keystorePaths(), productIdentityID(), result.Address)
		if err := os.Remove(path); err != nil {
			t.Fatalf("Remove(component public metadata) error = %v", err)
		}

		err := cmdAttestor([]string{"export-public", result.Address})
		if err == nil {
			t.Fatal("cmdAttestor(export-public missing sidecar) error = nil, want missing metadata rejection")
		}
		if !strings.Contains(err.Error(), "component public metadata") {
			t.Fatalf("cmdAttestor(export-public missing sidecar) error = %v, want metadata context", err)
		}
	})
}

func TestCmdAttestorExportPublicRejectsSpendingKey(t *testing.T) {
	withPolicyCommandStore(t, func(_ string, passphrase []byte) {
		masterKey := deriveTestMasterKey(t, passphrase)
		defer crypto.ZeroBytes(masterKey)

		result, err := keymgmt.GenerateKey(keystorePaths(), productIdentityID(), "ed25519", masterKey, nil)
		if err != nil {
			t.Fatalf("GenerateKey(ed25519) error = %v", err)
		}
		err = withTestStdin(string(passphrase)+"\n", func() error {
			return cmdAttestor([]string{"export-public", result.Address})
		})
		if err == nil {
			t.Fatal("cmdAttestor(export-public spending key) error = nil, want rejection")
		}
		if !strings.Contains(err.Error(), "invalid component key selector") {
			t.Fatalf("cmdAttestor(export-public spending key) error = %v, want component selector rejection", err)
		}
	})
}

func generateTestAttestorComponentKey(t *testing.T, passphrase []byte) (*keygen.GenerationResult, string) {
	t.Helper()
	masterKey := deriveTestMasterKey(t, passphrase)
	defer crypto.ZeroBytes(masterKey)

	g := &keygen.AttestorEd25519Generator{}
	result, err := g.GenerateRandom(context.Background(), keystorePaths(), productIdentityID(), masterKey, keytypes.AttestorComponentEd25519V1, nil)
	if err != nil {
		t.Fatalf("GenerateRandom(attestor-ed25519) error = %v", err)
	}
	if result.PublicKeyHex == "" {
		t.Fatal("GenerateRandom(attestor-ed25519) public key is empty")
	}
	return result, result.PublicKeyHex
}

func deriveTestMasterKey(t *testing.T, passphrase []byte) []byte {
	t.Helper()
	meta, err := crypto.LoadKeystoreMetadata(keystorePaths().KeystoreMetadataDir(productIdentityID()))
	if err != nil {
		t.Fatalf("LoadKeystoreMetadata() error = %v", err)
	}
	masterKey, err := meta.VerifyAndDeriveMasterKey(passphrase)
	if err != nil {
		t.Fatalf("VerifyAndDeriveMasterKey() error = %v", err)
	}
	return masterKey
}
