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

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keygen"
	"github.com/aplane-algo/aplane/internal/keymgmt"
	apkeys "github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
	"github.com/aplane-algo/aplane/internal/sentry/sentryrefs"
	falconkeygen "github.com/aplane-algo/aplane/lsig/falcon1024/keygen"
)

func TestCmdSentryExportWritesEnvelopeFile(t *testing.T) {
	withPolicyCommandStore(t, func(_ string, passphrase []byte) {
		result, publicKeyHex := generateTestSentryComponentKey(t, passphrase)
		outputPath := filepath.Join(t.TempDir(), "sentry-public.json")

		if err := cmdSentry([]string{"export", result.Address, outputPath}); err != nil {
			t.Fatalf("cmdSentry(export) error = %v", err)
		}

		data, err := os.ReadFile(outputPath)
		if err != nil {
			t.Fatalf("ReadFile(export) error = %v", err)
		}
		var env sentryrefs.ExportEnvelope
		if err := json.Unmarshal(data, &env); err != nil {
			t.Fatalf("Unmarshal(export) error = %v", err)
		}
		if env.Schema != sentryrefs.ExportSchema {
			t.Fatalf("Schema = %q, want %q", env.Schema, sentryrefs.ExportSchema)
		}
		if env.ComponentKey != result.Address {
			t.Fatalf("ComponentKey = %q, want %q", env.ComponentKey, result.Address)
		}
		if env.KeyType != keytypes.SentryComponentFalcon1024V1 {
			t.Fatalf("KeyType = %q, want %q", env.KeyType, keytypes.SentryComponentFalcon1024V1)
		}
		if env.PublicKeyHex != publicKeyHex {
			t.Fatalf("PublicKeyHex = %q, want %q", env.PublicKeyHex, publicKeyHex)
		}
	})
}

func TestCmdSentryExportStdoutIsJSONOnly(t *testing.T) {
	withPolicyCommandStore(t, func(_ string, passphrase []byte) {
		result, _ := generateTestSentryComponentKey(t, passphrase)

		out, err := withCapturedStdout(func() error {
			return cmdSentry([]string{"export", result.Address})
		})
		if err != nil {
			t.Fatalf("cmdSentry(export stdout) error = %v", err)
		}
		if strings.Contains(out, "Enter store passphrase") {
			t.Fatalf("stdout contains passphrase prompt: %q", out)
		}
		var env sentryrefs.ExportEnvelope
		if err := json.Unmarshal([]byte(out), &env); err != nil {
			t.Fatalf("stdout is not a JSON envelope: %v\n%s", err, out)
		}
		if env.ComponentKey != result.Address {
			t.Fatalf("ComponentKey = %q, want %q", env.ComponentKey, result.Address)
		}
	})
}

func TestCmdSentryExportRequiresPublicSidecar(t *testing.T) {
	withPolicyCommandStore(t, func(_ string, passphrase []byte) {
		result, _ := generateTestSentryComponentKey(t, passphrase)
		path := apkeys.ComponentPublicMetadataPath(keystorePaths(), productIdentityID(), result.Address)
		if err := os.Remove(path); err != nil {
			t.Fatalf("Remove(component public metadata) error = %v", err)
		}

		err := cmdSentry([]string{"export", result.Address})
		if err == nil {
			t.Fatal("cmdSentry(export missing sidecar) error = nil, want missing metadata rejection")
		}
		if !strings.Contains(err.Error(), "sentry public metadata") {
			t.Fatalf("cmdSentry(export missing sidecar) error = %v, want metadata context", err)
		}
	})
}

func TestCmdSentryExportRejectsSpendingKey(t *testing.T) {
	withPolicyCommandStore(t, func(_ string, passphrase []byte) {
		masterKey := deriveTestMasterKey(t, passphrase)
		defer crypto.ZeroBytes(masterKey)

		result, err := keymgmt.GenerateKey(keystorePaths(), productIdentityID(), "ed25519", masterKey, nil)
		if err != nil {
			t.Fatalf("GenerateKey(ed25519) error = %v", err)
		}
		err = withTestStdin(string(passphrase)+"\n", func() error {
			return cmdSentry([]string{"export", result.Address})
		})
		if err == nil {
			t.Fatal("cmdSentry(export spending key) error = nil, want rejection")
		}
		if !strings.Contains(err.Error(), "invalid Sentry Key ID") {
			t.Fatalf("cmdSentry(export spending key) error = %v, want Sentry Key ID rejection", err)
		}
	})
}

func generateTestSentryComponentKey(t *testing.T, passphrase []byte) (*keygen.GenerationResult, string) {
	t.Helper()
	masterKey := deriveTestMasterKey(t, passphrase)
	defer crypto.ZeroBytes(masterKey)

	g := &falconkeygen.SentryFalcon1024Generator{}
	result, err := g.GenerateRandom(context.Background(), keystorePaths(), productIdentityID(), masterKey, keytypes.SentryComponentFalcon1024V1, nil)
	if err != nil {
		t.Fatalf("GenerateRandom(sentry-falcon1024) error = %v", err)
	}
	if result.PublicKeyHex == "" {
		t.Fatal("GenerateRandom(sentry-falcon1024) public key is empty")
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
