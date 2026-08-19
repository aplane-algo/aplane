// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"context"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keygen"
	"github.com/aplane-algo/aplane/internal/keymgmt"
	"github.com/aplane-algo/aplane/internal/witness"
	falconkeygen "github.com/aplane-algo/aplane/lsig/falcon1024/keygen"
)

func TestCmdKeysListShowsIdentityKeyInventory(t *testing.T) {
	withPolicyCommandStore(t, func(_ string, passphrase []byte) {
		kr := deriveTestKeyring(t, passphrase)
		edResult, err := keymgmt.GenerateKey(keystorePaths(), "ed25519", kr, nil)
		if err != nil {
			t.Fatalf("GenerateKey(ed25519) error = %v", err)
		}
		attResult, attPublicHex := generateTestSentryComponentKey(t, passphrase)

		out, err := withCapturedStdout(func() error {
			return withTestStdin(string(passphrase)+"\n", func() error {
				return cmdKeys([]string{"list"})
			})
		})
		if err != nil {
			t.Fatalf("cmdKeys(list) error = %v", err)
		}

		for _, want := range []string{"ADDRESS/SELECTOR", edResult.Address} {
			if !strings.Contains(out, want) {
				t.Fatalf("list output = %q, want %q", out, want)
			}
		}
		if !strings.Contains(out, attResult.Address) {
			t.Fatalf("list output = %q, want Witness Key ID %q", out, attResult.Address)
		}
		if !strings.Contains(out, "ed25519") {
			t.Fatalf("list output = %q, want ed25519 key type", out)
		}
		if !strings.Contains(out, "aplane.witness-falcon1024.v1") {
			t.Fatalf("list output = %q, want sentry key type display", out)
		}
		if strings.Contains(out, edResult.PublicKeyHex) {
			t.Fatalf("list output exposed Ed25519 public key hex: %q", out)
		}
		if strings.Contains(out, attPublicHex) {
			t.Fatalf("list output exposed sentry public key hex: %q", out)
		}
	})
}

func generateTestSentryComponentKey(t *testing.T, passphrase []byte) (*keygen.GenerationResult, string) {
	t.Helper()
	kr := deriveTestKeyring(t, passphrase)
	generator := &falconkeygen.WitnessFalcon1024Generator{}
	result, err := generator.GenerateRandom(context.Background(), keystorePaths(), kr, witness.Falcon1024V1, nil)
	if err != nil {
		t.Fatalf("GenerateRandom(sentry-falcon1024) error = %v", err)
	}
	if result.PublicKeyHex == "" {
		t.Fatal("GenerateRandom(sentry-falcon1024) public key is empty")
	}
	return result, result.PublicKeyHex
}

func deriveTestKeyring(t *testing.T, passphrase []byte) *crypto.Keyring {
	t.Helper()
	keyring, err := crypto.OpenKeyringStore(keystorePaths().KeystoreMetadataDir(), passphrase)
	if err != nil {
		t.Fatalf("OpenKeyringStore() error = %v", err)
	}
	t.Cleanup(keyring.Zero)
	return keyring
}

func TestCmdKeysRejectsUnknownSubcommand(t *testing.T) {
	err := cmdKeys([]string{"show"})
	if err == nil || !strings.Contains(err.Error(), "usage: apstore keys list") {
		t.Fatalf("cmdKeys(show) error = %v, want usage error", err)
	}
}
