// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"github.com/aplane-algo/aplane/internal/crypto/cryptotest"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keymgmt"
)

func TestCmdKeysListShowsIdentityKeyInventory(t *testing.T) {
	withPolicyCommandStore(t, func(_ string, passphrase []byte) {
		masterKey := deriveTestMasterKey(t, passphrase)
		edResult, err := keymgmt.GenerateKey(keystorePaths(), productIdentityID(), "ed25519", cryptotest.Keyring(t, masterKey), nil)
		crypto.ZeroBytes(masterKey)
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

func TestCmdKeysRejectsUnknownSubcommand(t *testing.T) {
	err := cmdKeys([]string{"show"})
	if err == nil || !strings.Contains(err.Error(), "usage: apstore keys list") {
		t.Fatalf("cmdKeys(show) error = %v, want usage error", err)
	}
}
