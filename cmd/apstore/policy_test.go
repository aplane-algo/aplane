// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"os"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/storeinit"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

func TestCmdPolicyCheckAcceptsInitializedBaseline(t *testing.T) {
	withPolicyCommandStore(t, func(string, []byte) {
		if err := cmdPolicy([]string{"check"}); err != nil {
			t.Fatalf("cmdPolicy(check) error = %v", err)
		}
	})
}

func TestCmdPolicyCheckAcceptsValidTransferRoutingPolicy(t *testing.T) {
	withPolicyCommandStore(t, func(root string, _ []byte) {
		addr := types.Address{1}.String()
		raw := []byte(`
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  routes:
    - id: valid_route
      networks: [testnet]
      sources: ["*"]
      assets: ["algo"]
      destinations: ["` + addr + `"]
`)
		if err := os.WriteFile(policy.PolicyPath(root, productIdentityID()), raw, 0o600); err != nil {
			t.Fatalf("WriteFile(policy) error = %v", err)
		}
		if err := cmdPolicy([]string{"check"}); err != nil {
			t.Fatalf("cmdPolicy(check) error = %v, want valid transfer routing policy accepted", err)
		}
	})
}

func TestCmdPolicySignRepairsDirectEdit(t *testing.T) {
	withPolicyCommandStore(t, func(root string, passphrase []byte) {
		policyPath := policy.PolicyPath(root, productIdentityID())
		policyBytes := []byte("# direct policy edit\nreject_foreign_rekey: false\n")
		if err := os.WriteFile(policyPath, policyBytes, 0o600); err != nil {
			t.Fatalf("WriteFile(policy) error = %v", err)
		}

		err := withTestStdin(string(passphrase)+"\n", func() error {
			return cmdPolicy([]string{"verify"})
		})
		if err == nil {
			t.Fatal("cmdPolicy(verify) error = nil, want mismatch before signing")
		}
		if !strings.Contains(err.Error(), "policy.yaml integrity verification failed") {
			t.Fatalf("cmdPolicy(verify) error = %v, want integrity failure", err)
		}

		if err := withTestStdin(string(passphrase)+"\n", func() error {
			return cmdPolicy([]string{"sign"})
		}); err != nil {
			t.Fatalf("cmdPolicy(sign) error = %v", err)
		}
		gotBytes, err := os.ReadFile(policyPath)
		if err != nil {
			t.Fatalf("ReadFile(policy) error = %v", err)
		}
		if string(gotBytes) != string(policyBytes) {
			t.Fatalf("policy bytes changed during sign:\ngot  %q\nwant %q", string(gotBytes), string(policyBytes))
		}
		if err := withTestStdin(string(passphrase)+"\n", func() error {
			return cmdPolicy([]string{"verify"})
		}); err != nil {
			t.Fatalf("cmdPolicy(verify after sign) error = %v", err)
		}
	})
}

func TestCmdPolicyCheckRejectsMalformedPolicy(t *testing.T) {
	withPolicyCommandStore(t, func(root string, _ []byte) {
		if err := os.WriteFile(policy.PolicyPath(root, productIdentityID()), []byte("reject_foreign_rekey: [\n"), 0o600); err != nil {
			t.Fatalf("WriteFile(policy) error = %v", err)
		}
		err := cmdPolicy([]string{"check"})
		if err == nil || !strings.Contains(err.Error(), "failed to parse policy.yaml config") {
			t.Fatalf("cmdPolicy(check) error = %v, want parse failure", err)
		}
	})
}

func TestCmdPolicyCheckRejectsInvalidTransferRoutingPolicy(t *testing.T) {
	withPolicyCommandStore(t, func(root string, _ []byte) {
		raw := []byte(`
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  routes:
    - id: bad.route
      networks: [testnet]
      sources: ["*"]
      assets: ["algo"]
      destinations: ["*"]
`)
		if err := os.WriteFile(policy.PolicyPath(root, productIdentityID()), raw, 0o600); err != nil {
			t.Fatalf("WriteFile(policy) error = %v", err)
		}
		err := cmdPolicy([]string{"check"})
		if err == nil || !strings.Contains(err.Error(), "policy.yaml config invalid") {
			t.Fatalf("cmdPolicy(check) error = %v, want transfer routing validation failure", err)
		}
	})
}

func TestCmdPolicyCheckRejectsInvalidSentryReviewPolicy(t *testing.T) {
	withPolicyCommandStoreWithRole(t, noderole.RoleSentry, func(root string, _ []byte) {
		raw := []byte("always_review_warnings: true\n")
		if err := os.WriteFile(policy.PolicyPath(root, productIdentityID()), raw, 0o600); err != nil {
			t.Fatalf("WriteFile(policy) error = %v", err)
		}
		err := cmdPolicy([]string{"check"})
		if err == nil || !strings.Contains(err.Error(), "sentry.always_review_warnings") {
			t.Fatalf("cmdPolicy(check) error = %v, want sentry review rejection", err)
		}
	})
}

func withPolicyCommandStore(t *testing.T, fn func(root string, passphrase []byte)) {
	t.Helper()
	withPolicyCommandStoreWithRole(t, noderole.RoleSigner, fn)
}

func withPolicyCommandStoreWithRole(t *testing.T, role noderole.Role, fn func(root string, passphrase []byte)) {
	t.Helper()
	RegisterProviders()

	oldDataDirectory := dataDirectory
	oldConfig := config
	oldReader := stdinReader
	t.Cleanup(func() {
		dataDirectory = oldDataDirectory
		config = oldConfig
		stdinReader = oldReader
	})

	root := t.TempDir()
	dataDirectory = root
	config = serverconfig.DefaultServerConfig()
	stdinReader = nil
	passphrase := []byte("policy-passphrase")
	if _, err := storeinit.Initialize(passphrase, storeinit.Options{
		DataDir:    root,
		Paths:      storepaths.NewPaths(root),
		IdentityID: productIdentityID(),
		Role:       role,
	}); err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	fn(root, passphrase)
}
