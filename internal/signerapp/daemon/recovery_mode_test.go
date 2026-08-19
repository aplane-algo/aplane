// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"os"
	"testing"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

func TestUnlockIdentityEntersRecoveryWithoutPublishingSigningState(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	passphrase := []byte("recovery-mode-test-passphrase")
	if _, err := crypto.CreateKeyringStore(
		paths.ProductDir(),
		passphrase,
	); err != nil {
		t.Fatalf("CreateKeyringStore() error = %v", err)
	}
	// A present-but-invalid CURRENT pointer fails generational
	// reconciliation at unlock: the recovery condition under test.
	if err := os.MkdirAll(paths.ProductDir(), 0o770); err != nil {
		t.Fatalf("MkdirAll(identity) error = %v", err)
	}
	if err := os.WriteFile(paths.CurrentPointerPath(), []byte("garbage"+"\n"), 0o660); err != nil {
		t.Fatalf("WriteFile(CURRENT) error = %v", err)
	}
	ir := identity.New(identity.Config{
		ID:            auth.DefaultIdentityID,
		KeyStore:      keystore.NewFileKeyStoreForPaths(paths),
		KeyPaths:      paths,
		Authenticator: auth.NewTokenAuthenticator("token"),
	})
	service := signerAdminServices{}

	success, keyCount, errMsg, code := service.UnlockIdentity(ir, passphrase)
	if !success || keyCount != 0 || errMsg != "" || code != protocol.ResultCodeRecoveryBlocked {
		t.Fatalf("UnlockIdentity() = (%v, %d, %q, %q)", success, keyCount, errMsg, code)
	}
	if !ir.IsRecovery() || ir.IsUnlocked() || ir.KeyCount() != 0 {
		t.Fatalf("identity state = recovery %v unlocked %v keys %d",
			ir.IsRecovery(),
			ir.IsUnlocked(),
			ir.KeyCount(),
		)
	}
	if err := ir.WithKeyring(func(*crypto.Keyring) error { return nil }); err != nil {
		t.Fatalf("WithKeyring(recovery) error = %v", err)
	}
	ir.Lock()
	if err := ir.WithKeyring(func(*crypto.Keyring) error { return nil }); err == nil {
		t.Fatal("WithKeyring(after lock) error = nil")
	}
}
