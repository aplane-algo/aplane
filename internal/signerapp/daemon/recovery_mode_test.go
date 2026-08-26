// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"os"
	"testing"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore/genstoretest"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

func TestUnlockIdentityEntersRecoveryWithoutPublishingSigningState(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	passphrase := []byte("recovery-mode-test-passphrase")
	keyring, active := genstoretest.MintFirstAtomic(t, paths, passphrase)
	keyring.Zero()
	// A valid authenticated root selecting damaged generation content is the
	// recovery condition: authority remains known, but signing stays blocked.
	if err := os.RemoveAll(active.Dir()); err != nil {
		t.Fatalf("RemoveAll(selected generation) error = %v", err)
	}
	ir := productruntime.New(productruntime.Config{

		KeyStore:      keystore.NewAtomicFileKeyStoreForPaths(paths),
		KeyPaths:      paths,
		Authenticator: auth.NewTokenAuthenticator("token"),
	})
	service := signerAdminServices{product: ir}

	success, keyCount, errMsg, code := service.UnlockIdentity(passphrase)
	if !success || keyCount != 0 || errMsg != "" || code != protocol.ResultCodeRecoveryBlocked {
		t.Fatalf("UnlockIdentity() = (%v, %d, %q, %q)", success, keyCount, errMsg, code)
	}
	if !ir.IsRecovery() || ir.IsUnlocked() || ir.KeyCount() != 0 {
		t.Fatalf("runtime state = recovery %v unlocked %v keys %d",
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
