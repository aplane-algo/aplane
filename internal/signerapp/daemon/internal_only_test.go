// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"bytes"
	"context"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keygen"
)

// Build a pre-existing credential through internal derivation, without reopening
// the public creation route. These tests exercise signing/deleting old accounts.
func existingFalconCredentialForTest(t *testing.T, server *Signer) string {
	t.Helper()
	generator, err := keygen.GetGenerator("aplane.falcon1024.v1")
	if err != nil {
		t.Fatal(err)
	}
	var address string
	err = server.productRuntime().WithKeyring(func(kr *crypto.Keyring) error {
		result, err := generator.GenerateFromSeed(context.Background(), mustActiveKeyPaths(t, server), bytes.Repeat([]byte{0x42}, 64), kr, "aplane.falcon1024.v1", nil)
		if err == nil {
			address = result.Address
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return address
}
