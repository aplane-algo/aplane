// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keymgmt

import (
	"context"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/genstore/genstoretest"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// The Ed25519 plain host is opt-in: without activation it is not a valid key
// type. The Falcon one is enabled by default. With activation (or by default) a
// request reaches generation (which needs algod here). Mnemonic import stays
// native-only.
func TestPlainHostsAreOptIn(t *testing.T) {
	paths := genstoretest.MintFirst(t, storepaths.NewPaths(t.TempDir()))
	if _, err := GenerateKeyWithActivatedContext(context.Background(), paths, "aplane.falcon1024.v1", nil, nil, nil); err == nil || !strings.Contains(err.Error(), "algod client not set") {
		t.Fatalf("GenerateKey(aplane.falcon1024.v1) without activation = %v, want it to reach LogicSig derivation", err)
	}
	for _, keyType := range []string{"aplane.falcon1024.v1", "aplane.ed25519.v1"} {
		if keyType == "aplane.ed25519.v1" {
			if _, err := GenerateKeyWithActivatedContext(context.Background(), paths, keyType, nil, nil, nil); err == nil || !strings.Contains(err.Error(), "invalid key type") {
				t.Fatalf("GenerateKey(%s) without activation = %v", keyType, err)
			}
		}
		activated := []string{keyType}
		if _, err := GenerateKeyWithActivatedContext(context.Background(), paths, keyType, nil, nil, activated); err == nil || !strings.Contains(err.Error(), "algod client not set") {
			t.Fatalf("GenerateKey(%s) = %v, want it to reach LogicSig derivation", keyType, err)
		}
		if _, err := ImportKeyWithActivatedContext(context.Background(), paths, keyType, "unused phrase", nil, nil, activated); err == nil || !strings.Contains(err.Error(), "mnemonic import not supported") {
			t.Fatalf("ImportKey(%s) = %v", keyType, err)
		}
	}
}
