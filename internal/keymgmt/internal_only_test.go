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

func TestInternalOnlyRejectsDirectCreationWithStaleActivation(t *testing.T) {
	paths := genstoretest.MintFirst(t, storepaths.NewPaths(t.TempDir()))
	for _, keyType := range []string{"aplane.falcon1024.v1", "aplane.ed25519.v1"} {
		activated := []string{keyType}
		if _, err := GenerateKeyWithActivatedContext(context.Background(), paths, keyType, nil, nil, activated); err == nil || !strings.Contains(err.Error(), "invalid key type") {
			t.Fatalf("GenerateKey(%s) = %v", keyType, err)
		}
		if _, err := ImportKeyWithActivatedContext(context.Background(), paths, keyType, "unused phrase", nil, nil, activated); err == nil || !strings.Contains(err.Error(), "invalid key type") {
			t.Fatalf("ImportKey(%s) = %v", keyType, err)
		}
	}
}
