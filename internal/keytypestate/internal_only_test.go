// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keytypestate

import (
	"os"
	"testing"

	"github.com/aplane-algo/aplane/internal/genstore/genstoretest"
	"github.com/aplane-algo/aplane/internal/keytypecatalog"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

func TestInternalOnlyOverridesEnablementWithoutIgnoringCorruption(t *testing.T) {
	const keyType = "test.internal-state.v1"
	keytypecatalog.Register(keytypecatalog.Entry{KeyType: keyType, Family: "test.internal-state", Availability: keytypecatalog.AvailabilityInternalOnly})
	paths := genstoretest.MintFirst(t, storepaths.NewPaths(t.TempDir()))
	for _, state := range []State{"", StateEnabled, StateDisabled} {
		if state != "" {
			if err := Put(paths, Record{KeyType: keyType, Source: SourceCompiled, State: state}); err != nil {
				t.Fatal(err)
			}
		}
		if allowed, err := CanGenerate(paths, keyType); allowed || err != nil {
			t.Fatalf("CanGenerate(state %q) = %v, %v", state, allowed, err)
		}
	}
	if err := os.WriteFile(genstoretest.Active(t, paths).KeyTypeRecord(keyType), []byte("{invalid"), 0o600); err != nil {
		t.Fatal(err)
	}
	if allowed, err := CanGenerate(paths, keyType); allowed || err == nil {
		t.Fatalf("CanGenerate(corrupt) = %v, %v; want storage error", allowed, err)
	}
}
