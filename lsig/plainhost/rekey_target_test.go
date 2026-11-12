// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package plainhost_test

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/keytypecatalog"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/lsig/clientreg"
	"github.com/aplane-algo/aplane/lsig/plainhost"
)

// A plain host and every program it offers, plain1 arrangements and bounded2
// shapes alike, answer valid_rekey_target from the host's catalog entry, the
// one place a compiled key type declares it. A direct type assertion agrees
// with the catalog, as lsigprovider.ValidRekeyTarget does.
func TestPlainHostProgramsAnswerTheCatalogsValidRekeyTarget(t *testing.T) {
	clientreg.RegisterClient()
	for _, keyType := range []string{"aplane.falcon1024.v1", "aplane.ed25519.v1"} {
		t.Run(keyType, func(t *testing.T) {
			entry, ok := keytypecatalog.Get(keyType)
			if !ok || !entry.ValidRekeyTarget {
				t.Fatalf("catalog entry = %+v, %v; want a valid rekey target", entry, ok)
			}
			host, ok := lsigprovider.Get(keyType).(*plainhost.Provider)
			if !ok {
				t.Fatalf("registered provider for %s is %T, want *plainhost.Provider", keyType, lsigprovider.Get(keyType))
			}
			var declarer lsigprovider.RekeyTargetDeclarer = host
			if declarer.ValidRekeyTarget() != entry.ValidRekeyTarget {
				t.Fatalf("plain host answers %v, catalog says %v", declarer.ValidRekeyTarget(), entry.ValidRekeyTarget)
			}
			composers := host.ProgramComposersForTest()
			if len(composers) == 0 {
				t.Fatal("the plain host offers no programs")
			}
			for i, composer := range composers {
				if composer.ValidRekeyTarget() != entry.ValidRekeyTarget {
					t.Fatalf("program %d answers %v, catalog says %v", i, composer.ValidRekeyTarget(), entry.ValidRekeyTarget)
				}
			}
		})
	}
}
