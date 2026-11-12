// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keytypecatalog_test

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/keytypecatalog"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	ed25519signerreg "github.com/aplane-algo/aplane/internal/signing/ed25519/signerreg"
	nativefalconsignerreg "github.com/aplane-algo/aplane/internal/signing/falcon1024/signerreg"
	lsigsignerreg "github.com/aplane-algo/aplane/lsig/signerreg"
)

// declaredValidRekeyTarget is every compiled key type's valid_rekey_target.
// A compiled key type added without a decision here fails the test.
var declaredValidRekeyTarget = map[string]bool{
	// An aplane key of each of these may be the signing authority an account
	// is rekeyed to, its own account included, subject to its own
	// restrictions.
	"ed25519":              true,
	"falcon1024":           true,
	"aplane.falcon1024.v1": true,
	"aplane.ed25519.v1":    true,
	// A rotating account's address is its one-time stage 0 program, for
	// another account and for its own.
	"aplane.rotating-triple-xmss.v1":   false,
	"aplane.rotating-triple-slhdsa.v1": false,
	"aplane.rotating-triple-wotsc.v1":  false,
	// A witness key is a cosigner's component key, not an account.
	"aplane.witness-falcon1024.v1": false,
}

// Every catalog entry, whatever its availability (default-enabled, library,
// internal-only or disabled), has a decision here. The catalog is a compiled
// key type's only source: it resolves from there, and its registered provider
// does not declare the attribute itself, so nothing can disagree with it.
func TestEveryCompiledKeyTypeDeclaresValidRekeyTarget(t *testing.T) {
	lsigsignerreg.RegisterSigner()
	ed25519signerreg.RegisterSigner()
	nativefalconsignerreg.RegisterSigner()

	seen := map[string]bool{}
	for _, entry := range keytypecatalog.EntriesForTest() {
		want, ok := declaredValidRekeyTarget[entry.KeyType]
		if !ok {
			t.Errorf("compiled key type %s (%s) has no valid_rekey_target decision in this test", entry.KeyType, entry.Availability)
			continue
		}
		seen[entry.KeyType] = true
		if entry.ValidRekeyTarget != want {
			t.Errorf("%s: catalog ValidRekeyTarget = %v, want %v", entry.KeyType, entry.ValidRekeyTarget, want)
		}
		if got, resolved := lsigprovider.ResolveValidRekeyTarget(entry.KeyType); got != want || !resolved {
			t.Errorf("lsigprovider.ResolveValidRekeyTarget(%s) = %v, %v; want %v, true", entry.KeyType, got, resolved, want)
		}
		if _, declares := lsigprovider.Get(entry.KeyType).(lsigprovider.RekeyTargetDeclarer); declares {
			t.Errorf("%s: the registered provider declares valid_rekey_target; a compiled key type declares it in its catalog entry only", entry.KeyType)
		}
	}
	for keyType := range declaredValidRekeyTarget {
		if !seen[keyType] {
			t.Errorf("%s is decided here but not registered", keyType)
		}
	}
}
