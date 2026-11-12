// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package lsigprovider_test

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
	// A DSA private key controls each of these; an account rekeyed to one can
	// be rekeyed away again.
	"ed25519":              true,
	"falcon1024":           true,
	"aplane.falcon1024.v1": true,
	"aplane.ed25519.v1":    true,
	// A rotating account's address is its one-time stage 0 program;
	// rejectRekeyToRotating refuses a rekey to it on its own as well.
	"aplane.rotating-triple-xmss.v1":   false,
	"aplane.rotating-triple-slhdsa.v1": false,
	"aplane.rotating-triple-wotsc.v1":  false,
	// A witness key is a cosigner's component key, not an account.
	"aplane.witness-falcon1024.v1": false,
}

func TestEveryCompiledKeyTypeDeclaresValidRekeyTarget(t *testing.T) {
	lsigsignerreg.RegisterSigner()
	ed25519signerreg.RegisterSigner()
	nativefalconsignerreg.RegisterSigner()

	seen := map[string]bool{}
	for _, entry := range append(keytypecatalog.DefaultEnabled(), keytypecatalog.LibraryVisible()...) {
		want, ok := declaredValidRekeyTarget[entry.KeyType]
		if !ok {
			t.Errorf("compiled key type %s has no valid_rekey_target decision in this test", entry.KeyType)
			continue
		}
		seen[entry.KeyType] = true
		if entry.ValidRekeyTarget != want {
			t.Errorf("%s: catalog ValidRekeyTarget = %v, want %v", entry.KeyType, entry.ValidRekeyTarget, want)
		}
		if got := lsigprovider.ValidRekeyTarget(entry.KeyType); got != want {
			t.Errorf("lsigprovider.ValidRekeyTarget(%s) = %v, want %v", entry.KeyType, got, want)
		}
	}
	for keyType := range declaredValidRekeyTarget {
		if !seen[keyType] {
			t.Errorf("%s is decided here but not registered", keyType)
		}
	}
}

type declaringProvider struct {
	lsigprovider.LSigProvider
	keyType string
	valid   bool
}

func (p declaringProvider) KeyType() string        { return p.keyType }
func (p declaringProvider) RoutingFamily() string  { return p.keyType }
func (p declaringProvider) Version() int           { return 1 }
func (p declaringProvider) Category() string       { return lsigprovider.CategoryGenericLsig }
func (p declaringProvider) ValidRekeyTarget() bool { return p.valid }

// An installed template's provider declares the attribute; an unknown key
// type is not a valid rekey target.
func TestValidRekeyTargetReadsATemplateAndFailsClosed(t *testing.T) {
	lsigprovider.RegisterIfAbsent(declaringProvider{keyType: "test.rekey-target-valid.v1", valid: true})
	lsigprovider.RegisterIfAbsent(declaringProvider{keyType: "test.rekey-target-invalid.v1", valid: false})
	if !lsigprovider.ValidRekeyTarget("test.rekey-target-valid.v1") {
		t.Error("a template declaring valid_rekey_target true reads false")
	}
	if lsigprovider.ValidRekeyTarget("test.rekey-target-invalid.v1") {
		t.Error("a template declaring valid_rekey_target false reads true")
	}
	if lsigprovider.ValidRekeyTarget("test.never-registered.v1") {
		t.Error("an unknown key type reads as a valid rekey target")
	}
}
