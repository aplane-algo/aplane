// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package lsigprovider_test

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/lsigprovider"
)

type declaringProvider struct {
	lsigprovider.LSigProvider
	keyType  string
	valid    bool
	declared bool
}

var _ lsigprovider.RekeyTargetDeclarer = declaringProvider{}

func (p declaringProvider) KeyType() string       { return p.keyType }
func (p declaringProvider) RoutingFamily() string { return p.keyType }
func (p declaringProvider) Version() int          { return 1 }
func (p declaringProvider) Category() string      { return lsigprovider.CategoryGenericLsig }
func (p declaringProvider) RekeyTargetDeclaration() (valid, declared bool) {
	return p.valid, p.declared
}

// An installed template's provider declares the attribute. A template that
// declares nothing and an unknown key type do not resolve, and the non-creating
// read takes them as not a valid rekey target.
func TestResolveValidRekeyTargetReadsATemplateAndReportsUnresolved(t *testing.T) {
	lsigprovider.RegisterIfAbsent(declaringProvider{keyType: "test.rekey-target-valid.v1", valid: true, declared: true})
	lsigprovider.RegisterIfAbsent(declaringProvider{keyType: "test.rekey-target-invalid.v1", declared: true})
	lsigprovider.RegisterIfAbsent(declaringProvider{keyType: "test.rekey-target-undeclared.v1"})
	for _, tc := range []struct {
		keyType   string
		valid, ok bool
	}{
		{"test.rekey-target-valid.v1", true, true},
		{"test.rekey-target-invalid.v1", false, true},
		{"test.rekey-target-undeclared.v1", false, false},
		{"test.never-registered.v1", false, false},
	} {
		valid, ok := lsigprovider.ResolveValidRekeyTarget(tc.keyType)
		if valid != tc.valid || ok != tc.ok {
			t.Errorf("ResolveValidRekeyTarget(%s) = %v, %v; want %v, %v", tc.keyType, valid, ok, tc.valid, tc.ok)
		}
		if got := lsigprovider.ValidRekeyTarget(tc.keyType); got != tc.valid {
			t.Errorf("ValidRekeyTarget(%s) = %v, want %v", tc.keyType, got, tc.valid)
		}
	}
}
