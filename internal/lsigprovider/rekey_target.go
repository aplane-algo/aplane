// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package lsigprovider

import "github.com/aplane-algo/aplane/internal/keytypecatalog"

// RekeyTargetDeclarer is implemented only by an installed template's
// provider: ValidRekeyTarget is the template's valid_rekey_target, the
// author's declaration that an aplane key of this type may be the signing
// authority an account is rekeyed to, its own account included, subject to its
// program. A compiled key type declares the attribute in its catalog entry,
// the one place it is declared, and its providers do not implement this.
type RekeyTargetDeclarer interface {
	// RekeyTargetDeclaration is the template's valid_rekey_target and whether
	// it declares one: a template loaded without the field declares nothing.
	RekeyTargetDeclaration() (valid, declared bool)
}

// ResolveValidRekeyTarget resolves keyType's valid_rekey_target declaration
// and reports whether it resolved: from the catalog entry of a compiled key
// type, or from the provider of an installed template that declares it
// (RekeyTargetDeclarer). ok is false for any other key type. It is a Resolve-axis question: it needs
// the registries. Key creation reads it and fails on !ok (keygen.SaveNewKey),
// so no key records a value its key type never declared; the signer's rekey
// check reads the key's recorded value.
func ResolveValidRekeyTarget(keyType string) (valid, ok bool) {
	if entry, found := keytypecatalog.Get(keyType); found {
		return entry.ValidRekeyTarget, true
	}
	if declarer, found := Get(keyType).(RekeyTargetDeclarer); found {
		return declarer.RekeyTargetDeclaration()
	}
	return false, false
}

// ValidRekeyTarget is ResolveValidRekeyTarget for a read that creates nothing,
// such as the /keytypes listing: a key type whose declaration does not
// resolve reads as not a valid rekey target.
func ValidRekeyTarget(keyType string) bool {
	valid, _ := ResolveValidRekeyTarget(keyType)
	return valid
}
