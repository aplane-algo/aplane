// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package lsigprovider

import "github.com/aplane-algo/aplane/internal/keytypecatalog"

// RekeyTargetDeclarer is implemented by an installed template's provider:
// ValidRekeyTarget is the template's valid_rekey_target attribute, whether an
// account of another key type may safely be rekeyed to an account of this key
// type. A compiled key type declares the same attribute in its catalog entry.
type RekeyTargetDeclarer interface {
	ValidRekeyTarget() bool
}

// ValidRekeyTarget resolves keyType's valid_rekey_target declaration: whether
// an account of another key type may safely be rekeyed to an account of this
// key type. A compiled key type declares it in its catalog entry, which is
// read first; an installed template declares it in its YAML
// (RekeyTargetDeclarer). It is a Resolve-axis question: it needs the
// registries. It is read when an aplane key is created, which records the
// value (keys.Payload.ValidRekeyTarget), and by /keytypes; the signer's rekey
// check reads the key's recorded value. An unknown key type is not a valid
// rekey target.
func ValidRekeyTarget(keyType string) bool {
	if entry, ok := keytypecatalog.Get(keyType); ok {
		return entry.ValidRekeyTarget
	}
	if declarer, ok := Get(keyType).(RekeyTargetDeclarer); ok {
		return declarer.ValidRekeyTarget()
	}
	return false
}
