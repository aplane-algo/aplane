// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storepaths

// ActivePaths is the resolved handle to an identity's active key and
// key-type namespaces. Consumers take this instead of deriving those paths
// from Paths, so one operation resolves the layout exactly once (under the
// identity mutation lock, via internal/genstore.ResolveActive) and passes
// the result down — never re-resolving mid-operation. GenPaths implements
// it for the generation layout.
// until gate 5 removes the flat layout entirely.
type ActivePaths interface {
	KeysDir() string
	KeyTypeRecordsDir() string
	KeyTypeRecord(keyType string) string
	KeyTypeTemplate(keyType string) string
}

var _ ActivePaths = GenPaths{}
var _ ActivePaths = legacyActivePaths{}

type legacyActivePaths struct {
	p          Paths
	identityID string
}

func (l legacyActivePaths) KeysDir() string           { return l.p.KeysDir(l.identityID) }
func (l legacyActivePaths) KeyTypeRecordsDir() string { return l.p.KeyTypeRecordsDir(l.identityID) }
func (l legacyActivePaths) KeyTypeRecord(keyType string) string {
	return l.p.KeyTypeRecord(l.identityID, keyType)
}
func (l legacyActivePaths) KeyTypeTemplate(keyType string) string {
	return l.p.KeyTypeTemplate(l.identityID, keyType)
}
