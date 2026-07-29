// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package crypto

// KeyringFromMasterKeyForMigration wraps a raw term-1 key as a keyring.
//
// It exists only while phase 2 is in flight. A subsystem that has migrated
// threads a *Keyring; one that has not still threads raw bytes, and this is
// the adapter at the boundary between them. Every use is a subsystem that
// still owes the migration, so the count only goes down.
//
// The caller owns the returned keyring and must Zero it. Phase 2's last slice
// deletes this function, which turns any remaining boundary into a build
// failure rather than something to notice.
//
// That slice also deletes FileKeyStore.WithMasterKey and Keyring.CurrentTermKey
// and unexports the raw-key envelope functions. Run those deletions against
// the tagged tree as well as the untagged one: cmd/apadmin/batch.go sits behind
// //go:build testmode and is invisible to a plain `go build ./...`, so a
// surviving tagged call site would break only the integration harness.
func KeyringFromMasterKeyForMigration(masterKey []byte) (*Keyring, error) {
	return NewKeyringFromKey(masterKey)
}
