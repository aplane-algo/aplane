// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keytypecatalog

import "testing"

// EntriesForTest returns every cataloged key type, of every availability:
// DefaultEnabled and LibraryVisible leave out internal-only and disabled ones.
func EntriesForTest() []Entry {
	return filter(func(Entry) bool { return true })
}

// unregisterForTest removes a synthetic entry a test of this package
// registered, so the catalog other tests in this binary iterate holds only
// real key types.
func unregisterForTest(t *testing.T, keyType string) {
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		delete(entries, Canonicalize(keyType))
	})
}
