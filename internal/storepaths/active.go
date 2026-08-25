// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storepaths

// ActivePaths is the resolved handle to an identity's active key and
// key-type namespaces. Consumers take this instead of deriving those paths
// from Paths, so one operation resolves the layout exactly once (under the
// store mutation lock, via internal/genstore.ResolveActive) and passes
// the result down — never re-resolving mid-operation. GenPaths is the sole
// implementation: every store is generation-based.
type ActivePaths interface {
	KeysDir() string
	KeyTypeRecordsDir() string
	KeyTypeRecord(keyType string) string
	KeyTypeTemplate(keyType string) string
}

var _ ActivePaths = GenPaths{}
