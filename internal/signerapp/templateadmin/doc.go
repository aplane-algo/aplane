// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package templateadmin owns live administrative template and key-type
// workflows: identity-mutation locking, calls into templatelibrary, runtime
// reload and acceptance decisions, wire results, and logging. It does not call
// primitive template or key-type persistence writers directly.
package templateadmin
