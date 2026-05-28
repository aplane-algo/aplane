// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integration_test

// Mnemonic export is intentionally disabled in the admin protocol so that key
// material never leaves the signer machine. The previous round-trip suite that
// exercised generate→export→import has been removed: its determinism premise
// (re-importing the exported mnemonic produces the same address) cannot be
// observed end-to-end from the client side anymore.
//
// Coverage that remains:
//   - Per-algorithm derivation determinism is exercised in the lsig/* packages
//     (e.g. lsig/falcon1024/keygen, lsig/falcon1024/derivation).
//   - The protocol-level guarantee that keys.export is denied on every admin
//     transport is covered in internal/adminproto/key_transport_test.go.
//   - End-to-end recovery is now backup/restore; portability is exercised in
//     test/integration/backup_portability_test.go.
