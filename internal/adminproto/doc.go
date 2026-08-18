// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package adminproto defines the transport-neutral admin service vocabulary:
// domain requests and results, setting-name constants, and the framed
// server-side AdminConn transport. It is not the compatibility-bearing JSON
// wire contract; internal/protocol owns wire messages, envelopes, field names,
// and versioning, while internal/signerapp/adminserver owns their projection to
// and from these domain values. The package must stay free of signer-daemon
// internals so control-plane services can link it without pulling in the server
// stack. test/arch/layering_test.go enforces that boundary.
package adminproto
