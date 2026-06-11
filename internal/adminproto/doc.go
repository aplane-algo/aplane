// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package adminproto defines the transport-neutral admin protocol wire
// contract: message and result types, setting-name constants, and the framed
// AdminConn transport. It must stay free of signer-daemon internals so
// control-plane clients can link it without pulling in the server stack;
// dispatch, session, and service plumbing live in
// internal/signerapp/adminserver. test/arch/layering_test.go enforces the
// boundary.
package adminproto
