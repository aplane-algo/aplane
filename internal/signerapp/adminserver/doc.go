// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package adminserver implements the server side of the admin protocol:
// session lifecycle, request dispatch, message handlers, displacement, and
// the service interfaces the daemon wires its admin facets into. The wire
// contract it speaks lives in internal/adminproto, which must remain free of
// signer-daemon internals.
package adminserver
