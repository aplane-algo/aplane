// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// RequestID is the ID a signing or planning request is handled under: the
// request_id the client supplied or, when it supplied none, a new ID minted
// here, req- and 16 hex digits from crypto/rand. It is the one place the
// signer mints a request ID. The HTTP handlers call it before anything is
// logged, so the audit operation_id, the approval prompt, /sign/cancel and a
// response that returns an ID all carry the same value; the service calls it
// again wherever a request can reach the approval coordinator or a response
// with an ID, which keeps a direct caller that supplies none working and is
// a no-op for a request the handler already settled.
//
// A minted ID is random, not a clock reading, so two requests that arrive in
// the same instant cannot share one: they would share an operation_id and a
// cancel handle, and a cancel for one would stop the other. It is 20
// characters, the most of a waiting request's ID the signer console prints
// (requestIDPreview), so the console shows it whole; 64 random bits make two
// minted IDs equal with negligible probability. A supplied ID is the
// client's, used as given: the signer does not check that it is unique.
func RequestID(supplied string) string {
	if supplied != "" {
		return supplied
	}
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		// Unreachable: crypto/rand.Read ends the program rather than
		// return an error.
		panic(fmt.Sprintf("generate request ID: %v", err))
	}
	return "req-" + hex.EncodeToString(suffix[:])
}
