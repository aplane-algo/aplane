// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"context"
	"net/http"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
)

// productAuthenticator identifies an HTTP request by the connection it
// arrived on. The SSH server verified an enrolled key and the HTTP server
// attached that key's fingerprint to the connection context; nothing in the
// request itself is a credential. Enrollment is checked again on every
// request, including keep-alive requests, so a key revoked while its
// connection is open stops authenticating at once.
type productAuthenticator struct {
	nodeFailState *productruntime.NodeFailState
	runtime       *productruntime.Runtime
}

func newProductAuthenticator(nodeFailState *productruntime.NodeFailState, runtime *productruntime.Runtime) *productAuthenticator {
	return &productAuthenticator{nodeFailState: nodeFailState, runtime: runtime}
}

func (a *productAuthenticator) Authenticate(ctx context.Context, _ *http.Request) (*auth.Identity, error) {
	if a.nodeFailState != nil {
		if err := a.nodeFailState.Err(); err != nil {
			return nil, err
		}
	}
	if a.runtime == nil {
		return nil, auth.ErrInvalidCredentials
	}
	conn, ok := auth.ConnIdentityFromContext(ctx)
	if !ok {
		return nil, auth.ErrNoCredentials
	}
	entry, enrolled := a.runtime.EnrolledKey(conn.KeyFingerprint)
	if !enrolled {
		return nil, auth.ErrInvalidCredentials
	}
	return auth.NewClientIdentity(entry.Fingerprint, entry.Label), nil
}

func (*productAuthenticator) Method() string { return auth.MethodSSHKey }

var _ auth.Authenticator = (*productAuthenticator)(nil)
