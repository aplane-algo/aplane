// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"context"
	"net/http"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
)

// productAuthenticator verifies the one product runtime's token and maps the
// credential to the reserved product-admin principal. Token authentication is
// deliberately independent from runtime selection.
type productAuthenticator struct {
	nodeFailState *productruntime.NodeFailState
	runtime       *productruntime.Runtime
}

func newProductAuthenticator(nodeFailState *productruntime.NodeFailState, runtime *productruntime.Runtime) *productAuthenticator {
	return &productAuthenticator{nodeFailState: nodeFailState, runtime: runtime}
}

func (a *productAuthenticator) Authenticate(ctx context.Context, r *http.Request) (*auth.Identity, error) {
	if a.nodeFailState != nil {
		if err := a.nodeFailState.Err(); err != nil {
			return nil, err
		}
	}
	if a.runtime == nil || a.runtime.Authenticator() == nil {
		return nil, auth.ErrInvalidCredentials
	}
	ident, err := a.runtime.Authenticator().Authenticate(ctx, r)
	if err != nil {
		return nil, err
	}
	return ident, nil
}

func (*productAuthenticator) Method() string { return "aplane-token" }

var _ auth.Authenticator = (*productAuthenticator)(nil)
